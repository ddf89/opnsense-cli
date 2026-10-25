//go:build integration

package integrationsystem

import (
	"bytes"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// Backups are read (list, download, diff) but never reverted. The only entry ever deleted is one this test
// provably created: its diff to the previous entry adds a cron job carrying this run's unique description.
// Config contents are never logged, only sizes and whether a marker occurs.

func TestBackupProviders(t *testing.T) {
	var sys = systemApi(t)
	var providers, err = sys.BackupProviders()
	if err != nil {
		t.Fatal(err)
	}
	var local bool
	for _, provider := range providers {
		if provider.Name == system.BackupProviderLocal {
			local = true
			if provider.Description == "" || provider.Dirname == "" {
				t.Errorf("incomplete local provider: %+v", provider)
			}
		}
	}
	if !local {
		t.Errorf("no %q provider in %+v", system.BackupProviderLocal, providers)
	}
}

func TestBackupListDownloadDiff(t *testing.T) {
	var sys = systemApi(t)
	var backups, err = sys.BackupList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) < 2 {
		t.Skipf("need at least 2 backups, have %d", len(backups))
	}
	for i, backup := range backups {
		if !strings.HasPrefix(backup.Id, "config-") || !strings.HasSuffix(backup.Id, ".xml") || backup.Filesize <= 0 {
			t.Errorf("unexpected backup %d: %+v", i, backup)
		}
		if _, ok := backup.Timestamp(); !ok {
			t.Errorf("backup %s has no parsable time %q", backup.Id, backup.Time)
		}
		if i > 0 {
			var previous, _ = backups[i-1].Timestamp()
			var current, _ = backup.Timestamp()
			if current.After(previous) {
				t.Errorf("not sorted newest first: %s (%s) after %s (%s)", backup.Id, backup.Time, backups[i-1].Id, backups[i-1].Time)
			}
		}
	}
	if explicit, _ := sys.BackupList(system.BackupProviderLocal); len(explicit) == 0 {
		t.Errorf("listing provider %q explicitly returned nothing", system.BackupProviderLocal)
	}

	t.Run("download a specific backup", func(t *testing.T) {
		var target = backups[1]
		var content, filename, err = sys.BackupDownload("", target.Id)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(content)) != target.Filesize {
			t.Errorf("downloaded %d bytes, the history says %d", len(content), target.Filesize)
		}
		if !bytes.HasPrefix(content, []byte("<?xml")) || !bytes.Contains(content, []byte("<opnsense>")) {
			t.Errorf("download of %s is not a config.xml (%d bytes)", target.Id, len(content))
		}
		if filename == "" || strings.ContainsAny(filename, `/\`) || !strings.HasSuffix(filename, ".xml") {
			t.Errorf("unexpected file name %q", filename)
		}
	})

	t.Run("download the current configuration", func(t *testing.T) {
		var content, filename, err = sys.BackupDownload("", system.BackupCurrent)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(content, []byte("<?xml")) || filename == "" {
			t.Errorf("download of the current config returned %d bytes, file name %q", len(content), filename)
		}
	})

	t.Run("diff of a backup with itself is empty", func(t *testing.T) {
		var lines, err = sys.BackupDiff("", backups[1].Id, backups[1].Id)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 0 {
			t.Errorf("diff with itself has %d lines", len(lines))
		}
	})

	t.Run("diff of two backups is a unified diff", func(t *testing.T) {
		// pick the newest two adjacent entries with different sizes, so there is certainly a difference. The history
		// keeps 100 entries, old ones can drop out while other tests change the configuration
		var from, to string
		for i := 1; i < len(backups); i++ {
			if backups[i].Filesize != backups[i-1].Filesize {
				from, to = backups[i].Id, backups[i-1].Id
				break
			}
		}
		if from == "" {
			t.Skip("all backups have the same size")
		}
		var lines, err = sys.BackupDiff("", from, to)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) < 3 || !strings.HasPrefix(lines[0], "--- ") || !strings.HasPrefix(lines[1], "+++ ") {
			t.Fatalf("not a unified diff (%d lines)", len(lines))
		}
		// --- is the older (from), +++ the newer (to) file
		if !strings.Contains(lines[0], strings.TrimSuffix(from, ".xml")) || !strings.Contains(lines[1], strings.TrimSuffix(to, ".xml")) {
			t.Errorf("diff direction: want --- %s / +++ %s, got header %q / %q", from, to, lines[0], lines[1])
		}
		for _, line := range lines {
			if strings.Contains(line, "&lt;") || strings.Contains(line, "&gt;") {
				t.Errorf("diff lines are still html escaped")
				break
			}
		}
	})
}

func TestBackupErrors(t *testing.T) {
	var sys = systemApi(t)
	const unknown = "config-1000000000.0001.xml"

	if _, err := sys.BackupList("a8-no-such-provider"); !api.IsNotFound(err) {
		t.Errorf("list of an unknown provider: want *NotFoundError, got %T: %v", err, err)
	}
	if _, _, err := sys.BackupDownload("", unknown); !api.IsNotFound(err) {
		t.Errorf("download of an unknown id: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.BackupDiff("", unknown, system.BackupCurrent); !api.IsNotFound(err) {
		t.Errorf("diff with an unknown id: want *NotFoundError, got %T: %v", err, err)
	}
	if err := sys.BackupDelete(unknown); !api.IsNotFound(err) {
		t.Errorf("delete of an unknown id: want *NotFoundError, got %T: %v", err, err)
	}
	// revert is never called live, not even with an unknown id
}

// TestBackupDeleteOwnEntry creates a cron job (which writes a history entry), finds that entry by its diff
// and deletes exactly it
func TestBackupDeleteOwnEntry(t *testing.T) {
	var sys = systemApi(t)
	var uuid, job = createCronJob(t, sys, "backup-marker", system.CronJob{})

	var backups, err = sys.BackupList("")
	if err != nil {
		t.Fatal(err)
	}
	// the add_job entry is among the newest ones, other users may have saved since
	var own string
	for i := 0; i < len(backups)-1 && i < 15 && own == ""; i++ {
		if !strings.Contains(backups[i].Description, "add_job") {
			continue
		}
		var lines, diffErr = sys.BackupDiff("", backups[i+1].Id, backups[i].Id)
		if diffErr != nil {
			t.Fatal(diffErr)
		}
		for _, line := range lines {
			if strings.HasPrefix(line, "+") && strings.Contains(line, job.Description) {
				own = backups[i].Id
				break
			}
		}
	}
	if own == "" {
		t.Skipf("could not identify the history entry of cron job %s, not deleting anything", uuid)
	}

	if err := sys.BackupDelete(own); err != nil {
		t.Fatalf("BackupDelete(%s): %v", own, err)
	}
	var after, _ = sys.BackupList("")
	for _, backup := range after {
		if backup.Id == own {
			t.Errorf("%s still listed after delete", own)
		}
	}
	if err := sys.BackupDelete(own); !api.IsNotFound(err) {
		t.Errorf("second delete of %s: want *NotFoundError, got %T: %v", own, err, err)
	}
}
