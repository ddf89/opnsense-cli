//go:build integration

package integrationsystem

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// The CLI smoke tests run every read command and a full add / set / remove cycle per menu through the opn binary.
// Destructive commands (backup revert / remove of a real backup, defaults reset, reboot, shutdown) are never run
// live: only their refusal without confirm=yes is checked, which sends nothing. Their behaviour with confirmation
// is covered by the unit tests in cli/system_*_test.go

func TestCliCron(t *testing.T) {
	var sys = systemApi(t)
	var description = testDescription("cli-cron")

	var created = mustOpn(t, "/system/cron", "add", "command="+harmlessCronCommand, "description="+description,
		"disabled", "minutes=7", "hours=2")
	var uuid = uuidFrom(t, created)
	cleanupCronJob(t, sys, uuid)
	if strings.TrimSpace(created.stdout) != uuid {
		t.Errorf("add should print only the uuid:\n%s", created)
	}
	if job, err := sys.CronJobGet(uuid); err != nil || job.Enabled != "0" {
		t.Fatalf("the job is not disabled: %+v, %v", job, err)
	}

	var printed = mustOpn(t, "/system/cron", "print", "search="+description)
	requireContains(t, printed, printed.stdout, "#", "DISABLED", description, "7 2 * * *")
	var detail = mustOpn(t, "/system/cron", "print", "search="+description, "detail")
	requireContains(t, detail, detail.stdout, uuid)

	var show = mustOpn(t, "/system/cron", "show", description)
	requireContains(t, show, show.stdout, uuid, harmlessCronCommand)

	requireNoStdout(t, mustOpn(t, "/system/cron", "set", uuid, "hours=4"))
	if job, err := sys.CronJobGet(uuid); err != nil || job.Schedule() != "7 4 * * *" || job.Enabled != "0" {
		t.Errorf("after set: %+v, %v", job, err)
	}
	mustFailOpn(t, "/system/cron", "set", uuid, "hours=25")

	var disable = mustOpn(t, "/system/cron", "disable", description)
	requireContains(t, disable, disable.stderr, "already disabled")

	// the description names the job: add refuses a duplicate unless replace is given
	var duplicate = mustFailOpn(t, "/system/cron", "add", "command="+harmlessCronCommand, "description="+description, "disabled")
	requireContains(t, duplicate, duplicate.stderr, "exists already", uuid)
	var replaced = mustOpn(t, "/system/cron", "add", "command="+harmlessCronCommand, "description="+description, "disabled", "minutes=9", "replace")
	if replacedUuid := uuidFrom(t, replaced); replacedUuid != uuid {
		cleanupCronJob(t, sys, replacedUuid)
		t.Errorf("add replace created %s instead of replacing %s", replacedUuid, uuid)
	}
	if job, err := sys.CronJobGet(uuid); err != nil || job.Schedule() != "9 0 * * *" || job.Enabled != "0" {
		t.Errorf("after add replace (hours reset to the default 0): %+v, %v", job, err)
	}

	var commands = mustOpn(t, "/system/cron", "commands")
	requireContains(t, commands, commands.stdout, harmlessCronCommand)

	var missing = mustFailOpn(t, "/system/cron", "show", description+"-missing")
	requireContains(t, missing, missing.stderr, "not found")

	requireNoStdout(t, mustOpn(t, "/system/cron", "remove", description))
	if _, err := sys.CronJobGet(uuid); !api.IsNotFound(err) {
		t.Errorf("job still exists after remove: %v", err)
	}
	mustOpn(t, "/system/cron", "apply")
}

func TestCliTunable(t *testing.T) {
	var sys = systemApi(t)
	var runtime, builtin = runtimeValue(t, sys)
	applyTunablesOnCleanup(t, sys)
	var description = testDescription("cli-tunable")

	var show = mustOpn(t, "/system/tunable", "show", safeTunable)
	requireContains(t, show, show.stdout, builtin.Uuid, "built-in")

	var added = mustOpn(t, "/system/tunable", "add", "name="+safeTunable, "value="+runtime, "description="+description)
	var uuid = uuidFrom(t, added)
	cleanupTunable(t, sys, uuid)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add should print only the uuid on stdout:\n%s", added)
	}

	var printed = mustOpn(t, "/system/tunable", "print", "search="+safeTunable)
	requireContains(t, printed, printed.stdout, safeTunable, "override")

	var duplicate = mustFailOpn(t, "/system/tunable", "add", "name="+safeTunable, "value="+runtime)
	requireContains(t, duplicate, duplicate.stderr, uuid)
	var replaced = mustOpn(t, "/system/tunable", "add", "name="+safeTunable, "value="+runtime, "replace")
	if uuidFrom(t, replaced) != uuid {
		t.Errorf("add replace returned another uuid:\n%s", replaced)
	}
	if tunable, err := sys.TunableGetByName(safeTunable); err != nil || tunable.Description == description || tunable.Value != runtime {
		// a cleared description reads as the description of the built-in default
		t.Errorf("add replace should clear the description: %+v, %v", tunable, err)
	}

	requireNoStdout(t, mustOpn(t, "/system/tunable", "set", safeTunable, "description="+description))
	if tunable, err := sys.TunableGetByName(safeTunable); err != nil || tunable.Description != description || tunable.Value != runtime {
		t.Errorf("after set: %+v, %v", tunable, err)
	}

	var invalid = mustFailOpn(t, "/system/tunable", "add", "name=kern.a8 sys", "value=1", "description="+description)
	requireContains(t, invalid, invalid.stderr, "kern.a8 sys")

	requireNoStdout(t, mustOpn(t, "/system/tunable", "remove", uuid))
	if tunable, err := sys.TunableGetByName(safeTunable); err != nil || !tunable.IsBuiltin() {
		t.Errorf("after remove: %+v, %v", tunable, err)
	}
	// a built-in default which is not configured can not be removed
	mustFailOpn(t, "/system/tunable", "remove", safeTunable)

	t.Run("set of a built-in default stores an override", func(t *testing.T) {
		var set = mustOpn(t, "/system/tunable", "set", safeTunable, "value="+runtime, "description="+description)
		requireNoStdout(t, set)
		var tunable, err = sys.TunableGetByName(safeTunable)
		if err == nil && !tunable.IsBuiltin() {
			cleanupTunable(t, sys, tunable.Uuid)
		}
		if err != nil || tunable.IsBuiltin() || tunable.Value != runtime || tunable.Description != description {
			t.Errorf("after set of the built-in: %+v, %v", tunable, err)
		}
		requireContains(t, set, set.stderr, tunable.Uuid)
	})
	// the tunables are applied by the cleanup
}

func TestCliLogging(t *testing.T) {
	var sys = systemApi(t)
	var before = snapshotLoggingGeneral(t, sys)
	var description = testDescription("cli-dest")

	var printed = mustOpn(t, "/system/logging", "print")
	requireContains(t, printed, printed.stdout, "max-preserve:", before.MaxPreserve)
	mustOpn(t, "/system/logging", "print", "json")

	var preserve = "30"
	if before.MaxPreserve == preserve {
		preserve = "29"
	}
	requireNoStdout(t, mustOpn(t, "/system/logging", "set", "max-preserve="+preserve))
	if after, err := sys.LoggingGeneralGet(); err != nil || after.MaxPreserve != preserve || after.LogLocal != before.LogLocal {
		t.Errorf("after set: %+v, %v", after, err)
	}
	mustFailOpn(t, "/system/logging", "set", "max-preserve=many")

	var created = mustOpn(t, "/system/logging/destination", "add", "disabled", "hostname="+safeSyslogHost,
		"port=1514", "level=err", "description="+description)
	var uuid = uuidFrom(t, created)
	cleanupDestination(t, sys, uuid)
	if destination, err := sys.LoggingDestinationGet(uuid); err != nil || destination.Enabled != "0" {
		t.Fatalf("the destination is not disabled: %+v, %v", destination, err)
	}

	var list = mustOpn(t, "/system/logging/destination", "print", "search="+description)
	requireContains(t, list, list.stdout, "DISABLED", safeSyslogHost, "1514")

	var showDest = mustOpn(t, "/system/logging/destination", "show", description)
	requireContains(t, showDest, showDest.stdout, uuid, "udp4", "err")

	requireNoStdout(t, mustOpn(t, "/system/logging/destination", "set", uuid, "port=1515"))
	if destination, _ := sys.LoggingDestinationGet(uuid); destination.Port != "1515" || destination.Level != "err" || destination.Enabled != "0" {
		t.Errorf("after set: %+v", destination)
	}
	// udp6 does not match the IPv4 hostname
	mustFailOpn(t, "/system/logging/destination", "set", uuid, "transport=udp6")
	// the description selects the destination: no duplicates
	mustFailOpn(t, "/system/logging/destination", "add", "disabled", "hostname="+safeSyslogHost, "description="+description)
	mustOpn(t, "/system/logging/destination", "disable", description)

	requireNoStdout(t, mustOpn(t, "/system/logging/destination", "remove", description))
	if _, err := sys.LoggingDestinationGet(uuid); !api.IsNotFound(err) {
		t.Errorf("destination still exists after remove: %v", err)
	}

	var status = mustOpn(t, "/system/logging/service", "status")
	requireContains(t, status, status.stdout, "running")
	var stats = mustOpn(t, "/system/logging", "stats", "search=global")
	requireContains(t, stats, stats.stdout, "SOURCE", "global")
	mustOpn(t, "/system/logging/service", "reconfigure")
	mustOpn(t, "/system/logging/service", "restart")
	if status, err := sys.LoggingServiceStatus(); err != nil || status != "running" {
		t.Errorf("syslog after restart: %q, %v", status, err)
	}
}

func TestCliBackup(t *testing.T) {
	var sys = systemApi(t)
	var providers = mustOpn(t, "/system/backup", "providers")
	requireContains(t, providers, providers.stdout, system.BackupProviderLocal)

	var backups, err = sys.BackupList("")
	if err != nil || len(backups) < 2 {
		t.Skipf("need 2 backups: %d, %v", len(backups), err)
	}
	var list = mustOpn(t, "/system/backup", "print")
	requireContains(t, list, list.stdout, "#", "ID", backups[1].Id)

	t.Run("download writes a 0600 file and prints no config", func(t *testing.T) {
		var dir = t.TempDir()
		var result = runOpnIn(t, dir, "/system/backup", "download", backups[1].Id, "file=cfg.xml")
		if result.exitCode != 0 {
			t.Fatalf("download failed:\n%s", result)
		}
		var path = filepath.Join(dir, "cfg.xml")
		var content, readErr = os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if int64(len(content)) != backups[1].Filesize || !bytes.HasPrefix(content, []byte("<?xml")) {
			t.Errorf("downloaded %d bytes, want %d of XML", len(content), backups[1].Filesize)
		}
		if info, _ := os.Stat(path); info == nil || info.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", info.Mode().Perm())
		}
		if strings.Contains(result.stdout+result.stderr, "<opnsense>") {
			t.Errorf("config printed to the terminal")
		}
		var exists = runOpnIn(t, dir, "/system/backup", "download", backups[1].Id, "file=cfg.xml")
		if exists.exitCode != 1 {
			t.Errorf("download over an existing file without overwrite: want exit code 1:\n%s", exists)
		}
		if replaced := runOpnIn(t, dir, "/system/backup", "download", backups[1].Id, "file=cfg.xml", "overwrite"); replaced.exitCode != 0 {
			t.Errorf("download with overwrite: want exit code 0:\n%s", replaced)
		}

		var current = runOpnIn(t, dir, "/system/backup", "download")
		if current.exitCode != 0 {
			t.Fatalf("download of the current config failed: exit %d", current.exitCode)
		}
		var files, _ = filepath.Glob(filepath.Join(dir, "config-*.xml"))
		if len(files) != 1 {
			t.Errorf("want one config-*.xml named like OPNsense suggests, got %v", files)
		}
	})

	t.Run("diff", func(t *testing.T) {
		var same = runOpnIn(t, "", "/system/backup", "diff", "from="+backups[1].Id, "to="+backups[1].Id)
		if same.exitCode != 0 || !strings.Contains(strings.ToLower(same.stderr), "no differences") {
			t.Errorf("diff of a backup with itself: exit %d, stderr %q", same.exitCode, same.stderr)
		}
		// a recent entry, old ones can drop out of the 100 entries history while other tests change the configuration
		var diff = runOpnIn(t, "", "/system/backup", "diff", backups[min(5, len(backups)-1)].Id)
		if diff.exitCode != 0 || !strings.HasPrefix(diff.stdout, "--- ") {
			t.Errorf("diff against current: exit %d, %d bytes of output", diff.exitCode, len(diff.stdout))
		}
		var unknown = runOpnIn(t, "", "/system/backup", "diff", "config-1000000000.0001.xml")
		if unknown.exitCode != 1 || !strings.Contains(unknown.stderr, "not found") {
			t.Errorf("diff with an unknown id: exit %d, stderr %q", unknown.exitCode, unknown.stderr)
		}
	})

	// an unknown id is resolved against the history before anything is deleted
	var rmUnknown = mustFailOpn(t, "/system/backup", "remove", "config-1000000000.0001.xml", "confirm=yes")
	requireContains(t, rmUnknown, rmUnknown.stderr, "not found")
	mustFailOpn(t, "/system/backup", "remove", "current", "confirm=yes")
}

func TestCliDefaultsWizard(t *testing.T) {
	var sys = systemApi(t)
	var defaults, err = sys.DefaultsGet()
	if err != nil {
		t.Fatal(err)
	}
	var show = mustOpn(t, "/system/defaults", "print")
	requireContains(t, show, show.stdout, defaults.DefaultIp)

	var wizard, wizardErr = sys.WizardGet()
	if wizardErr != nil {
		t.Fatal(wizardErr)
	}
	var wizardShow = mustOpn(t, "/system/wizard", "print")
	requireContains(t, wizardShow, wizardShow.stdout, wizard.Hostname, wizard.Domain, wizard.Timezone)
	if strings.Contains(strings.ToLower(wizardShow.stdout), "password") {
		t.Errorf("wizard print mentions passwords")
	}
}

// TestCliConfirmRefused checks that the dangerous commands refuse to run without confirm=yes when nobody can be
// asked. The refusal happens before any API call. NEVER add confirm=yes here
func TestCliConfirmRefused(t *testing.T) {
	var sys = systemApi(t)
	var backups, err = sys.BackupList("")
	if err != nil || len(backups) < 2 {
		t.Fatalf("BackupList: %d backups, %v", len(backups), err)
	}
	for _, args := range [][]string{
		{"/system", "reboot"},
		{"/system", "reboot", "wait", "confirm=no"},
		{"/system", "shutdown"},
		{"/system", "poweroff"},
		{"/system/defaults", "reset"},
		{"/system/backup", "revert", backups[1].Id},
		{"/system/backup", "remove", backups[1].Id},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var refused = mustFailOpn(t, args...)
			requireContains(t, refused, refused.stderr, "confirm=yes")
		})
	}
	// in a script stdin is not a terminal, a "y" line is the next command, not an answer
	t.Run("script", func(t *testing.T) {
		var refused = runOpnStdin(t, "", "/system\nreboot\ny\n")
		if refused.exitCode != 1 || !strings.Contains(refused.stderr, "stdin:2:") || !strings.Contains(refused.stderr, "confirm=yes") {
			t.Errorf("want exit code 1 and the refusal of line 2:\n%s", refused)
		}
	})
	// the history keeps at most 100 entries, other tests may push old ones out meanwhile
	var after, afterErr = sys.BackupList("")
	if afterErr != nil {
		t.Fatalf("BackupList: %v", afterErr)
	}
	var kept bool
	for _, entry := range after {
		kept = kept || entry.Id == backups[1].Id
	}
	if !kept && len(after) < 100 {
		t.Errorf("backup %s is gone after the refused remove", backups[1].Id)
	}
}
