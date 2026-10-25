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

// The CLI smoke tests run every read command and a full create / update / remove cycle per group through the
// opn binary. Destructive commands (backup revert, defaults reset, wizard) are never run live, not even without
// --yes: their guards are covered by the unit tests in cmd/system_*_test.go

func TestCliCron(t *testing.T) {
	var sys = systemApi(t)
	var description = testDescription("cli-cron")

	var created = mustOpn(t, "system", "cron", "create", "--command", harmlessCronCommand, "--description", description,
		"--enabled", "0", "--minutes", "7", "--hours", "2")
	var uuid = uuidFrom(t, created)
	cleanupCronJob(t, sys, uuid)

	var list = mustOpn(t, "system", "cron", "list", "--search", description)
	requireContains(t, list, list.stdout, uuid, description, "7 2 * * *")

	var show = mustOpn(t, "system", "cron", "show", "--description", description)
	requireContains(t, show, show.stdout, uuid, harmlessCronCommand)

	mustOpn(t, "system", "cron", "update", "--uuid", uuid, "--hours", "4")
	if job, err := sys.CronJobGet(uuid); err != nil || job.Schedule() != "7 4 * * *" || job.Enabled != "0" {
		t.Errorf("after update: %+v, %v", job, err)
	}

	var disable = mustOpn(t, "system", "cron", "disable", "--description", description)
	requireContains(t, disable, disable.stdout, "already disabled")

	var commands = mustOpn(t, "system", "cron", "commands")
	requireContains(t, commands, commands.stdout, harmlessCronCommand)

	var missing = mustFailOpn(t, "system", "cron", "show", "--description", description+"-missing")
	requireContains(t, missing, missing.stdout+missing.stderr, "not found")

	mustOpn(t, "system", "cron", "rm", "--description", description)
	if _, err := sys.CronJobGet(uuid); !api.IsNotFound(err) {
		t.Errorf("job still exists after rm: %v", err)
	}
	mustOpn(t, "system", "cron", "apply")
}

func TestCliTunable(t *testing.T) {
	var sys = systemApi(t)
	var runtime, builtin = runtimeValue(t, sys)
	applyTunablesOnCleanup(t, sys)
	var description = testDescription("cli-tunable")

	var show = mustOpn(t, "system", "tunable", "show", "--name", safeTunable)
	requireContains(t, show, show.stdout, builtin.Uuid, "built-in")

	var set = mustOpn(t, "system", "tunable", "set", "--name", safeTunable, "--value", runtime, "--description", description)
	var uuid = uuidFrom(t, set)
	cleanupTunable(t, sys, uuid)
	requireContains(t, set, set.stderr, "created")

	var list = mustOpn(t, "system", "tunable", "list", "--search", safeTunable)
	requireContains(t, list, list.stdout, uuid, "override")

	var again = mustOpn(t, "system", "tunable", "set", "--name", safeTunable, "--value", runtime)
	if uuidFrom(t, again) != uuid {
		t.Errorf("second set returned another uuid:\n%s", again)
	}
	requireContains(t, again, again.stderr, "updated")

	var invalid = mustFailOpn(t, "system", "tunable", "set", "--name", "kern.a8 sys", "--value", "1", "--description", description)
	requireContains(t, invalid, invalid.stderr, "invalid tunable name")

	mustOpn(t, "system", "tunable", "rm", "--uuid", uuid)
	if tunable, err := sys.TunableGetByName(safeTunable); err != nil || !tunable.IsBuiltin() {
		t.Errorf("after rm: %+v, %v", tunable, err)
	}
	// the tunables are applied by the cleanup
}

func TestCliLogging(t *testing.T) {
	var sys = systemApi(t)
	var before = snapshotLoggingGeneral(t, sys)
	var description = testDescription("cli-dest")

	var show = mustOpn(t, "system", "logging", "show")
	requireContains(t, show, show.stdout, "maxpreserve", before.MaxPreserve)

	var preserve = "30"
	if before.MaxPreserve == preserve {
		preserve = "29"
	}
	mustOpn(t, "system", "logging", "set", "--maxpreserve", preserve)
	if after, err := sys.LoggingGeneralGet(); err != nil || after.MaxPreserve != preserve || after.LogLocal != before.LogLocal {
		t.Errorf("after set: %+v, %v", after, err)
	}
	mustFailOpn(t, "system", "logging", "set", "--maxpreserve", "many")

	var created = mustOpn(t, "system", "logging", "destination", "create", "--enabled=false", "--hostname", safeSyslogHost,
		"--port", "1514", "--level", "err", "--description", description)
	var uuid = uuidFrom(t, created)
	cleanupDestination(t, sys, uuid)
	if destination, err := sys.LoggingDestinationGet(uuid); err != nil || destination.Enabled != "0" {
		t.Fatalf("the destination is not disabled: %+v, %v", destination, err)
	}

	var list = mustOpn(t, "system", "logging", "destination", "list", "--search", description)
	requireContains(t, list, list.stdout, uuid, safeSyslogHost, "1514")

	var showDest = mustOpn(t, "system", "logging", "destination", "show", "--description", description)
	requireContains(t, showDest, showDest.stdout, uuid, "udp4", "err")

	mustOpn(t, "system", "logging", "destination", "update", "--uuid", uuid, "--port", "1515")
	if destination, _ := sys.LoggingDestinationGet(uuid); destination.Port != "1515" || destination.Level != "err" || destination.Enabled != "0" {
		t.Errorf("after update: %+v", destination)
	}
	mustFailOpn(t, "system", "logging", "destination", "update", "--uuid", uuid, "--transport", "udp6")
	mustOpn(t, "system", "logging", "destination", "disable", "--description", description)

	mustOpn(t, "system", "logging", "destination", "rm", "--description", description)
	if _, err := sys.LoggingDestinationGet(uuid); !api.IsNotFound(err) {
		t.Errorf("destination still exists after rm: %v", err)
	}

	var status = mustOpn(t, "system", "logging", "service", "status")
	requireContains(t, status, status.stdout+status.stderr, "running")
	var stats = mustOpn(t, "system", "logging", "stats", "--search", "global")
	requireContains(t, stats, stats.stdout, "SOURCE", "global")
	mustOpn(t, "system", "logging", "service", "reconfigure")
	mustOpn(t, "system", "logging", "service", "restart")
	if status, err := sys.LoggingServiceStatus(); err != nil || status != "running" {
		t.Errorf("syslog after restart: %q, %v", status, err)
	}
}

func TestCliBackup(t *testing.T) {
	var sys = systemApi(t)
	var providers = mustOpn(t, "system", "backup", "providers")
	requireContains(t, providers, providers.stdout, system.BackupProviderLocal)

	var backups, err = sys.BackupList("")
	if err != nil || len(backups) < 2 {
		t.Skipf("need 2 backups: %d, %v", len(backups), err)
	}
	var list = mustOpn(t, "system", "backup", "list")
	requireContains(t, list, list.stdout, "ID", backups[1].Id)

	t.Run("download writes a 0600 file and prints no config", func(t *testing.T) {
		var dir = t.TempDir()
		var result = runOpnIn(t, dir, "system", "backup", "download", "--id", backups[1].Id, "--output", "cfg.xml")
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

		var current = runOpnIn(t, dir, "system", "backup", "download")
		if current.exitCode != 0 {
			t.Fatalf("download of the current config failed: exit %d", current.exitCode)
		}
		var files, _ = filepath.Glob(filepath.Join(dir, "config-*.xml"))
		if len(files) != 1 {
			t.Errorf("want one config-*.xml named like OPNsense suggests, got %v", files)
		}
	})

	t.Run("diff", func(t *testing.T) {
		var same = runOpnIn(t, "", "system", "backup", "diff", "--from", backups[1].Id, "--to", backups[1].Id)
		if same.exitCode != 0 || !strings.Contains(same.stderr, "No differences") {
			t.Errorf("diff of a backup with itself: exit %d, stderr %q", same.exitCode, same.stderr)
		}
		// a recent entry, old ones can drop out of the 100 entries history while other tests change the configuration
		var diff = runOpnIn(t, "", "system", "backup", "diff", "--from", backups[min(5, len(backups)-1)].Id)
		if diff.exitCode != 0 || !strings.HasPrefix(diff.stdout, "--- ") {
			t.Errorf("diff against current: exit %d, %d bytes of output", diff.exitCode, len(diff.stdout))
		}
		var unknown = runOpnIn(t, "", "system", "backup", "diff", "--from", "config-1000000000.0001.xml")
		if unknown.exitCode == 0 || !strings.Contains(unknown.stderr, "not found") {
			t.Errorf("diff with an unknown id: exit %d, stderr %q", unknown.exitCode, unknown.stderr)
		}
	})

	var rmUnknown = mustFailOpn(t, "system", "backup", "rm", "--id", "config-1000000000.0001.xml", "--yes")
	requireContains(t, rmUnknown, rmUnknown.stderr, "not found")
}

func TestCliDefaultsWizard(t *testing.T) {
	var sys = systemApi(t)
	var defaults, err = sys.DefaultsGet()
	if err != nil {
		t.Fatal(err)
	}
	var show = mustOpn(t, "system", "defaults", "show")
	requireContains(t, show, show.stdout, defaults.DefaultIp)

	var wizard, wizardErr = sys.WizardGet()
	if wizardErr != nil {
		t.Fatal(wizardErr)
	}
	var wizardShow = mustOpn(t, "system", "wizard", "show")
	requireContains(t, wizardShow, wizardShow.stdout, wizard.Hostname, wizard.Domain, wizard.Timezone)
	if strings.Contains(strings.ToLower(wizardShow.stdout), "password") {
		t.Errorf("wizard show mentions passwords")
	}
}
