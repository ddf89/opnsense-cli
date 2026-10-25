//go:build integration

package integrationsystem

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// harmlessCronCommand is used for every test job. The jobs are always created disabled, so it never runs
const harmlessCronCommand = "firmware changelog cron"

func systemApi(t *testing.T) *system.SystemApi {
	t.Helper()
	return &system.SystemApi{OPNsense: coreApi(t)}
}

func strPtr(s string) *string { return &s }

// createCronJob creates a disabled job with a description owned by this run and registers its removal
func createCronJob(t *testing.T, sys *system.SystemApi, label string, job system.CronJob) (string, system.CronJob) {
	t.Helper()
	job.Enabled = "0"
	job.Description = testDescription(label)
	if job.Command == "" {
		job.Command = harmlessCronCommand
	}
	var uuid, err = sys.CronJobCreate(job)
	if err != nil {
		t.Fatalf("CronJobCreate(%+v): %v", job, err)
	}
	if uuid == "" {
		t.Fatalf("CronJobCreate returned no uuid")
	}
	cleanupCronJob(t, sys, uuid)
	return uuid, job
}

func cleanupCronJob(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.CronJobRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of cron job %s failed: %v", uuid, err)
		}
	})
}

func TestCronCommands(t *testing.T) {
	var sys = systemApi(t)
	var commands, err = sys.CronCommands()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for i, command := range commands {
		if command.Key == "" || command.Description == "" {
			t.Errorf("command %d has an empty key or description: %+v", i, command)
		}
		if i > 0 && commands[i-1].Key >= command.Key {
			t.Errorf("commands are not sorted by key: %q before %q", commands[i-1].Key, command.Key)
		}
		found = found || command.Key == harmlessCronCommand
	}
	if !found {
		t.Errorf("%q not among the %d commands", harmlessCronCommand, len(commands))
	}
}

func TestCronJobLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var uuid, created = createCronJob(t, sys, "cron-lifecycle", system.CronJob{
		Minutes: "17", Hours: "3", Days: "*", Months: "*", Weekdays: "1-5", Who: "root", Parameters: "--a8",
	})

	t.Run("get returns the created fields", func(t *testing.T) {
		var job, err = sys.CronJobGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if job.Uuid != uuid || job.Enabled != "0" || job.Description != created.Description ||
			job.Command != harmlessCronCommand || job.Parameters != "--a8" || job.Who != "root" || job.Origin != system.CronOriginUser {
			t.Errorf("unexpected job: %+v", job)
		}
		if job.Schedule() != "17 3 * * 1-5" {
			t.Errorf("schedule %q, want %q", job.Schedule(), "17 3 * * 1-5")
		}
		if job.CommandDescription == "" {
			t.Errorf("no command description: %+v", job)
		}
	})

	t.Run("lookup by exact description", func(t *testing.T) {
		var job, err = sys.CronJobGetByDescription(created.Description)
		if err != nil {
			t.Fatal(err)
		}
		if job.Uuid != uuid {
			t.Errorf("found %s, want %s", job.Uuid, uuid)
		}
		// a prefix of the description is no match
		_, err = sys.CronJobGetByDescription(created.Description[:len(created.Description)-2])
		if !api.IsNotFound(err) {
			t.Errorf("prefix lookup: want *NotFoundError, got %T: %v", err, err)
		}
	})

	t.Run("search", func(t *testing.T) {
		var jobs, err = sys.CronJobSearch(created.Description)
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) != 1 || jobs[0].Uuid != uuid {
			t.Errorf("search %q returned %+v", created.Description, jobs)
		}
	})

	t.Run("update changes only the given fields", func(t *testing.T) {
		if err := sys.CronJobUpdate(uuid, system.CronJobPatch{Minutes: strPtr("42"), Parameters: strPtr("--b8")}); err != nil {
			t.Fatal(err)
		}
		var job, err = sys.CronJobGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if job.Schedule() != "42 3 * * 1-5" || job.Parameters != "--b8" || job.Enabled != "0" ||
			job.Description != created.Description || job.Command != harmlessCronCommand {
			t.Errorf("unexpected job after update: %+v", job)
		}
	})

	t.Run("invalid update is a validation error and changes nothing", func(t *testing.T) {
		var err = sys.CronJobUpdate(uuid, system.CronJobPatch{Minutes: strPtr("61")})
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("want *ValidationError, got %T: %v", err, err)
		}
		if _, ok := validationErr.Validations["job.minutes"]; !ok {
			t.Errorf("no job.minutes validation: %v", validationErr.Validations)
		}
		var job, _ = sys.CronJobGet(uuid)
		if job.Minutes != "42" {
			t.Errorf("minutes changed to %q by a failed update", job.Minutes)
		}
	})

	t.Run("disabling a disabled job changes nothing", func(t *testing.T) {
		var changed, err = sys.CronJobSetEnabled(uuid, false)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Errorf("changed = true for an already disabled job")
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := sys.CronJobRemove(uuid); err != nil {
			t.Fatal(err)
		}
		if _, err := sys.CronJobGet(uuid); !api.IsNotFound(err) {
			t.Errorf("get after remove: want *NotFoundError, got %T: %v", err, err)
		}
		if err := sys.CronJobRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want *NotFoundError, got %T: %v", err, err)
		}
	})
}

func TestCronJobErrors(t *testing.T) {
	var sys = systemApi(t)
	const unknown = "00000000-0000-4000-8000-0000000000a8"

	if _, err := sys.CronJobGet(unknown); !api.IsNotFound(err) {
		t.Errorf("get unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if err := sys.CronJobUpdate(unknown, system.CronJobPatch{Parameters: strPtr("x")}); !api.IsNotFound(err) {
		t.Errorf("update unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if err := sys.CronJobRemove(unknown); !api.IsNotFound(err) {
		t.Errorf("remove unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.CronJobSetEnabled(unknown, false); !api.IsNotFound(err) {
		t.Errorf("disable unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.CronJobGetByDescription(testDescription("does-not-exist")); !api.IsNotFound(err) {
		t.Errorf("lookup unknown description: want *NotFoundError, got %T: %v", err, err)
	}

	t.Run("invalid create is a validation error and creates nothing", func(t *testing.T) {
		var description = testDescription("cron-invalid")
		var uuid, err = sys.CronJobCreate(system.CronJob{
			Enabled: "0", Command: harmlessCronCommand, Hours: "25", Description: description,
		})
		if uuid != "" {
			cleanupCronJob(t, sys, uuid)
		}
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("want *ValidationError, got %T: %v (uuid %q)", err, err, uuid)
		}
		if _, ok := validationErr.Validations["job.hours"]; !ok {
			t.Errorf("no job.hours validation: %v", validationErr.Validations)
		}
		var jobs, _ = sys.CronJobSearch(description)
		if len(jobs) != 0 {
			t.Errorf("a failed create left %+v", jobs)
		}
	})
}

func TestCronJobAmbiguousDescription(t *testing.T) {
	var sys = systemApi(t)
	var first, job = createCronJob(t, sys, "cron-dup", system.CronJob{})
	var second, _ = createCronJob(t, sys, "cron-dup", system.CronJob{})

	var _, err = sys.CronJobGetByDescription(job.Description)
	var tooMany *api.TooManyFoundError
	if !errors.As(err, &tooMany) {
		t.Fatalf("want *TooManyFoundError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Errorf("error does not list both uuids %s, %s: %v", first, second, err)
	}
}

func TestCronReconfigure(t *testing.T) {
	var sys = systemApi(t)
	if err := sys.CronReconfigure(); err != nil {
		t.Fatal(err)
	}
}
