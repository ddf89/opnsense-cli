//go:build integration

package integrationsystem

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// safeSyslogHost is from TEST-NET-1 (RFC 5737), nothing is ever sent there since the destinations stay disabled
const safeSyslogHost = "192.0.2.10"

// createDestination creates a DISABLED destination to safeSyslogHost owned by this run and registers its removal
func createDestination(t *testing.T, sys *system.SystemApi, label string, destination system.LoggingDestination) (string, system.LoggingDestination) {
	t.Helper()
	destination.Enabled = "0"
	destination.Hostname = safeSyslogHost
	destination.Description = testDescription(label)
	if destination.Transport == "" {
		destination.Transport = "udp4"
	}
	var uuid, err = sys.LoggingDestinationCreate(destination)
	if err != nil {
		t.Fatalf("LoggingDestinationCreate(%+v): %v", destination, err)
	}
	if uuid == "" {
		t.Fatalf("LoggingDestinationCreate returned no uuid")
	}
	cleanupDestination(t, sys, uuid)
	return uuid, destination
}

func cleanupDestination(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.LoggingDestinationRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of logging destination %s failed: %v", uuid, err)
		}
	})
}

// snapshotLoggingGeneral reads the general settings and restores them exactly (followed by a reconfigure) on cleanup
func snapshotLoggingGeneral(t *testing.T, sys *system.SystemApi) system.LoggingGeneral {
	t.Helper()
	var before, err = sys.LoggingGeneralGet()
	if err != nil {
		t.Fatalf("LoggingGeneralGet: %v", err)
	}
	t.Cleanup(func() {
		var restore = system.LoggingGeneralFields{
			Enabled: strPtr(before.Enabled), LogLocal: strPtr(before.LogLocal),
			MaxPreserve: strPtr(before.MaxPreserve), MaxFileSize: strPtr(before.MaxFileSize),
		}
		if err := sys.LoggingGeneralSet(restore); err != nil {
			t.Errorf("restoring the logging settings %+v failed: %v", before, err)
			return
		}
		if after, err := sys.LoggingGeneralGet(); err != nil || after != before {
			t.Errorf("logging settings not restored: got %+v (%v), want %+v", after, err, before)
		}
		if err := sys.LoggingServiceReconfigure(); err != nil {
			t.Errorf("reconfigure after restoring the logging settings: %v", err)
		}
	})
	return before
}

func TestLoggingGeneral(t *testing.T) {
	var sys = systemApi(t)
	var before = snapshotLoggingGeneral(t, sys)
	if before.Enabled == "" || before.LogLocal == "" {
		t.Errorf("incomplete general settings: %+v", before)
	}

	// change one harmless field to a different valid value
	var preserve, convErr = strconv.Atoi(before.MaxPreserve)
	if convErr != nil {
		preserve = 31
	}
	var changed = strconv.Itoa(preserve - 1)
	if preserve <= 1 {
		changed = strconv.Itoa(preserve + 1)
	}

	t.Run("set changes only the given field", func(t *testing.T) {
		if err := sys.LoggingGeneralSet(system.LoggingGeneralFields{MaxPreserve: &changed}); err != nil {
			t.Fatal(err)
		}
		var after, err = sys.LoggingGeneralGet()
		if err != nil {
			t.Fatal(err)
		}
		var want = before
		want.MaxPreserve = changed
		if after != want {
			t.Errorf("after set: got %+v, want %+v", after, want)
		}
	})

	t.Run("invalid value is a validation error and changes nothing", func(t *testing.T) {
		var err = sys.LoggingGeneralSet(system.LoggingGeneralFields{MaxPreserve: strPtr("not-a-number")})
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("want *ValidationError, got %T: %v", err, err)
		}
		if _, ok := validationErr.Validations["syslog.general.maxpreserve"]; !ok {
			t.Errorf("no syslog.general.maxpreserve validation: %v", validationErr.Validations)
		}
		var after, _ = sys.LoggingGeneralGet()
		if after.MaxPreserve != changed {
			t.Errorf("maxpreserve is %q after a failed set, want %q", after.MaxPreserve, changed)
		}
	})
}

func TestLoggingDestinationLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var uuid, created = createDestination(t, sys, "dest-lifecycle", system.LoggingDestination{
		Transport: "udp4", Program: "filterlog,unbound", Level: "info,err", Facility: "kern,local0", Port: "1514",
	})

	t.Run("get returns the created fields", func(t *testing.T) {
		var destination, err = sys.LoggingDestinationGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var want = created
		want.Uuid = uuid
		want.Rfc5424 = "0"
		want.Certificate = ""
		if destination != want {
			t.Errorf("get:\n got  %+v\n want %+v", destination, want)
		}
	})

	t.Run("list and find by exact description", func(t *testing.T) {
		var destinations, err = sys.LoggingDestinationList(created.Description)
		if err != nil {
			t.Fatal(err)
		}
		if len(destinations) != 1 || destinations[0].Uuid != uuid || destinations[0].Enabled != "0" ||
			destinations[0].Hostname != safeSyslogHost || destinations[0].Port != "1514" {
			t.Errorf("list %q returned %+v", created.Description, destinations)
		}
		var found, findErr = sys.LoggingDestinationFind(created.Description)
		if findErr != nil || found.Uuid != uuid {
			t.Errorf("find: %+v, %v", found, findErr)
		}
		if _, err := sys.LoggingDestinationFind(created.Description[:len(created.Description)-1]); !api.IsNotFound(err) {
			t.Errorf("find by a prefix: want *NotFoundError, got %T: %v", err, err)
		}
	})

	t.Run("update changes only the given fields", func(t *testing.T) {
		if err := sys.LoggingDestinationUpdate(uuid, system.LoggingDestinationFields{Port: strPtr("1515"), Level: strPtr("err")}); err != nil {
			t.Fatal(err)
		}
		var destination, err = sys.LoggingDestinationGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		var want = created
		want.Uuid, want.Rfc5424, want.Port, want.Level = uuid, "0", "1515", "err"
		if destination != want {
			t.Errorf("after update:\n got  %+v\n want %+v", destination, want)
		}
	})

	t.Run("invalid update is a validation error", func(t *testing.T) {
		// an IPv4 host with an IPv6 transport
		var err = sys.LoggingDestinationUpdate(uuid, system.LoggingDestinationFields{Transport: strPtr("udp6")})
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("want *ValidationError, got %T: %v", err, err)
		}
		var destination, _ = sys.LoggingDestinationGet(uuid)
		if destination.Transport != "udp4" {
			t.Errorf("transport changed to %q by a failed update", destination.Transport)
		}
	})

	t.Run("disabling a disabled destination changes nothing", func(t *testing.T) {
		var changed, err = sys.LoggingDestinationSetEnabled(uuid, false)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Errorf("changed = true for an already disabled destination")
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := sys.LoggingDestinationRemove(uuid); err != nil {
			t.Fatal(err)
		}
		if _, err := sys.LoggingDestinationGet(uuid); !api.IsNotFound(err) {
			t.Errorf("get after remove: want *NotFoundError, got %T: %v", err, err)
		}
		if err := sys.LoggingDestinationRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want *NotFoundError, got %T: %v", err, err)
		}
	})
}

func TestLoggingDestinationErrors(t *testing.T) {
	var sys = systemApi(t)
	const unknown = "00000000-0000-4000-8000-0000000000a8"

	if _, err := sys.LoggingDestinationGet(unknown); !api.IsNotFound(err) {
		t.Errorf("get unknown: want *NotFoundError, got %T: %v", err, err)
	}
	// OPNsense 26.7 set_destination/<unknown uuid> CREATES a destination with that uuid when the fields are valid
	// (an upsert). Only the port is sent here, so it can never be valid; remove it anyway should it ever exist
	cleanupDestination(t, sys, unknown)
	if err := sys.LoggingDestinationUpdate(unknown, system.LoggingDestinationFields{Port: strPtr("1516")}); !api.IsNotFound(err) {
		t.Errorf("update unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if err := sys.LoggingDestinationRemove(unknown); !api.IsNotFound(err) {
		t.Errorf("remove unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.LoggingDestinationSetEnabled(unknown, false); !api.IsNotFound(err) {
		t.Errorf("disable unknown: want *NotFoundError, got %T: %v", err, err)
	}

	t.Run("invalid create is a validation error and creates nothing", func(t *testing.T) {
		var description = testDescription("dest-invalid")
		var uuid, err = sys.LoggingDestinationCreate(system.LoggingDestination{
			Enabled: "0", Transport: "udp6", Hostname: safeSyslogHost, Description: description,
		})
		if uuid != "" {
			cleanupDestination(t, sys, uuid)
		}
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("want *ValidationError, got %T: %v (uuid %q)", err, err, uuid)
		}
		var destinations, _ = sys.LoggingDestinationList(description)
		if len(destinations) != 0 {
			t.Errorf("a failed create left %+v", destinations)
		}
	})
}

func TestLoggingDestinationAmbiguousDescription(t *testing.T) {
	var sys = systemApi(t)
	var first, destination = createDestination(t, sys, "dest-dup", system.LoggingDestination{})
	var second, _ = createDestination(t, sys, "dest-dup", system.LoggingDestination{})

	var _, err = sys.LoggingDestinationFind(destination.Description)
	var tooMany *api.TooManyFoundError
	if !errors.As(err, &tooMany) {
		t.Fatalf("want *TooManyFoundError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Errorf("error does not list both uuids %s, %s: %v", first, second, err)
	}
}

func TestLoggingService(t *testing.T) {
	var sys = systemApi(t)

	var status, err = sys.LoggingServiceStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Errorf("syslog status %q, want running", status)
	}

	var stats, statsErr = sys.LoggingStats("")
	if statsErr != nil {
		t.Fatal(statsErr)
	}
	if len(stats) == 0 {
		t.Fatalf("no syslog-ng statistics")
	}
	var filtered, _ = sys.LoggingStats("GLOBAL")
	if len(filtered) == 0 || len(filtered) >= len(stats) {
		t.Errorf("filtering by %q returned %d of %d counters", "GLOBAL", len(filtered), len(stats))
	}
	for _, stat := range filtered {
		if !strings.Contains(strings.ToLower(stat.SourceName+stat.SourceId+stat.SourceInstance+stat.Description+stat.State+stat.Type+stat.Number), "global") {
			t.Errorf("counter does not match the filter: %+v", stat)
		}
	}

	if err := sys.LoggingServiceReconfigure(); err != nil {
		t.Errorf("reconfigure: %v", err)
	}
}
