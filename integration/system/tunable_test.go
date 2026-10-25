//go:build integration

package integrationsystem

import (
	"errors"
	"strings"
	"sync"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
)

// safeTunable is a harmless kernel knob (timestamps in the kernel message buffer), not networking or security
// related. It is only ever configured to its current runtime value, so applying changes nothing at runtime
const safeTunable = "kern.msgbuf_show_timestamp"

// runtimeValue returns the runtime value of safeTunable from its built-in row, skipping the test when the
// tunable is configured already (by someone else) or not offered by the instance
func runtimeValue(t *testing.T, sys *system.SystemApi) (string, system.Tunable) {
	t.Helper()
	var rows, err = sys.TunableFindByName(safeTunable)
	if err != nil {
		t.Fatalf("TunableFindByName(%s): %v", safeTunable, err)
	}
	if len(rows) != 1 || !rows[0].IsBuiltin() || rows[0].Type != "w" {
		t.Skipf("%s is not a single unconfigured runtime built-in here: %+v", safeTunable, rows)
	}
	return rows[0].Value, rows[0]
}

var applyOnce sync.Mutex

// cleanupTunable removes the configured entry uuid and applies the tunables afterwards
func cleanupTunable(t *testing.T, sys *system.SystemApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := sys.TunableRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of tunable %s failed: %v", uuid, err)
		}
	})
}

// applyTunablesOnCleanup applies the tunables once all other cleanups of the test (registered later) ran
func applyTunablesOnCleanup(t *testing.T, sys *system.SystemApi) {
	t.Helper()
	t.Cleanup(func() {
		applyOnce.Lock()
		defer applyOnce.Unlock()
		if err := sys.TunableReconfigure(); err != nil {
			t.Errorf("applying the tunables after the cleanup failed: %v", err)
		}
	})
}

func TestTunableList(t *testing.T) {
	var sys = systemApi(t)
	var tunables, err = sys.TunableList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(tunables) == 0 {
		t.Fatal("no tunables")
	}
	for _, tunable := range tunables {
		if tunable.Uuid == "" || tunable.Tunable == "" && !tunable.IsBuiltin() && !ownedByRun(tunable.Description) {
			t.Errorf("incomplete tunable %+v", tunable)
		}
	}
	var filtered, _ = sys.TunableList(safeTunable)
	if len(filtered) == 0 || len(filtered) >= len(tunables) {
		t.Errorf("search %q returned %d of %d", safeTunable, len(filtered), len(tunables))
	}
}

func TestTunableLifecycle(t *testing.T) {
	var sys = systemApi(t)
	var runtime, builtin = runtimeValue(t, sys)
	applyTunablesOnCleanup(t, sys)

	var description = testDescription("tunable-lifecycle")
	var uuid, err = sys.TunableCreate(system.Tunable{Tunable: safeTunable, Value: runtime, Description: description})
	if err != nil {
		t.Fatalf("TunableCreate: %v", err)
	}
	cleanupTunable(t, sys, uuid)

	t.Run("the override replaces the built-in row", func(t *testing.T) {
		var tunable, err = sys.TunableGetByName(safeTunable)
		if err != nil {
			t.Fatal(err)
		}
		if tunable.Uuid != uuid || tunable.IsBuiltin() || tunable.Value != runtime || tunable.Description != description ||
			tunable.DefaultValue != builtin.DefaultValue {
			t.Errorf("unexpected row %+v (built-in was %+v)", tunable, builtin)
		}
		if got, err := sys.TunableGet(uuid); err != nil || got.Uuid != uuid {
			t.Errorf("TunableGet: %+v, %v", got, err)
		}
		if _, err := sys.TunableGet(builtin.Uuid); !api.IsNotFound(err) {
			t.Errorf("the built-in row is still listed: %v", err)
		}
	})

	t.Run("set updates the existing entry", func(t *testing.T) {
		var newDescription = description + " updated"
		var setUuid, created, err = sys.TunableSet(safeTunable, runtime, &newDescription)
		if err != nil {
			t.Fatal(err)
		}
		if setUuid != uuid || created {
			t.Errorf("TunableSet: uuid %s created %v, want %s false", setUuid, created, uuid)
		}
		var tunable, _ = sys.TunableGet(uuid)
		if tunable.Description != newDescription || tunable.Value != runtime || tunable.Tunable != safeTunable {
			t.Errorf("after set: %+v", tunable)
		}

		// without description the description is kept
		if _, _, err := sys.TunableSet(safeTunable, runtime, nil); err != nil {
			t.Fatal(err)
		}
		if tunable, _ = sys.TunableGet(uuid); tunable.Description != newDescription {
			t.Errorf("description changed to %q", tunable.Description)
		}
	})

	t.Run("update sends only the given fields", func(t *testing.T) {
		if err := sys.TunableUpdate(uuid, system.TunableFields{"descr": description}); err != nil {
			t.Fatal(err)
		}
		var tunable, _ = sys.TunableGet(uuid)
		if tunable.Description != description || tunable.Value != runtime || tunable.Tunable != safeTunable {
			t.Errorf("after update: %+v", tunable)
		}
	})

	t.Run("a second entry for the name makes lookups ambiguous", func(t *testing.T) {
		var second, err = sys.TunableCreate(system.Tunable{Tunable: safeTunable, Value: runtime, Description: testDescription("tunable-dup")})
		if err != nil {
			t.Fatal(err)
		}
		cleanupTunable(t, sys, second)

		var tooMany *api.TooManyFoundError
		if _, err := sys.TunableGetByName(safeTunable); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), second) {
			t.Errorf("TunableGetByName: want *TooManyFoundError naming %s, got %T: %v", second, err, err)
		}
		if _, _, err := sys.TunableSet(safeTunable, runtime, nil); !errors.As(err, &tooMany) {
			t.Errorf("TunableSet: want *TooManyFoundError, got %T: %v", err, err)
		}
		if err := sys.TunableRemove(second); err != nil {
			t.Errorf("remove the second entry: %v", err)
		}
	})

	t.Run("remove brings back the built-in row", func(t *testing.T) {
		if err := sys.TunableRemove(uuid); err != nil {
			t.Fatal(err)
		}
		var tunable, err = sys.TunableGetByName(safeTunable)
		if err != nil {
			t.Fatal(err)
		}
		if tunable.Uuid != builtin.Uuid || !tunable.IsBuiltin() {
			t.Errorf("after remove: %+v, want the built-in %+v", tunable, builtin)
		}
		if err := sys.TunableRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want *NotFoundError, got %T: %v", err, err)
		}
	})
}

func TestTunableErrors(t *testing.T) {
	var sys = systemApi(t)
	const unknown = "00000000-0000-4000-8000-0000000000c8"

	t.Run("update of an unknown uuid", func(t *testing.T) {
		// OPNsense 26.7 set_item/<unknown uuid> CREATES an entry with that uuid (an upsert), so remove it should
		// the library let that happen. The value stays empty, an entry without name and value is skipped on apply
		cleanupTunable(t, sys, unknown)
		var err = sys.TunableUpdate(unknown, system.TunableFields{"descr": testDescription("tunable-unknown")})
		if !api.IsNotFound(err) {
			t.Errorf("want *NotFoundError, got %T: %v", err, err)
		}
		if leftover, getErr := sys.TunableGet(unknown); getErr == nil {
			t.Errorf("updating an unknown uuid created an entry: %+v", leftover)
		}
	})

	if err := sys.TunableRemove(unknown); !api.IsNotFound(err) {
		t.Errorf("remove unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.TunableGet(unknown); !api.IsNotFound(err) {
		t.Errorf("get unknown: want *NotFoundError, got %T: %v", err, err)
	}
	if _, err := sys.TunableGetByName("a8.sys.no.such.tunable"); !api.IsNotFound(err) {
		t.Errorf("get unknown name: want *NotFoundError, got %T: %v", err, err)
	}

	t.Run("built-in rows can not be removed or updated", func(t *testing.T) {
		var _, builtin = runtimeValue(t, sys)
		if err := sys.TunableRemove(builtin.Uuid); err == nil {
			t.Errorf("removing the built-in %s succeeded", builtin.Uuid)
		}
		if err := sys.TunableUpdate(builtin.Uuid, system.TunableFields{"descr": testDescription("builtin")}); err == nil {
			t.Errorf("updating the built-in %s succeeded", builtin.Uuid)
		}
	})

	t.Run("invalid names and values are rejected before reaching the API", func(t *testing.T) {
		for _, tunable := range []system.Tunable{
			{Tunable: "", Value: "1"},
			{Tunable: "kern.a8 sys", Value: "1"},
			{Tunable: safeTunable, Value: "0\nkern.evil=1"},
		} {
			tunable.Description = testDescription("tunable-invalid")
			var uuid, err = sys.TunableCreate(tunable)
			if uuid != "" {
				cleanupTunable(t, sys, uuid)
			}
			if err == nil {
				t.Errorf("TunableCreate(%q, %q) succeeded", tunable.Tunable, tunable.Value)
			}
		}
		var rows, _ = sys.TunableList(testDescription("tunable-invalid"))
		if len(rows) != 0 {
			t.Errorf("invalid creates left %+v", rows)
		}
	})
}
