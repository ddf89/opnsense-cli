//go:build integration

package integration

import (
	"testing"
	"time"

	"opnsense-cli/opnsense/api/unbound"
)

func createUnboundOverride(t *testing.T, unboundApi *unbound.UnboundApi, hostOverride unbound.HostOverride) string {
	t.Helper()
	var uuid, err = unboundApi.HostOverrideCreate(hostOverride)
	cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
	if err != nil {
		t.Fatalf("HostOverrideCreate %s.%s (%s): %v", hostOverride.Host, hostOverride.Domain, hostOverride.Rr, err)
	}
	if uuid == "" {
		t.Fatalf("HostOverrideCreate %s.%s returned no uuid", hostOverride.Host, hostOverride.Domain)
	}
	return uuid
}

func getUnboundOverride(t *testing.T, unboundApi *unbound.UnboundApi, uuid string) unbound.HostOverride {
	t.Helper()
	var hostOverride, err = unboundApi.HostOverrideGet(uuid)
	if err != nil {
		t.Fatalf("HostOverrideGet %s: %v", uuid, err)
	}
	return hostOverride
}

func TestUnboundHostOverrideLifecycle(t *testing.T) {
	var unboundApi = unboundApi(t)
	var domain = testDomain("uh")

	var fooUuid = createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "foo", Domain: domain, Ip: "10.4.4.4", Description: "a7 integration foo"})
	var foobarUuid = createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "foobar", Domain: domain, Rr: "A", Ip: "10.4.4.5", Description: "a7 integration foobar"})

	t.Run("search returns the stored values incl. defaults", func(t *testing.T) {
		var overrides, err = unboundApi.HostOverrideSearch(domain)
		if err != nil {
			t.Fatalf("HostOverrideSearch: %v", err)
		}
		if len(overrides) != 2 {
			t.Errorf("want 2 host overrides in %s, got %+v", domain, overrides)
		}
		var want = unbound.HostOverride{
			Uuid: fooUuid, Enabled: "1", Host: "foo", Domain: domain, Ip: "10.4.4.4", Rr: "A", Addptr: "1", Description: "a7 integration foo",
		}
		if got := getUnboundOverride(t, unboundApi, fooUuid); got != want {
			t.Errorf("stored host override differs\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("FQDN lookup is an exact match", func(t *testing.T) {
		var foo, err = unboundApi.HostEntryGetByFQDN("foo", domain)
		if err != nil || foo.Uuid != fooUuid {
			t.Fatalf("HostEntryGetByFQDN foo: want %s, got %s (%v)", fooUuid, foo.Uuid, err)
		}
		var matches, findErr = unboundApi.HostOverrideFindByFQDN("FOO", domain+".", "")
		if findErr != nil || len(matches) != 1 || matches[0].Uuid != fooUuid {
			t.Errorf("HostOverrideFindByFQDN FOO (case-insensitive, trailing dot): want only %s, got %+v (%v)", fooUuid, matches, findErr)
		}
		var foobar, foobarErr = unboundApi.HostEntryGetByFQDN("foobar", domain)
		if foobarErr != nil || foobar.Uuid != foobarUuid {
			t.Errorf("HostEntryGetByFQDN foobar: want %s, got %s (%v)", foobarUuid, foobar.Uuid, foobarErr)
		}
		_, err = unboundApi.HostEntryGetByFQDN("fo", domain)
		requireNotFound(t, err, "HostEntryGetByFQDN fo (prefix)")
		_, err = unboundApi.HostEntryGetByFQDN("foo", "x"+domain)
		requireNotFound(t, err, "HostEntryGetByFQDN foo in another domain")

		var exists, existsErr = unboundApi.HostEntryExists("foo", domain)
		if existsErr != nil || !exists {
			t.Errorf("HostEntryExists foo: %v (%v)", exists, existsErr)
		}
		exists, existsErr = unboundApi.HostEntryExists("nothere", domain)
		if existsErr != nil || exists {
			t.Errorf("HostEntryExists nothere: %v (%v)", exists, existsErr)
		}
	})

	t.Run("create or update on an existing FQDN updates", func(t *testing.T) {
		var uuid, err = unboundApi.HostOverrideCreateOrUpdate(unbound.HostOverride{Host: "foo", Domain: domain, Rr: "A", Ip: "10.4.4.6", Ttl: "900", Description: "updated"})
		if uuid != fooUuid {
			cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
		}
		if err != nil || uuid != fooUuid {
			t.Fatalf("want update of %s, got %s (%v)", fooUuid, uuid, err)
		}
		var matches, _ = unboundApi.HostOverrideFindByFQDN("foo", domain, "")
		if len(matches) != 1 {
			t.Fatalf("want exactly one foo, got %+v", matches)
		}
		if foo := matches[0]; foo.Ip != "10.4.4.6" || foo.Ttl != "900" || foo.Description != "updated" || foo.Enabled != "1" || foo.Rr != "A" {
			t.Errorf("create-or-update did not update: %+v", foo)
		}
	})

	t.Run("update without the omitempty fields keeps them", func(t *testing.T) {
		var foo = getUnboundOverride(t, unboundApi, fooUuid)
		foo.Enabled = "0"
		foo.Addptr = "0"
		if _, err := unboundApi.HostOverrideUpdate(foo); err != nil {
			t.Fatalf("HostOverrideUpdate: %v", err)
		}
		// Enabled, Rr and Addptr are not sent when empty, so OPNsense keeps them
		if _, err := unboundApi.HostOverrideUpdate(unbound.HostOverride{Uuid: fooUuid, Host: "foo", Domain: domain, Ip: "10.4.4.7"}); err != nil {
			t.Fatalf("HostOverrideUpdate: %v", err)
		}
		var got = getUnboundOverride(t, unboundApi, fooUuid)
		if got.Enabled != "0" || got.Addptr != "0" || got.Rr != "A" || got.Ip != "10.4.4.7" {
			t.Errorf("want enabled 0, addptr 0, rr A, ip 10.4.4.7, got %+v", got)
		}
	})

	t.Run("validation errors name the fields", func(t *testing.T) {
		var uuid, err = unboundApi.HostOverrideCreate(unbound.HostOverride{Host: "bogus", Domain: domain, Rr: "BOGUS", Ip: "10.4.4.4"})
		cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
		asValidationError(t, err, "host.rr")

		uuid, err = unboundApi.HostOverrideCreate(unbound.HostOverride{Host: "badip", Domain: domain, Rr: "A", Ip: "10.4.4.999"})
		cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
		asValidationError(t, err, "host.server")

		var foo = getUnboundOverride(t, unboundApi, fooUuid)
		foo.Ip = "not-an-ip"
		_, err = unboundApi.HostOverrideUpdate(foo)
		asValidationError(t, err, "host.server")
	})

	t.Run("remove", func(t *testing.T) {
		if err := unboundApi.HostEntryRemove(foobarUuid); err != nil {
			t.Fatalf("HostEntryRemove: %v", err)
		}
		requireNotFound(t, unboundApi.HostEntryRemove(foobarUuid), "second HostEntryRemove")
		var _, err = unboundApi.HostOverrideGet(foobarUuid)
		requireNotFound(t, err, "HostOverrideGet after remove")
		_, err = unboundApi.HostEntryGetByFQDN("foobar", domain)
		requireNotFound(t, err, "HostEntryGetByFQDN after remove")
	})

	// set_host_override is an upsert on unknown (well-formed v4) uuids, so HostOverrideUpdate must check the uuid exists.
	// The cleanup registered on create removes a resurrected entry
	t.Run("update of a removed uuid does not resurrect it", func(t *testing.T) {
		var _, err = unboundApi.HostOverrideUpdate(unbound.HostOverride{Uuid: foobarUuid, Host: "ghost", Domain: domain, Rr: "A", Ip: "10.4.9.9"})
		requireNotFound(t, err, "HostOverrideUpdate after remove")
		if ghost, getErr := unboundApi.HostOverrideGet(foobarUuid); getErr == nil {
			t.Errorf("HostOverrideUpdate of a removed uuid created a new entry: %+v", ghost)
		}
	})
}

func TestUnboundRecordTypes(t *testing.T) {
	var unboundApi = unboundApi(t)
	var domain = testDomain("ur")

	var records = []unbound.HostOverride{
		{Host: "v6", Domain: domain, Rr: "AAAA", Ip: "fd00::4", Ttl: "600", Addptr: "0", Description: "aaaa"},
		{Host: "mail", Domain: domain, Rr: "MX", Mxprio: "10", Mx: "mx1." + domain, Ttl: "3600", Description: "mx"},
		{Host: "txt", Domain: domain, Rr: "TXT", Txtdata: "v=spf1 ip4:10.0.0.0/8 -all", Ttl: "120", Description: "txt"},
	}
	for _, record := range records {
		t.Run(record.Rr, func(t *testing.T) {
			var uuid = createUnboundOverride(t, unboundApi, record)
			var want = record
			want.Uuid = uuid
			want.Enabled = "1"
			if want.Addptr == "" {
				want.Addptr = "1"
			}
			if got := getUnboundOverride(t, unboundApi, uuid); got != want {
				t.Errorf("record does not round-trip\n got: %+v\nwant: %+v", got, want)
			}
			var byType, err = unboundApi.HostOverrideGetByFQDNAndRr(record.Host, domain, record.Rr)
			if err != nil || byType.Uuid != uuid {
				t.Errorf("HostOverrideGetByFQDNAndRr: want %s, got %s (%v)", uuid, byType.Uuid, err)
			}
		})
	}

	t.Run("several record types for one FQDN", func(t *testing.T) {
		var aUuid = createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "dual", Domain: domain, Rr: "A", Ip: "10.4.5.1"})
		var aaaaUuid = createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "dual", Domain: domain, Rr: "AAAA", Ip: "fd00::451"})

		var _, err = unboundApi.HostEntryGetByFQDN("dual", domain)
		requireTooManyFound(t, err, "HostEntryGetByFQDN with A and AAAA")

		var aaaa, aaaaErr = unboundApi.HostOverrideGetByFQDNAndRr("dual", domain, "aaaa")
		if aaaaErr != nil || aaaa.Uuid != aaaaUuid {
			t.Errorf("HostOverrideGetByFQDNAndRr AAAA: want %s, got %s (%v)", aaaaUuid, aaaa.Uuid, aaaaErr)
		}

		// create-or-update with a record type only touches that record
		var uuid, updateErr = unboundApi.HostOverrideCreateOrUpdate(unbound.HostOverride{Host: "dual", Domain: domain, Rr: "AAAA", Ip: "fd00::452"})
		if uuid != aaaaUuid {
			cleanupRemove(t, "unbound host override", uuid, unboundApi.HostEntryRemove)
		}
		if updateErr != nil || uuid != aaaaUuid {
			t.Fatalf("HostOverrideCreateOrUpdate AAAA: want %s, got %s (%v)", aaaaUuid, uuid, updateErr)
		}
		if a := getUnboundOverride(t, unboundApi, aUuid); a.Ip != "10.4.5.1" {
			t.Errorf("the A record changed: %+v", a)
		}
		if aaaa := getUnboundOverride(t, unboundApi, aaaaUuid); aaaa.Ip != "fd00::452" {
			t.Errorf("the AAAA record was not updated: %+v", aaaa)
		}
	})
}

func TestUnboundService(t *testing.T) {
	var unboundApi = unboundApi(t)

	var status, err = unboundApi.ServiceStatus()
	if err != nil || status != "running" {
		t.Fatalf("ServiceStatus: want running, got %q (%v)", status, err)
	}
	if err := unboundApi.ServiceReconfigure(); err != nil {
		t.Errorf("ServiceReconfigure: %v", err)
	}

	// the only service restart of the whole run
	if err := unboundApi.ServiceRestart(); err != nil {
		t.Errorf("ServiceRestart: %v", err)
	}
	var deadline = time.Now().Add(30 * time.Second)
	for {
		status, err = unboundApi.ServiceStatus()
		if err == nil && status == "running" || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || status != "running" {
		t.Errorf("after restart: want running, got %q (%v)", status, err)
	}
}

// TestUnboundHostOverrideResolves checks that a host override is served by unbound after a reconfigure
func TestUnboundHostOverrideResolves(t *testing.T) {
	var unboundApi = unboundApi(t)
	requireDnsReachable(t, unboundDnsPort)

	var domain = testDomain("urs")
	createUnboundOverride(t, unboundApi, unbound.HostOverride{Host: "resolve", Domain: domain, Rr: "A", Ip: "10.4.6.6"})
	if err := unboundApi.ServiceReconfigure(); err != nil {
		t.Fatalf("ServiceReconfigure: %v", err)
	}
	requireResolves(t, unboundDnsPort, "resolve."+domain, "10.4.6.6")
}
