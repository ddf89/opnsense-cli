//go:build integration

package integration

import (
	"strconv"
	"testing"

	"opnsense-cli/opnsense/api/dnsmasq"
)

// createDnsmasqHost creates host and registers its removal
func createDnsmasqHost(t *testing.T, dnsmasqApi *dnsmasq.DnsmasqApi, host dnsmasq.Host) string {
	t.Helper()
	var uuid, err = dnsmasqApi.HostCreate(host)
	cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
	if err != nil {
		t.Fatalf("HostCreate %s: %v", host.FQDN(), err)
	}
	if uuid == "" {
		t.Fatalf("HostCreate %s returned no uuid", host.FQDN())
	}
	return uuid
}

func createDnsmasqDomain(t *testing.T, dnsmasqApi *dnsmasq.DnsmasqApi, domainOverride dnsmasq.DomainOverride) string {
	t.Helper()
	var uuid, err = dnsmasqApi.DomainOverrideCreate(domainOverride)
	cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)
	if err != nil {
		t.Fatalf("DomainOverrideCreate %s: %v", domainOverride.Domain, err)
	}
	if uuid == "" {
		t.Fatalf("DomainOverrideCreate %s returned no uuid", domainOverride.Domain)
	}
	return uuid
}

func findHost(t *testing.T, hosts []dnsmasq.Host, uuid string) (dnsmasq.Host, bool) {
	t.Helper()
	for _, host := range hosts {
		if host.Uuid == uuid {
			return host, true
		}
	}
	return dnsmasq.Host{}, false
}

func TestDnsmasqHostLifecycle(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("dh")

	var fooUuid = createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{
		Host:        "foo",
		Domain:      domain,
		Ip:          "10.1.1.1,fd00::1",
		Cnames:      "cname1." + domain + ",cname2." + domain,
		Aliases:     "alias1." + domain,
		Description: "a7 integration foo",
		Comments:    "comment foo",
	})
	var foobarUuid = createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "foobar", Domain: domain, Ip: "10.1.1.2", Description: "a7 integration foobar"})

	t.Run("search returns the stored values", func(t *testing.T) {
		var hosts, err = dnsmasqApi.HostList(domain)
		if err != nil {
			t.Fatalf("HostList: %v", err)
		}
		if len(hosts) != 2 {
			t.Errorf("want 2 hosts in %s, got %d: %+v", domain, len(hosts), hosts)
		}
		var foo, found = findHost(t, hosts, fooUuid)
		if !found {
			t.Fatalf("created host %s not in search result %+v", fooUuid, hosts)
		}
		var want = dnsmasq.Host{
			Uuid:        fooUuid,
			Host:        "foo",
			Domain:      domain,
			Local:       "0",
			Ip:          "10.1.1.1,fd00::1",
			Cnames:      "cname1." + domain + ",cname2." + domain,
			Aliases:     "alias1." + domain,
			Ignore:      "0",
			Description: "a7 integration foo",
			Comments:    "comment foo",
		}
		if foo != want {
			t.Errorf("stored host differs\n got: %+v\nwant: %+v", foo, want)
		}

		var byUuid, getErr = dnsmasqApi.HostGet(fooUuid)
		if getErr != nil {
			t.Fatalf("HostGet: %v", getErr)
		}
		if byUuid != foo {
			t.Errorf("HostGet differs from the search row\n got: %+v\nwant: %+v", byUuid, foo)
		}
	})

	t.Run("FQDN lookup is an exact match", func(t *testing.T) {
		var foo, err = dnsmasqApi.HostGetByFQDN("foo", domain)
		if err != nil {
			t.Fatalf("HostGetByFQDN foo: %v", err)
		}
		if foo.Uuid != fooUuid {
			t.Errorf("HostGetByFQDN foo returned %s (%s), want %s", foo.Uuid, foo.FQDN(), fooUuid)
		}

		var matches, findErr = dnsmasqApi.HostFindByFQDN("FOO", domain)
		if findErr != nil {
			t.Fatalf("HostFindByFQDN FOO: %v", findErr)
		}
		if len(matches) != 1 || matches[0].Uuid != fooUuid {
			t.Errorf("HostFindByFQDN FOO (case-insensitive) want only %s, got %+v", fooUuid, matches)
		}

		var foobar, foobarErr = dnsmasqApi.HostGetByFQDN("foobar", domain)
		if foobarErr != nil || foobar.Uuid != foobarUuid {
			t.Errorf("HostGetByFQDN foobar: want %s, got %s (%v)", foobarUuid, foobar.Uuid, foobarErr)
		}

		_, err = dnsmasqApi.HostGetByFQDN("fo", domain)
		requireNotFound(t, err, "HostGetByFQDN fo (prefix)")
		_, err = dnsmasqApi.HostGetByFQDN("foo", "other."+domain)
		requireNotFound(t, err, "HostGetByFQDN foo in other domain")
		_, err = dnsmasqApi.HostGetByFQDN("foo", "")
		requireNotFound(t, err, "HostGetByFQDN foo without domain")
	})

	t.Run("partial update keeps untouched fields", func(t *testing.T) {
		if err := dnsmasqApi.HostUpdate(fooUuid, dnsmasq.HostFields{"descr": "changed description"}); err != nil {
			t.Fatalf("HostUpdate descr: %v", err)
		}
		var foo, err = dnsmasqApi.HostGet(fooUuid)
		if err != nil {
			t.Fatalf("HostGet: %v", err)
		}
		if foo.Description != "changed description" {
			t.Errorf("description not updated: %q", foo.Description)
		}
		if foo.Ip != "10.1.1.1,fd00::1" || foo.Cnames != "cname1."+domain+",cname2."+domain || foo.Aliases != "alias1."+domain || foo.Comments != "comment foo" {
			t.Errorf("set_host is not a merge, untouched fields changed: %+v", foo)
		}

		// an empty value clears a field, the rest is kept
		if err := dnsmasqApi.HostUpdate(fooUuid, dnsmasq.HostFields{"cnames": "", "ip": "10.1.1.3"}); err != nil {
			t.Fatalf("HostUpdate cnames/ip: %v", err)
		}
		foo, _ = dnsmasqApi.HostGet(fooUuid)
		if foo.Cnames != "" || foo.Ip != "10.1.1.3" || foo.Description != "changed description" || foo.Aliases != "alias1."+domain {
			t.Errorf("clearing cnames / changing ip went wrong: %+v", foo)
		}
	})

	t.Run("create or update on an existing FQDN updates", func(t *testing.T) {
		var uuid, updated, err = dnsmasqApi.HostCreateOrUpdate(dnsmasq.Host{Host: "foo", Domain: domain, Ip: "10.1.1.4", Description: "replaced"})
		if uuid != "" && uuid != fooUuid {
			cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
		}
		if err != nil {
			t.Fatalf("HostCreateOrUpdate: %v", err)
		}
		if !updated || uuid != fooUuid {
			t.Errorf("want update of %s, got uuid %s updated=%v", fooUuid, uuid, updated)
		}
		var matches, _ = dnsmasqApi.HostFindByFQDN("foo", domain)
		if len(matches) != 1 {
			t.Fatalf("want exactly one foo after create-or-update, got %d: %+v", len(matches), matches)
		}
		// create-or-update replaces all fields
		var foo = matches[0]
		if foo.Ip != "10.1.1.4" || foo.Description != "replaced" || foo.Aliases != "" || foo.Comments != "" {
			t.Errorf("create-or-update did not replace the fields: %+v", foo)
		}

		// and creates when the FQDN is new
		uuid, updated, err = dnsmasqApi.HostCreateOrUpdate(dnsmasq.Host{Host: "new", Domain: domain, Ip: "10.1.1.5"})
		cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
		if err != nil || updated || uuid == "" || uuid == fooUuid {
			t.Errorf("HostCreateOrUpdate of a new FQDN: uuid %q updated=%v err=%v", uuid, updated, err)
		}
	})

	t.Run("duplicate FQDN is reported as too many found", func(t *testing.T) {
		createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "dup", Domain: domain, Ip: "10.1.2.1"})
		createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "dup", Domain: domain, Ip: "10.1.2.2"})
		var _, err = dnsmasqApi.HostGetByFQDN("dup", domain)
		requireTooManyFound(t, err, "HostGetByFQDN dup")
		_, _, err = dnsmasqApi.HostCreateOrUpdate(dnsmasq.Host{Host: "dup", Domain: domain, Ip: "10.1.2.3"})
		requireTooManyFound(t, err, "HostCreateOrUpdate dup")
	})

	t.Run("validation errors name the fields", func(t *testing.T) {
		var uuid, err = dnsmasqApi.HostCreate(dnsmasq.Host{Host: "invalid", Domain: domain, Ip: "10.1.1.999"})
		cleanupRemove(t, "dnsmasq host", uuid, dnsmasqApi.HostRemove)
		asValidationError(t, err, "host.ip")

		err = dnsmasqApi.HostUpdate(fooUuid, dnsmasq.HostFields{"ip": "not-an-ip"})
		asValidationError(t, err, "host.ip")

		err = dnsmasqApi.HostUpdate(fooUuid, dnsmasq.HostFields{"hwaddr": "zz:zz"})
		asValidationError(t, err, "host.hwaddr")

		if err := dnsmasqApi.HostUpdate(fooUuid, dnsmasq.HostFields{"bogus": "x"}); err == nil {
			t.Errorf("HostUpdate with an unknown field: want an error")
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := dnsmasqApi.HostRemove(foobarUuid); err != nil {
			t.Fatalf("HostRemove: %v", err)
		}
		requireNotFound(t, dnsmasqApi.HostRemove(foobarUuid), "second HostRemove")
		var _, err = dnsmasqApi.HostGet(foobarUuid)
		requireNotFound(t, err, "HostGet after remove")
		requireNotFound(t, dnsmasqApi.HostUpdate(foobarUuid, dnsmasq.HostFields{"descr": "x"}), "HostUpdate after remove")
		_, err = dnsmasqApi.HostGetByFQDN("foobar", domain)
		requireNotFound(t, err, "HostGetByFQDN after remove")
	})

	// OPNsense 26.7 set_host is an upsert: an unknown (well-formed v4) uuid with valid fields creates the entry,
	// so HostUpdate must check that the uuid exists. The cleanup registered on create removes a resurrected entry
	t.Run("update of a removed uuid does not resurrect it", func(t *testing.T) {
		var err = dnsmasqApi.HostUpdate(foobarUuid, dnsmasq.Host{Host: "ghost", Domain: domain, Ip: "10.1.9.9"}.Fields())
		requireNotFound(t, err, "HostUpdate with all fields after remove")
		if ghost, getErr := dnsmasqApi.HostGet(foobarUuid); getErr == nil {
			t.Errorf("HostUpdate of a removed uuid created a new entry: %+v", ghost)
		}

		var uuid string
		uuid, _, err = dnsmasqApi.HostCreateOrUpdate(dnsmasq.Host{Uuid: foobarUuid, Host: "ghost2", Domain: domain, Ip: "10.1.9.8"})
		requireNotFound(t, err, "HostCreateOrUpdate with a removed uuid")
		if ghost, getErr := dnsmasqApi.HostGet(foobarUuid); getErr == nil {
			t.Errorf("HostCreateOrUpdate with a removed uuid silently recreated it as %s: %+v", uuid, ghost)
		}
	})
}

func TestDnsmasqDomainOverrideLifecycle(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var domain = testDomain("dd")
	var fooDomain = "foo." + domain
	var foobarDomain = "foobar." + domain

	var fooUuid = createDnsmasqDomain(t, dnsmasqApi, dnsmasq.DomainOverride{Domain: fooDomain, Ip: "10.2.2.2", Port: "5353", Description: "a7 integration foo"})
	var foobarUuid = createDnsmasqDomain(t, dnsmasqApi, dnsmasq.DomainOverride{Domain: foobarDomain, Ip: "fd00::53", Sequence: "7", Description: "a7 integration foobar"})
	// without a sequence OPNsense assigns the next free number (1 when there are no other domain overrides, but the
	// instance is shared), so the stored value is what the following checks expect to be kept
	var fooSequence = "1"
	if stored, err := dnsmasqApi.DomainOverrideGet(fooUuid); err == nil {
		if number, convErr := strconv.Atoi(stored.Sequence); convErr != nil || number < 1 {
			t.Errorf("OPNsense assigned no sequence: %+v", stored)
		} else {
			fooSequence = stored.Sequence
		}
	}

	t.Run("search returns the stored values", func(t *testing.T) {
		var overrides, err = dnsmasqApi.DomainOverrideList(domain)
		if err != nil {
			t.Fatalf("DomainOverrideList: %v", err)
		}
		if len(overrides) != 2 {
			t.Errorf("want 2 domain overrides in %s, got %+v", domain, overrides)
		}
		var want = map[string]dnsmasq.DomainOverride{
			fooUuid:    {Uuid: fooUuid, Sequence: fooSequence, Domain: fooDomain, Ip: "10.2.2.2", Port: "5353", Description: "a7 integration foo"},
			foobarUuid: {Uuid: foobarUuid, Sequence: "7", Domain: foobarDomain, Ip: "fd00::53", Description: "a7 integration foobar"},
		}
		for _, override := range overrides {
			if override != want[override.Uuid] {
				t.Errorf("stored domain override differs\n got: %+v\nwant: %+v", override, want[override.Uuid])
			}
		}

		var byUuid, getErr = dnsmasqApi.DomainOverrideGet(fooUuid)
		if getErr != nil {
			t.Fatalf("DomainOverrideGet: %v", getErr)
		}
		if byUuid != want[fooUuid] {
			t.Errorf("DomainOverrideGet differs\n got: %+v\nwant: %+v", byUuid, want[fooUuid])
		}
	})

	t.Run("domain lookup is an exact match", func(t *testing.T) {
		var foo, err = dnsmasqApi.DomainOverrideFind(fooDomain, "")
		if err != nil || foo.Uuid != fooUuid {
			t.Fatalf("DomainOverrideFind %s: want %s, got %s (%v)", fooDomain, fooUuid, foo.Uuid, err)
		}
		foo, err = dnsmasqApi.DomainOverrideFind("FOO."+domain+".", "")
		if err != nil || foo.Uuid != fooUuid {
			t.Errorf("DomainOverrideFind is not case / trailing dot insensitive: got %s (%v)", foo.Uuid, err)
		}
		_, err = dnsmasqApi.DomainOverrideFind(domain, "")
		requireNotFound(t, err, "DomainOverrideFind parent domain")
		_, err = dnsmasqApi.DomainOverrideFind(fooDomain, "10.2.2.3")
		requireNotFound(t, err, "DomainOverrideFind with another ip")
		// ip is compared semantically
		var foobar, foobarErr = dnsmasqApi.DomainOverrideFind(foobarDomain, "FD00:0::53")
		if foobarErr != nil || foobar.Uuid != foobarUuid {
			t.Errorf("DomainOverrideFind with an equivalent IPv6: got %s (%v)", foobar.Uuid, foobarErr)
		}
	})

	t.Run("partial update keeps untouched fields", func(t *testing.T) {
		var description = "changed"
		if err := dnsmasqApi.DomainOverrideUpdate(fooUuid, dnsmasq.DomainOverrideFields{Description: &description}); err != nil {
			t.Fatalf("DomainOverrideUpdate: %v", err)
		}
		var foo, err = dnsmasqApi.DomainOverrideGet(fooUuid)
		if err != nil {
			t.Fatalf("DomainOverrideGet: %v", err)
		}
		if foo.Description != "changed" || foo.Ip != "10.2.2.2" || foo.Port != "5353" || foo.Sequence != fooSequence || foo.Domain != fooDomain {
			t.Errorf("set_domain is not a merge: %+v", foo)
		}

		var empty = ""
		if err := dnsmasqApi.DomainOverrideUpdate(fooUuid, dnsmasq.DomainOverrideFields{Port: &empty}); err != nil {
			t.Fatalf("DomainOverrideUpdate clear port: %v", err)
		}
		foo, _ = dnsmasqApi.DomainOverrideGet(fooUuid)
		if foo.Port != "" || foo.Description != "changed" || foo.Ip != "10.2.2.2" {
			t.Errorf("clearing the port went wrong: %+v", foo)
		}
	})

	t.Run("create or update matches domain and ip", func(t *testing.T) {
		var uuid, created, err = dnsmasqApi.DomainOverrideCreateOrUpdate(dnsmasq.DomainOverride{Domain: fooDomain, Ip: "10.2.2.2", Port: "5300", Description: "updated"})
		if uuid != fooUuid {
			cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)
		}
		if err != nil || created || uuid != fooUuid {
			t.Fatalf("want update of %s, got %s created=%v err=%v", fooUuid, uuid, created, err)
		}
		var foo, _ = dnsmasqApi.DomainOverrideGet(fooUuid)
		if foo.Port != "5300" || foo.Description != "updated" || foo.Sequence != fooSequence {
			t.Errorf("create-or-update did not update: %+v", foo)
		}

		// another upstream server for the same domain is a new entry
		var second string
		second, created, err = dnsmasqApi.DomainOverrideCreateOrUpdate(dnsmasq.DomainOverride{Domain: fooDomain, Ip: "10.2.2.3"})
		cleanupRemove(t, "dnsmasq domain override", second, dnsmasqApi.DomainOverrideRemove)
		if err != nil || !created || second == fooUuid {
			t.Fatalf("want a new entry, got %s created=%v err=%v", second, created, err)
		}
		_, err = dnsmasqApi.DomainOverrideFind(fooDomain, "")
		requireTooManyFound(t, err, "DomainOverrideFind of a domain with two servers")
		var all, _ = dnsmasqApi.DomainOverrideFindAll(fooDomain, "")
		if len(all) != 2 {
			t.Errorf("DomainOverrideFindAll: want 2, got %+v", all)
		}
		if err := dnsmasqApi.DomainOverrideRemove(second); err != nil {
			t.Errorf("DomainOverrideRemove: %v", err)
		}
	})

	t.Run("validation errors name the fields", func(t *testing.T) {
		var uuid, err = dnsmasqApi.DomainOverrideCreate(dnsmasq.DomainOverride{Domain: "invalid." + domain, Ip: "10.2.2.2", Port: "99999"})
		cleanupRemove(t, "dnsmasq domain override", uuid, dnsmasqApi.DomainOverrideRemove)
		asValidationError(t, err, "domainoverride.port")

		var badIp = "10.2.2.999"
		asValidationError(t, dnsmasqApi.DomainOverrideUpdate(fooUuid, dnsmasq.DomainOverrideFields{Ip: &badIp}), "domainoverride.ip")
	})

	t.Run("remove", func(t *testing.T) {
		if err := dnsmasqApi.DomainOverrideRemove(foobarUuid); err != nil {
			t.Fatalf("DomainOverrideRemove: %v", err)
		}
		requireNotFound(t, dnsmasqApi.DomainOverrideRemove(foobarUuid), "second DomainOverrideRemove")
		var _, err = dnsmasqApi.DomainOverrideGet(foobarUuid)
		requireNotFound(t, err, "DomainOverrideGet after remove")
		var description = "x"
		requireNotFound(t, dnsmasqApi.DomainOverrideUpdate(foobarUuid, dnsmasq.DomainOverrideFields{Description: &description}), "DomainOverrideUpdate after remove")
	})

	// set_domain is an upsert on unknown uuids, see TestDnsmasqHostLifecycle
	t.Run("update of a removed uuid does not resurrect it", func(t *testing.T) {
		var ghostDomain, ghostIp = "ghost." + domain, "10.2.9.9"
		var err = dnsmasqApi.DomainOverrideUpdate(foobarUuid, dnsmasq.DomainOverrideFields{Domain: &ghostDomain, Ip: &ghostIp})
		requireNotFound(t, err, "DomainOverrideUpdate with domain and ip after remove")
		if ghost, getErr := dnsmasqApi.DomainOverrideGet(foobarUuid); getErr == nil {
			t.Errorf("DomainOverrideUpdate of a removed uuid created a new entry: %+v", ghost)
		}
	})
}

func TestDnsmasqService(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)

	var status, err = dnsmasqApi.ServiceStatus()
	if err != nil {
		t.Fatalf("ServiceStatus: %v", err)
	}
	if status != "running" {
		t.Errorf("want status running, got %q", status)
	}

	if err := dnsmasqApi.ServiceReconfigure(); err != nil {
		t.Errorf("ServiceReconfigure: %v", err)
	}
	if status, err = dnsmasqApi.ServiceStatus(); err != nil || status != "running" {
		t.Errorf("after reconfigure: status %q, err %v", status, err)
	}
}

func TestDnsmasqLeases(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	var leases, err = dnsmasqApi.LeaseList("")
	if err != nil {
		t.Fatalf("LeaseList: %v", err)
	}
	t.Logf("%d leases", len(leases))
	if _, err := dnsmasqApi.LeaseList(runDomain); err != nil {
		t.Errorf("LeaseList with search phrase: %v", err)
	}
}

// TestDnsmasqHostResolves checks that a host override is served by dnsmasq after a reconfigure
func TestDnsmasqHostResolves(t *testing.T) {
	var dnsmasqApi = dnsmasqApi(t)
	requireDnsReachable(t, dnsmasqDnsPort)

	var domain = testDomain("dr")
	createDnsmasqHost(t, dnsmasqApi, dnsmasq.Host{Host: "resolve", Domain: domain, Ip: "10.3.3.3"})
	if err := dnsmasqApi.ServiceReconfigure(); err != nil {
		t.Fatalf("ServiceReconfigure: %v", err)
	}
	requireResolves(t, dnsmasqDnsPort, "resolve."+domain, "10.3.3.3")
}
