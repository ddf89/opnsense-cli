//go:build integration

package integrationdns

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"
)

// TestUnboundRecordsLibrary creates disabled ACLs, forwards, blocklists and a host alias of a disabled host
// override in the run's domain / documentation networks, changes and removes them. Nothing is applied
func TestUnboundRecordsLibrary(t *testing.T) {
	var ub = unboundApi(t)

	t.Run("acl", func(t *testing.T) {
		var uuid, err = ub.AclCreate(unbound.Acl{Enabled: "0", Name: prefix() + "-acl", Action: "refuse", Networks: "192.0.2.0/24,2001:db8::/32"})
		cleanupRemove(t, "acl", uuid, ub.AclRemove)
		if err != nil {
			t.Fatalf("AclCreate: %v", err)
		}
		if err := ub.AclUpdate(uuid, unbound.Patch{"description": prefix()}); err != nil {
			t.Fatalf("AclUpdate: %v", err)
		}
		var acl, getErr = ub.AclGet(uuid)
		if getErr != nil || acl.Enabled != "0" || acl.Action != "refuse" || acl.Networks != "192.0.2.0/24,2001:db8::/32" || acl.Description != prefix() {
			t.Errorf("AclGet: %+v, %v", acl, getErr)
		}
		var validationErr *api.ValidationError
		if _, err := ub.AclCreate(unbound.Acl{Enabled: "0", Name: prefix() + "-bad", Networks: "192.0.2.1"}); !errors.As(err, &validationErr) {
			t.Errorf("a network without mask: want a validation error, got %v", err)
		}
		if action, err := ub.AclDefaultAction(); err != nil || action == "" {
			t.Errorf("AclDefaultAction: %q, %v", action, err)
		}
		if err := ub.AclRemove(uuid); err != nil {
			t.Errorf("AclRemove: %v", err)
		}
	})

	t.Run("forward and dot", func(t *testing.T) {
		var forwardUuid, err = ub.ForwardCreate(unbound.Forward{Type: "forward", Enabled: "0", Domain: "fwd." + domain(), Server: "192.0.2.53", Description: prefix() + "-fwd"})
		cleanupRemove(t, "forward", forwardUuid, ub.ForwardRemove)
		if err != nil {
			t.Fatalf("ForwardCreate: %v", err)
		}
		dotUuid, err := ub.ForwardCreate(unbound.Forward{Type: "dot", Enabled: "0", Domain: "dot." + domain(), Server: "192.0.2.54", Verify: "dot." + domain(), Description: prefix() + "-dot"})
		cleanupRemove(t, "dot", dotUuid, ub.ForwardRemove)
		if err != nil {
			t.Fatalf("ForwardCreate dot: %v", err)
		}
		if forward, err := ub.ForwardGet(dotUuid); err != nil || forward.Type != "dot" || forward.Verify != "dot."+domain() {
			t.Errorf("ForwardGet dot: %+v, %v", forward, err)
		}
		if err := ub.ForwardUpdate(forwardUuid, "dot", unbound.Patch{"port": "853"}); err != nil {
			t.Fatalf("ForwardUpdate to dot: %v", err)
		}
		if forward, err := ub.ForwardGet(forwardUuid); err != nil || forward.Type != "dot" || forward.Port != "853" || forward.Server != "192.0.2.53" {
			t.Errorf("after converting to dot: %+v, %v", forward, err)
		}
		if err := ub.ForwardUpdate("0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", "forward", unbound.Patch{"port": "53"}); !api.IsNotFound(err) {
			t.Errorf("unknown uuid: want not found, got %v", err)
		}
		if _, err := ub.UseSystemNameservers(); err != nil {
			t.Errorf("UseSystemNameservers: %v", err)
		}
		if _, err := ub.SystemNameservers(); err != nil {
			t.Errorf("SystemNameservers: %v", err)
		}
	})

	t.Run("blocklist", func(t *testing.T) {
		var uuid, err = ub.BlocklistCreate(unbound.Blocklist{Enabled: "0", Description: prefix() + "-bl", Type: "ag",
			SourceNets: "192.0.2.0/24", Wildcards: "w." + domain(), Allowlists: "ok." + domain()})
		cleanupRemove(t, "blocklist", uuid, ub.BlocklistRemove)
		if err != nil {
			t.Fatalf("BlocklistCreate: %v", err)
		}
		var blocklist, getErr = ub.BlocklistGet(uuid)
		if getErr != nil || blocklist.Type != "ag" || blocklist.CacheTtl != "72000" || blocklist.SourceNets != "192.0.2.0/24" {
			t.Errorf("BlocklistGet: %+v, %v", blocklist, getErr)
		}
		var validationErr *api.ValidationError
		if err := ub.BlocklistUpdate(uuid, unbound.Patch{"source_nets": "192.0.2.0/24,198.51.100.0/25"}); !errors.As(err, &validationErr) {
			t.Errorf("unequally sized source nets: want a validation error, got %v", err)
		}
		types, err := ub.BlocklistTypes()
		if err != nil || len(types) < 10 {
			t.Errorf("BlocklistTypes: %d, %v", len(types), err)
		}
	})

	t.Run("host alias", func(t *testing.T) {
		var hostUuid, err = ub.HostOverrideCreate(unbound.HostOverride{Enabled: "0", Host: "web", Domain: domain(), Rr: "A", Ip: "192.0.2.80"})
		cleanupRemove(t, "host override", hostUuid, ub.HostEntryRemove)
		if err != nil {
			t.Fatalf("HostOverrideCreate: %v", err)
		}
		aliasUuid, err := ub.HostAliasCreate(unbound.HostAlias{Enabled: "0", Host: hostUuid, Hostname: "www", Domain: domain()})
		cleanupRemove(t, "host alias", aliasUuid, ub.HostAliasRemove)
		if err != nil {
			t.Fatalf("HostAliasCreate: %v", err)
		}
		if alias, err := ub.HostAliasGet(aliasUuid); err != nil || alias.Host != hostUuid || alias.FQDN() != "www."+domain() {
			t.Errorf("HostAliasGet: %+v, %v", alias, err)
		}
		// removing the host override removes its aliases
		if err := ub.HostEntryRemove(hostUuid); err != nil {
			t.Fatalf("HostEntryRemove: %v", err)
		}
		if _, err := ub.HostAliasGet(aliasUuid); !api.IsNotFound(err) {
			t.Errorf("the alias survived its host override: %v", err)
		}
	})
}

// TestUnboundSettingsRoundTrip changes advanced.hideversion (not applied) and restores it
func TestUnboundSettingsRoundTrip(t *testing.T) {
	var ub = unboundApi(t)
	var before, err = ub.SettingsGet()
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	for _, name := range []string{"general.enabled", "general.port", "advanced.logverbosity", "acls.default_action", "forwarding.enabled"} {
		if _, found := before.Values[name]; !found {
			t.Errorf("setting %s missing", name)
		}
	}
	var original = before.Values["advanced.hideversion"]
	var changed = "1"
	if original == "1" {
		changed = "0"
	}
	t.Cleanup(func() {
		if err := ub.SettingsSet(unbound.Patch{"advanced.hideversion": original}); err != nil {
			t.Errorf("restoring hideversion %q failed: %v", original, err)
		}
	})
	if err := ub.SettingsSet(unbound.Patch{"advanced.hideversion": changed}); err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}
	var after, _ = ub.SettingsGet()
	if after.Values["advanced.hideversion"] != changed || after.Values["general.port"] != before.Values["general.port"] ||
		after.Values["general.active_interface"] != before.Values["general.active_interface"] {
		t.Errorf("after set: %v", after.Values)
	}
}

func TestUnboundStatisticsAndDiagnostics(t *testing.T) {
	var ub = unboundApi(t)
	enabled, err := ub.StatisticsEnabled()
	if err != nil {
		t.Fatalf("StatisticsEnabled: %v", err)
	}
	totals, err := ub.StatisticsTotals(5)
	if err != nil {
		t.Fatalf("StatisticsTotals: %v", err)
	}
	if !enabled && totals.Available {
		t.Logf("statistics disabled but totals available (old database): %+v", totals)
	}
	if _, _, err := ub.StatisticsQueries(""); err != nil {
		t.Errorf("StatisticsQueries: %v", err)
	}
	if _, err := ub.StatisticsHistory(1); err != nil {
		t.Errorf("StatisticsHistory: %v", err)
	}
	counters, err := ub.Counters()
	if err != nil || counters["total.num.queries"] == "" {
		t.Errorf("Counters: %d counters, %v", len(counters), err)
	}
	if zones, err := ub.LocalZones(); err != nil || len(zones) == 0 {
		t.Errorf("LocalZones: %d, %v", len(zones), err)
	}
	if _, err := ub.LocalData(); err != nil {
		t.Errorf("LocalData: %v", err)
	}
	if _, err := ub.CacheDump(); err != nil {
		t.Errorf("CacheDump: %v", err)
	}
	if _, err := ub.InfraDump(); err != nil {
		t.Errorf("InfraDump: %v", err)
	}
	if _, err := ub.InsecureZones(); err != nil {
		t.Errorf("InsecureZones: %v", err)
	}
	// without loaded blocklists the test endpoint answers {"status":"error"}, with them Pass for a documentation name
	if result, err := ub.BlocklistTest("www."+domain(), "192.0.2.1"); err == nil && result.Action != "Pass" {
		t.Errorf("BlocklistTest: %+v", result)
	}
}

func TestCliUnbound(t *testing.T) {
	coreApi(t)
	t.Run("acl", func(t *testing.T) {
		var name = prefix() + "-cli-acl"
		opn(t, "/unbound/acl", "add", "name="+name, "networks=192.0.2.0/24", "action=deny", "disabled")
		opnFails(t, "exists already", "/unbound/acl", "add", "name="+name, "networks=192.0.2.0/24")
		opn(t, "/unbound/acl", "set", name, "networks=192.0.2.0/25,192.0.2.128/25")
		if out := opn(t, "/unbound/acl", "show", name); !strings.Contains(out, "192.0.2.0/25,192.0.2.128/25") || !strings.Contains(out, "disabled:     yes") {
			t.Errorf("show acl:\n%s", out)
		}
		opn(t, "/unbound/acl", "default-action")
		opn(t, "/unbound/acl", "remove", name)
	})

	t.Run("forward", func(t *testing.T) {
		var description = prefix() + "-cli-fwd"
		opn(t, "/unbound/forward", "add", "domain=cli."+domain(), "server=192.0.2.55", "description="+description, "disabled")
		opn(t, "/unbound/forward", "set", description, "type=dot", "verify=cli."+domain())
		if out := opn(t, "/unbound/forward", "print", "search="+description); !strings.Contains(out, "dot") || !strings.Contains(out, "192.0.2.55") {
			t.Errorf("print forward:\n%s", out)
		}
		opn(t, "/unbound/forward", "system-nameservers")
		opn(t, "/unbound/forward", "remove", description)
	})

	t.Run("blocklist", func(t *testing.T) {
		var description = prefix() + "-cli-bl"
		opn(t, "/unbound/blocklist", "add", "description="+description, "type=AG,el", "source-nets=192.0.2.0/24", "disabled")
		opnFails(t, "unknown list", "/unbound/blocklist", "set", description, "type=no-such-list")
		if out := opn(t, "/unbound/blocklist", "print", "search="+description); !strings.Contains(out, "AdGuard List, EasyList") {
			t.Errorf("print blocklist:\n%s", out)
		}
		if out := opn(t, "/unbound/blocklist", "types", "search=hagezi"); !strings.Contains(out, "hgz002") {
			t.Errorf("types:\n%s", out)
		}
		opn(t, "/unbound/blocklist", "remove", description)
	})

	t.Run("host alias", func(t *testing.T) {
		opn(t, "/unbound/host-override", "add", "host=cli", "domain="+domain(), "ip=192.0.2.81", "disabled")
		opn(t, "/unbound/host-alias", "add", "host=cli."+domain(), "hostname=alias", "domain="+domain(), "disabled")
		if out := opn(t, "/unbound/host-alias", "print", "search="+domain()); !strings.Contains(out, "cli."+domain()) {
			t.Errorf("print host-alias:\n%s", out)
		}
		opn(t, "/unbound/host-alias", "remove", "alias."+domain())
		opn(t, "/unbound/host-override", "remove", "cli."+domain())
	})

	t.Run("read only views", func(t *testing.T) {
		opn(t, "/unbound/settings", "print")
		opn(t, "/unbound/advanced", "print", "options=log-verbosity")
		opn(t, "/unbound/statistics", "print")
		opn(t, "/unbound/statistics", "queries", "limit=5")
		opn(t, "/unbound/statistics", "counters", "search=total.num")
		opn(t, "/unbound/diagnostics", "local-zones")
		opn(t, "/unbound/diagnostics", "cache", "search="+domain())
		opnFails(t, "confirm", "/unbound/statistics", "reset")
		opnFails(t, "confirm", "/unbound/service", "stop")
	})
}
