//go:build integration

package integrationdns

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
)

// TestDnsmasqDhcpLibrary creates a tag, a range in 192.0.2.0/24 (no interface), an option and a boot entry for
// that tag, changes and removes them. Nothing is reconfigured
func TestDnsmasqDhcpLibrary(t *testing.T) {
	var dm = dnsmasqApi(t)
	var tagUuid, err = dm.TagCreate(dnsmasq.Tag{Tag: tagName() + "-lib"})
	cleanupRemove(t, "tag", tagUuid, dm.TagRemove)
	if err != nil {
		t.Fatalf("TagCreate: %v", err)
	}
	if _, err := dm.TagCreate(dnsmasq.Tag{Tag: tagName() + "-lib"}); err == nil {
		t.Error("a duplicate tag name must be refused")
	}
	if tag, err := dm.TagGetByName(strings.ToUpper(tagName() + "-lib")); err != nil || tag.Uuid != tagUuid {
		t.Errorf("TagGetByName: %+v, %v", tag, err)
	}

	rangeUuid, err := dm.RangeCreate(dnsmasq.Range{StartAddr: "192.0.2.10", EndAddr: "192.0.2.20", SetTag: tagUuid, Description: prefix() + " lib range"})
	cleanupRemove(t, "range", rangeUuid, dm.RangeRemove)
	if err != nil {
		t.Fatalf("RangeCreate: %v", err)
	}
	optionUuid, err := dm.OptionCreate(dnsmasq.Option{Option: "6", Value: "192.0.2.53", Tag: tagUuid, Description: prefix() + " lib option"})
	cleanupRemove(t, "option", optionUuid, dm.OptionRemove)
	if err != nil {
		t.Fatalf("OptionCreate: %v", err)
	}
	bootUuid, err := dm.BootCreate(dnsmasq.Boot{Filename: "a9.0", Address: "192.0.2.69", Tag: tagUuid, Description: prefix() + " lib boot"})
	cleanupRemove(t, "boot", bootUuid, dm.BootRemove)
	if err != nil {
		t.Fatalf("BootCreate: %v", err)
	}

	t.Run("read back", func(t *testing.T) {
		var dhcpRange, err = dm.RangeGet(rangeUuid)
		if err != nil || dhcpRange.StartAddr != "192.0.2.10" || dhcpRange.SetTag != tagUuid || dhcpRange.DomainType != "range" {
			t.Errorf("RangeGet: %+v, %v", dhcpRange, err)
		}
		option, err := dm.OptionGet(optionUuid)
		if err != nil || option.Type != "set" || option.Option != "6" || option.Tag != tagUuid {
			t.Errorf("OptionGet: %+v, %v", option, err)
		}
		boot, err := dm.BootGet(bootUuid)
		if err != nil || boot.Filename != "a9.0" {
			t.Errorf("BootGet: %+v, %v", boot, err)
		}
	})

	t.Run("update and validation", func(t *testing.T) {
		if err := dm.RangeUpdate(rangeUuid, dnsmasq.Patch{"lease_time": "600"}); err != nil {
			t.Fatalf("RangeUpdate: %v", err)
		}
		if dhcpRange, _ := dm.RangeGet(rangeUuid); dhcpRange.LeaseTime != "600" || dhcpRange.EndAddr != "192.0.2.20" {
			t.Errorf("partial update: %+v", dhcpRange)
		}
		var validationErr *api.ValidationError
		if err := dm.RangeUpdate(rangeUuid, dnsmasq.Patch{"mode": "static"}); !errors.As(err, &validationErr) {
			t.Errorf("static with an end address: want a validation error, got %v", err)
		}
		if err := dm.RangeUpdate("0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", dnsmasq.Patch{"lease_time": "1"}); !api.IsNotFound(err) {
			t.Errorf("unknown uuid: want not found, got %v", err)
		}
		// switching to match clears the set-only fields
		if err := dm.OptionUpdate(optionUuid, dnsmasq.Patch{"type": "match", "option": "77", "value": "a9", "set_tag": tagUuid}); err != nil {
			t.Fatalf("OptionUpdate: %v", err)
		}
		if option, _ := dm.OptionGet(optionUuid); option.Type != "match" || option.Tag != "" || option.SetTag != tagUuid {
			t.Errorf("after switching to match: %+v", option)
		}
	})

	t.Run("a tag in use can not be removed", func(t *testing.T) {
		var err = dm.TagRemove(tagUuid)
		if err == nil || !strings.Contains(err.Error(), "in use by") {
			t.Errorf("want an in use error, got %v", err)
		}
	})

	t.Run("option codes and interfaces", func(t *testing.T) {
		var codes, err = dm.OptionCodes(false)
		if err != nil || len(codes) < 50 {
			t.Fatalf("OptionCodes: %d, %v", len(codes), err)
		}
		var found bool
		for _, code := range codes {
			found = found || (code.Key == "6" && strings.HasPrefix(code.Value, "dns-server"))
		}
		if !found {
			t.Error("option 6 dns-server missing")
		}
		interfaces, err := dm.DhcpInterfaces()
		if err != nil || len(interfaces) == 0 {
			t.Errorf("DhcpInterfaces: %v, %v", interfaces, err)
		}
	})

	for _, remove := range []struct {
		what string
		fn   func(string) error
		uuid string
	}{{"boot", dm.BootRemove, bootUuid}, {"option", dm.OptionRemove, optionUuid}, {"range", dm.RangeRemove, rangeUuid}, {"tag", dm.TagRemove, tagUuid}} {
		if err := remove.fn(remove.uuid); err != nil {
			t.Errorf("remove %s: %v", remove.what, err)
		}
		if err := remove.fn(remove.uuid); !api.IsNotFound(err) {
			t.Errorf("remove %s twice: want not found, got %v", remove.what, err)
		}
	}
}

// TestDnsmasqSettingsRoundTrip changes cache_size (not applied) and restores it
func TestDnsmasqSettingsRoundTrip(t *testing.T) {
	var dm = dnsmasqApi(t)
	var before, err = dm.SettingsGet()
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	for _, name := range []string{"enable", "port", "interface", "dhcp.domain", "dhcp.fqdn"} {
		if _, found := before.Values[name]; !found {
			t.Errorf("setting %s missing: %v", name, before.Values)
		}
	}
	var original = before.Values["cache_size"]
	t.Cleanup(func() {
		if err := dm.SettingsSet(dnsmasq.Patch{"cache_size": original}); err != nil {
			t.Errorf("restoring cache_size %q failed: %v", original, err)
		}
	})
	if err := dm.SettingsSet(dnsmasq.Patch{"cache_size": "1234"}); err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}
	if after, _ := dm.SettingsGet(); after.Values["cache_size"] != "1234" || after.Values["port"] != before.Values["port"] {
		t.Errorf("after set: %v", after.Values)
	}
	var validationErr *api.ValidationError
	if err := dm.SettingsSet(dnsmasq.Patch{"dhcp.reply_delay": "61"}); !errors.As(err, &validationErr) {
		t.Errorf("reply delay 61: want a validation error, got %v", err)
	}
	// the CLI shows the same value
	if out := opn(t, "/dnsmasq/settings", "print"); !strings.Contains(out, "1234") {
		t.Errorf("print does not show the cache size:\n%s", out)
	}
}

func TestCliDnsmasqDhcp(t *testing.T) {
	coreApi(t)
	var tag = tagName() + "-cli"
	opn(t, "/dnsmasq/tag", "add", "name="+tag)
	opnFails(t, "exists already", "/dnsmasq/tag", "add", "name="+tag)

	var rangeDescription = prefix() + "-cli-range"
	opn(t, "/dnsmasq/range", "add", "start=192.0.2.30", "end=192.0.2.40", "set-tag="+tag, "description="+rangeDescription)
	opnFails(t, "exists already", "/dnsmasq/range", "add", "start=192.0.2.30", "end=192.0.2.31")
	opn(t, "/dnsmasq/range", "add", "start=192.0.2.30", "end=192.0.2.35", "description="+rangeDescription, "replace")
	opn(t, "/dnsmasq/range", "set", rangeDescription, "lease-time=900", "set-tag="+tag)
	if out := opn(t, "/dnsmasq/range", "show", "192.0.2.30-192.0.2.35"); !strings.Contains(out, "900") || !strings.Contains(out, tag) {
		t.Errorf("show range:\n%s", out)
	}

	var optionDescription = prefix() + "-cli-option"
	opn(t, "/dnsmasq/option", "add", "option=dns-server", "value=192.0.2.53", "tag="+tag, "description="+optionDescription)
	opnFails(t, "unknown option", "/dnsmasq/option", "add", "option=no-such-option-a9", "tag="+tag)
	if out := opn(t, "/dnsmasq/option", "print", "search="+optionDescription); !strings.Contains(out, "dns-server [6]") {
		t.Errorf("print option:\n%s", out)
	}
	opn(t, "/dnsmasq/option", "set", optionDescription, "option6=dns-server", "value=[2001:db8::53]")
	if out := opn(t, "/dnsmasq/option", "show", optionDescription); !strings.Contains(out, "option6:      23") {
		t.Errorf("show option after switching to DHCPv6:\n%s", out)
	}

	var bootDescription = prefix() + "-cli-boot"
	opn(t, "/dnsmasq/boot", "add", "filename=a9.efi", "address=192.0.2.69", "tag="+tag, "description="+bootDescription)
	opnFails(t, "in use by", "/dnsmasq/tag", "remove", tag)

	opn(t, "/dnsmasq/boot", "remove", bootDescription)
	opn(t, "/dnsmasq/option", "remove", optionDescription)
	opn(t, "/dnsmasq/range", "remove", rangeDescription)
	opn(t, "/dnsmasq/tag", "remove", tag)
	if out := opn(t, "/dnsmasq/tag", "print"); strings.Contains(out, tag) {
		t.Errorf("tag still listed:\n%s", out)
	}
}
