//go:build integration

package integrationsystem

import (
	"net"
	"strings"
	"testing"
)

// Read-only: factory reset and the wizard configure endpoint are never called

func TestDefaultsGet(t *testing.T) {
	var sys = systemApi(t)
	var defaults, err = sys.DefaultsGet()
	if err != nil {
		t.Fatal(err)
	}
	if net.ParseIP(defaults.DefaultIp) == nil {
		t.Errorf("default ip %q is no IP address", defaults.DefaultIp)
	}
}

func TestWizardGet(t *testing.T) {
	var sys = systemApi(t)
	var wizard, err = sys.WizardGet()
	if err != nil {
		t.Fatal(err)
	}
	if wizard.Hostname == "" || wizard.Domain == "" {
		t.Errorf("no hostname / domain: %+v", wizard)
	}
	if wizard.Language == "" || strings.Contains(wizard.Language, ",") {
		t.Errorf("want exactly one selected language, got %q", wizard.Language)
	}
	if wizard.Timezone == "" || strings.Contains(wizard.Timezone, ",") {
		t.Errorf("want exactly one selected timezone, got %q", wizard.Timezone)
	}
	switch wizard.Wan.Ipv4Type {
	case "dhcp", "static", "pppoe":
	default:
		t.Errorf("unexpected wan ipv4 type %q", wizard.Wan.Ipv4Type)
	}
	if wizard.Lan.Ipaddr != "" {
		if _, _, err := net.ParseCIDR(wizard.Lan.Ipaddr); err != nil {
			t.Errorf("lan ipaddr %q is no CIDR", wizard.Lan.Ipaddr)
		}
	}
	for _, flag := range []string{wizard.Unbound.Enabled, wizard.DnsAllowOverride, wizard.DeploymentType.Multiwan} {
		if flag != "0" && flag != "1" {
			t.Errorf("boolean field is %q: %+v", flag, wizard)
		}
	}
}
