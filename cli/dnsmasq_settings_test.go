package cli

import (
	"encoding/json"
	"reflect"
	"testing"
)

const dnsmasqSettingsGetAnswer = `{"dnsmasq":{"enable":"1","regdhcp":"0","regdhcpstatic":"0","dhcpfirst":"0","strict_order":"0",
	"domain_needed":"1","no_private_reverse":"0","no_resolv":"0","log_queries":"0","no_hosts":"0","strictbind":"0","dnssec":"0",
	"regdhcpdomain":"","interface":{"lan":{"value":"LAN","selected":1},"opt1":{"value":"DMZ","selected":0}},"port":"53053",
	"dns_port":"53053","dns_forward_max":"","cache_size":"500","local_ttl":"",
	"add_mac":{"":{"value":"None","selected":1},"standard":{"value":"standard","selected":0},"text":{"value":"text","selected":0}},
	"add_subnet":"0","strip_subnet":"0",
	"dhcp":{"no_interface":{"lan":{"value":"LAN","selected":0},"opt1":{"value":"DMZ","selected":1}},"fqdn":"1","domain":"lan.example",
		"local":"1","lease_max":"","authoritative":"1","default_fw_rules":"1","reply_delay":"","enable_ra":"0","host_ping":"1",
		"nosync":"0","log_dhcp":"0","log_quiet":"0","%domain":"internal"},
	"no_ident":"1","hosts":[],"domainoverrides":[],"dhcp_tags":[],"dhcp_ranges":{"r1":{"start_addr":"192.168.1.100"}},"dhcp_options":[],"dhcp_boot":[]}}`

func dnsmasqSettingsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", "/api/dnsmasq/settings/get", 200, dnsmasqSettingsGetAnswer)
	f.on("POST", "/api/dnsmasq/settings/set", 200, answerSaved)
	return f
}

func TestDnsmasqSettingsPrint(t *testing.T) {
	t.Parallel()
	var f = dnsmasqSettingsFake(t)
	var r = f.run("/dnsmasq/settings", "print")
	wantExit(t, r, 0)
	var lines = dnsLines(r.stdout)
	for _, want := range []string{"enabled:|yes", "interface:|lan", "port:|53053", "domain-needed:|yes", "cache-size:|500",
		"add-mac:", "dhcp-no-interface:|opt1", "dhcp-domain:|lan.example", "dhcp-authoritative:|yes", "no-ident:|yes"} {
		var found = false
		for _, line := range lines {
			found = found || line == want
		}
		if !found {
			t.Errorf("print lacks %q:\n%s", want, r.stdout)
		}
	}

	var asJSON = f.run("/dnsmasq/settings", "print", "json")
	wantExit(t, asJSON, 0)
	var values map[string]string
	if err := json.Unmarshal([]byte(asJSON.stdout), &values); err != nil || values["dhcp.domain"] != "lan.example" || values["interface"] != "lan" {
		t.Errorf("json: %v %q", err, asJSON.stdout)
	}

	var options = f.run("/dnsmasq/settings", "print", "options=interface")
	wantExit(t, options, 0)
	if got := dnsLines(options.stdout); !reflect.DeepEqual(got, []string{"KEY|NAME|SELECTED", "lan|LAN|yes", "opt1|DMZ|no"}) {
		t.Errorf("options: %q", got)
	}
	wantNoMutations(t, f)
}

func TestDnsmasqSettingsSet(t *testing.T) {
	t.Parallel()
	var f = dnsmasqSettingsFake(t)
	wantExit(t, f.run("/dnsmasq/settings", "set", "dhcp-domain=lab.example", "log-queries", "interface=LAN,opt1", "add-mac=TEXT", "cache-size="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/dnsmasq/settings/set"), map[string]any{"dnsmasq": map[string]any{
		"log_queries": "1", "interface": "lan,opt1", "add_mac": "text", "cache_size": "",
		"dhcp": map[string]any{"domain": "lab.example"},
	}})
}

func TestDnsmasqSettingsSetValidation(t *testing.T) {
	t.Parallel()
	var f = dnsmasqSettingsFake(t)
	wantFailure(t, f.run("/dnsmasq/settings", "set"), "nothing to change")
	wantFailure(t, f.run("/dnsmasq/settings", "set", "interface=lan,opt9"), "unknown value", "opt9")
	wantFailure(t, f.run("/dnsmasq/settings", "set", "dhcp-reply-delay=61"), "from 0 to 60")
	wantFailure(t, f.run("/dnsmasq/settings", "set", "port=70000"), "from 0 to 65535")
	wantNoMutations(t, f)

	var g = newFakeOPN(t)
	g.on("POST", "/api/dnsmasq/settings/set", 200, answerValidation("dnsmasq.port", "Unbound DNS is currently using this port."))
	wantFailure(t, g.run("/dnsmasq/settings", "set", "port=53"), "currently using this port")
}
