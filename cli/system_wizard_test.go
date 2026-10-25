package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	systemWizardGetPath = "/api/core/initial_setup/get"

	// systemWizardAnswer is core/initial_setup/get (option lists trimmed), the password fields are normally sent empty
	systemWizardAnswer = `{"wizard":{"hostname":"OPNsense","domain":"internal",` +
		`"language":{"cs_CZ":{"value":"Czech","selected":0},"en_US":{"value":"English","selected":1},"de_DE":{"value":"German","selected":0}},` +
		`"dns_servers":{"9.9.9.9":{"value":"9.9.9.9","selected":1},"1.1.1.1":{"value":"1.1.1.1","selected":1}},"dnsallowoverride":"1",` +
		`"unbound":{"enabled":"1","dnssec":"0","dnssecstripped":"0"},` +
		`"timezone":{"Africa/Abidjan":{"value":"Africa/Abidjan","selected":0},"Etc/UTC":{"value":"Etc/UTC","selected":1}},` +
		`"interfaces":{"wan":{"disable":"0","ipv4_type":{"dhcp":{"value":"DHCP","selected":1},"static":{"value":"Static","selected":0},"pppoe":{"value":"PPPoE","selected":0}},` +
		`"spoofmac":"","mtu":"","mss":"","ipaddr":"","gateway":"","dhcphostname":"","pppoe_username":"","pppoe_password":"s3cr3t-pppoe","pppoe_provider":"","blockpriv":"1","blockbogons":"1"},` +
		`"lan":{"ipaddr":"192.168.1.1/24","disable":"0","configure_dhcp":"1"}},` +
		`"deployment_type":{"multiwan":"1","dhcp_dns_registration":"1","maxthreads":"0"},"password":"s3cr3t-root","password_confirm":"s3cr3t-root"}}`
)

func TestSystemWizardPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", systemWizardGetPath, 200, systemWizardAnswer)
	var r = f.run("/system/wizard", "print")
	wantExit(t, r, 0)

	var fields = map[string]string{}
	for _, row := range systemBackupTable(r.stdout) {
		fields[strings.TrimSuffix(row[0], ":")] = strings.Join(row[1:], " ")
	}
	for key, want := range map[string]string{
		"hostname": "OPNsense", "domain": "internal", "language": "en_US", "timezone": "Etc/UTC",
		"dns-servers": "9.9.9.9,1.1.1.1", "wan.ipv4-type": "dhcp", "lan.ipaddr": "192.168.1.1/24", "unbound.enabled": "yes",
		"unbound.dnssec": "no", "wan.block-bogons": "yes", "deployment-type.maxthreads": "0",
	} {
		if fields[key] != want {
			t.Errorf("%s: got %q, want %q", key, fields[key], want)
		}
	}
	// the (normally empty) password fields are never shown
	wantNotContains(t, "output", r.stdout+r.stderr, "s3cr3t", "password")
	wantNoMutations(t, f)

	t.Run("json without passwords", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemWizardGetPath, 200, systemWizardAnswer)
		var r = f.run("/system/wizard", "print", "json")
		wantExit(t, r, 0)
		wantNotContains(t, "output", r.stdout+r.stderr, "s3cr3t", "password")
		var object struct {
			Hostname   string `json:"hostname"`
			DnsServers string `json:"dns_servers"`
			Interfaces struct {
				Wan map[string]string `json:"wan"`
				Lan map[string]string `json:"lan"`
			} `json:"interfaces"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &object); err != nil || strings.Count(r.stdout, "\n") != 1 {
			t.Fatalf("not one JSON line: %v %q", err, r.stdout)
		}
		if object.Hostname != "OPNsense" || object.DnsServers != "9.9.9.9,1.1.1.1" || object.Interfaces.Wan["ipv4_type"] != "dhcp" ||
			object.Interfaces.Lan["configure_dhcp"] != "1" {
			t.Errorf("json %q", r.stdout)
		}
	})
	t.Run("answer without wizard is an error", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemWizardGetPath, 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/wizard", "print"), "wizard")
	})
	t.Run("there is no way to apply the wizard", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemWizardGetPath, 200, systemWizardAnswer)
		for _, command := range []string{"set", "configure", "apply"} {
			wantFailure(t, f.run("/system/wizard", command), "no such menu or command")
		}
		wantNoCalls(t, f)
	})
}
