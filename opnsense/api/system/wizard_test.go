package system

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// wizardTestAnswer is shaped like core/initial_setup/get of OPNsense 26.7 (option lists shortened)
const wizardTestAnswer = `{"wizard":{
	"hostname":"OPNsense","domain":"internal",
	"language":{"de_DE":{"value":"German","selected":0},"en_US":{"value":"English","selected":1}},
	"dns_servers":{"9.9.9.9":{"value":"9.9.9.9","selected":1},"1.1.1.1":{"value":"1.1.1.1","selected":1},"":{"value":"","selected":0}},
	"dnsallowoverride":"1",
	"unbound":{"enabled":"1","dnssec":"0","dnssecstripped":"0"},
	"timezone":{"Africa\/Abidjan":{"value":"Africa\/Abidjan","selected":0},"Etc\/UTC":{"value":"Etc\/UTC","selected":1}},
	"interfaces":{
		"wan":{"disable":"0","ipv4_type":{"dhcp":{"value":"DHCP","selected":0},"static":{"value":"Static","selected":1},"pppoe":{"value":"PPPoE","selected":0}},
			"spoofmac":"","mtu":"1500","mss":"","ipaddr":"203.0.113.2/24","gateway":"203.0.113.1","dhcphostname":"",
			"pppoe_username":"isp-user","pppoe_password":"pppoe-secret","pppoe_provider":"","blockpriv":"1","blockbogons":"1"},
		"lan":{"ipaddr":"192.168.1.1/24","disable":"0","configure_dhcp":"1"}},
	"deployment_type":{"multiwan":"1","dhcp_dns_registration":"1","maxthreads":"0"},
	"password":"root-secret","password_confirm":"root-secret"}}`

func TestWizardGet(t *testing.T) {
	var api, requests = defaultsTestApi(t, 200, wizardTestAnswer)

	var wizard, err = api.WizardGet()
	if err != nil {
		t.Fatal(err)
	}
	if got := *requests; len(got) != 1 || got[0].Method != "GET" || got[0].Path != "/api/core/initial_setup/get" {
		t.Errorf("requests = %v, want GET /api/core/initial_setup/get", got)
	}

	var want = Wizard{
		Hostname:         "OPNsense",
		Domain:           "internal",
		Language:         "en_US",
		DnsServers:       "9.9.9.9,1.1.1.1", // order as sent, empty option skipped
		DnsAllowOverride: "1",
		Timezone:         "Etc/UTC",
		Unbound:          WizardUnbound{Enabled: "1", Dnssec: "0", DnssecStripped: "0"},
		Wan: WizardWan{Disable: "0", Ipv4Type: "static", Mtu: "1500", Ipaddr: "203.0.113.2/24", Gateway: "203.0.113.1",
			PppoeUsername: "isp-user", BlockPriv: "1", BlockBogons: "1"},
		Lan:            WizardLan{Ipaddr: "192.168.1.1/24", Disable: "0", ConfigureDhcp: "1"},
		DeploymentType: WizardDeploymentType{Multiwan: "1", DhcpDnsRegistration: "1", Maxthreads: "0"},
	}
	if !reflect.DeepEqual(wizard, want) {
		t.Errorf("wizard =\n%+v\nwant\n%+v", wizard, want)
	}
	// passwords must never end up in the result
	for _, secret := range []string{"root-secret", "pppoe-secret"} {
		if strings.Contains(fmt.Sprintf("%+v", wizard), secret) {
			t.Errorf("wizard contains password %q: %+v", secret, wizard)
		}
	}
}

func TestWizardGetEmptyDnsServers(t *testing.T) {
	var api, _ = defaultsTestApi(t, 200, `{"wizard":{"hostname":"fw","dns_servers":{"":{"value":"","selected":1}},"timezone":"Etc/UTC"}}`)

	var wizard, err = api.WizardGet()
	if err != nil {
		t.Fatal(err)
	}
	if wizard.DnsServers != "" {
		t.Errorf("DnsServers = %q, want empty", wizard.DnsServers)
	}
	if wizard.Timezone != "Etc/UTC" {
		t.Errorf("Timezone = %q, want Etc/UTC (plain string values are kept)", wizard.Timezone)
	}
}

func TestWizardGetErrors(t *testing.T) {
	var cases = []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"no wizard", 200, `{"foo":{}}`, "no wizard"},
		{"empty body", 200, ``, "empty response"},
		{"broken option", 200, `{"wizard":{"language":[1]}}`, "unexpected option value"},
		{"not found", 404, `{"errorMessage":"Endpoint not found"}`, "HTTP 404: Endpoint not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var api, _ = defaultsTestApi(t, c.status, c.body)
			var _, err = api.WizardGet()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}
