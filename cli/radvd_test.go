package cli

import (
	"reflect"
	"testing"
)

const (
	radvdEntryPath = "/api/radvd/settings/search_entry"
	radvdEntryUuid = "386c6914-6997-4f9c-899f-33336ede380b"
)

func radvdFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(radvdEntryPath, map[string]any{"uuid": radvdEntryUuid, "enabled": "0", "interface": "lan", "%interface": "LAN", "Base6Interface": "",
		"mode": "managed", "%mode": "Managed", "DeprecatePrefix": "", "RemoveAdvOnExit": "", "RemoveRoute": "", "routes": "2001:db8:1::/64",
		"RDNSS": "2001:db8::53", "DNSSL": "example.lan", "dns": "1", "MinRtrAdvInterval": "200", "MaxRtrAdvInterval": "600",
		"AdvDNSSLLifetime": "", "AdvDefaultLifetime": "", "AdvLinkMTU": "", "AdvPreferredLifetime": "", "AdvRASrcAddress": "",
		"AdvRDNSSLifetime": "", "AdvRouteLifetime": "", "AdvValidLifetime": "", "AdvDefaultPreference": "medium", "nat64prefix": "", "AdvCurHopLimit": "64"})
	return f
}

func TestRadvdEntry(t *testing.T) {
	t.Parallel()
	var f = radvdFake(t)
	f.on("POST", "/api/radvd/settings/add_entry", 200, answerAdded("e2"))
	f.on("POST", "/api/radvd/settings/set_entry/"+radvdEntryUuid, 200, answerSaved)
	var r = f.run("/radvd/entry", "print")
	wantExit(t, r, 0)
	if got := keaTestLines(r.stdout); !reflect.DeepEqual(got, []string{"#|DISABLED|INTERFACE|MODE|DNS-SERVERS|DNS-SEARCH|ROUTES",
		"0|yes|lan|managed|2001:db8::53|example.lan|2001:db8:1::/64"}) {
		t.Errorf("print %q", got)
	}
	var show = f.run("/radvd/entry", "show", "LAN")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "disabled:", "min-interval:", "200", "default-preference:", "medium")

	wantExit(t, f.run("/radvd/entry", "add", "interface=opt1", "disabled", "mode=Stateless", "dns-servers=2001:db8::53", "max-interval=300", "min-interval=200"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"entries": map[string]any{"interface": "opt1", "enabled": "0", "mode": "stateless",
		"RDNSS": "2001:db8::53", "MaxRtrAdvInterval": "300", "MinRtrAdvInterval": "200"}})
	wantExit(t, f.run("/radvd/entry", "set", "lan", "routes=", "link-mtu=1500", "deprecate-prefix=off"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"entries": map[string]any{"routes": "", "AdvLinkMTU": "1500", "DeprecatePrefix": "off"}})

	var refused = radvdFake(t)
	wantFailure(t, refused.run("/radvd/entry", "add", "interface=lan"), "exists already", radvdEntryUuid)
	for _, args := range [][]string{
		{"interface=opt1", "min-interval=500", "max-interval=600"}, {"interface=opt1", "mode="}, {"interface=opt1", "max-interval=2000"},
		{"interface=opt1", "source-address=2001:db8::1"}, {"interface=opt1", "dns-servers=192.0.2.1"}, {"interface=opt1", "link-mtu=100"},
	} {
		wantFailure(t, refused.run(append([]string{"/radvd/entry", "add"}, args...)...))
	}
	wantNoMutations(t, refused)
}

func TestRadvdService(t *testing.T) {
	t.Parallel()
	var f = radvdFake(t)
	f.on("GET", "/api/radvd/service/status", 200, `{"status":"stopped","widget":{}}`)
	f.on("POST", "/api/radvd/service/reconfigure", 200, `{"status":"ok"}`)
	f.on("POST", "/api/radvd/service/stop", 200, `{"response":"OK"}`)
	f.on("POST", "/api/radvd/settings/toggle_entry/"+radvdEntryUuid+"/1", 200, `{"result":"Enabled","changed":true}`)
	wantExit(t, f.run("/radvd/service", "status"), 0)
	wantFailure(t, f.run("/radvd/service", "stop"), "stops radvd", "confirm=yes")
	wantNoMutations(t, f)
	wantExit(t, f.run("/radvd/service", "stop", "confirm=yes"), 0)
	wantExit(t, f.run("/radvd/entry", "enable", "lan"), 0)
	wantExit(t, f.run("/radvd/service", "reconfigure"), 0)
	if got := len(f.mutations()); got != 3 {
		t.Errorf("mutations %v", f.mutations())
	}
}
