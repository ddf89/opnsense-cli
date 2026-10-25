package cli

import (
	"reflect"
	"strings"
	"testing"
)

const (
	hostDiscoverySettingsGetPath = "/api/hostdiscovery/settings/get"
	hostDiscoverySettingsSetPath = "/api/hostdiscovery/settings/set"
	hostDiscoverySearchPath      = "/api/hostdiscovery/service/search"
	hostDiscoverySettingsAnswer  = `{"hostdiscovery":{"general":{"enabled":"1","promisc":"0","verbose":"0",` +
		`"skip_nets":{"":{"value":"","selected":1}},"expire4_interval":"7200","expire6_interval":"",` +
		`"interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}}}}}`
)

func hostDiscoveryFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", hostDiscoverySettingsGetPath, 200, hostDiscoverySettingsAnswer)
	f.search(hostDiscoverySearchPath,
		map[string]any{"source": "hostwatch", "interface_name": "LAN", "ether_address": "52:54:00:12:34:56", "ip_address": "192.168.1.1",
			"organization_name": "QEMU", "first_seen": "2026-10-25 10:00:00", "last_seen": "2026-10-25 12:00:00"},
		map[string]any{"source": "hostwatch", "interface_name": "WAN", "ether_address": "52:55:0a:00:02:02", "ip_address": "10.0.2.2",
			"organization_name": "", "first_seen": "2026-10-25 10:00:01", "last_seen": "2026-10-25 12:00:01"},
	)
	return f
}

func TestHostDiscoveryPrint(t *testing.T) {
	t.Parallel()
	var f = hostDiscoveryFake(t)
	var r = f.run("/interface/host-discovery", "print")
	wantExit(t, r, 0)
	var lines = firewallGroupLines(r.stdout)
	if len(lines) != 3 || lines[0] != "INTERFACE|IP|MAC|ORGANIZATION|FIRST-SEEN|LAST-SEEN|SOURCE" ||
		!strings.HasPrefix(lines[1], "LAN|192.168.1.1|52:54:00:12:34:56|QEMU|2026-10-25") || !strings.HasPrefix(lines[2], "WAN|10.0.2.2|") {
		t.Errorf("print: %q", lines)
	}
	var wan = f.run("/interface/host-discovery", "print", "interface=wan", "json")
	wantExit(t, wan, 0)
	if !strings.HasPrefix(wan.stdout, `{"source":"hostwatch","interface_name":"WAN"`) || strings.Count(wan.stdout, "\n") != 1 {
		t.Errorf("json: %q", wan.stdout)
	}
	var searched = f.run("/interface/host-discovery", "print", "search=qemu", "detail")
	wantExit(t, searched, 0)
	wantContains(t, "detail", searched.stdout, "ip:            192.168.1.1\n", "organization:  QEMU\n")
	wantNotContains(t, "detail", searched.stdout, "10.0.2.2")
	wantNoMutations(t, f)
}

func TestHostDiscoveryService(t *testing.T) {
	t.Parallel()
	var f = hostDiscoveryFake(t)
	f.on("GET", "/api/hostdiscovery/service/status", 200, `{"status":"running"}`)
	var r = f.run("/interface/host-discovery", "status")
	wantExit(t, r, 0)
	if r.stdout != "status:  running\n" {
		t.Errorf("status %q", r.stdout)
	}
	for _, action := range []string{"start", "stop", "restart"} {
		var f = hostDiscoveryFake(t)
		f.on("POST", "/api/hostdiscovery/service/"+action, 200, `{"response":"OK"}`)
		wantExit(t, f.run("/interface/host-discovery", action), 0)
		wantOneMutation(t, f, "POST", "/api/hostdiscovery/service/"+action)
	}
	f.on("POST", "/api/hostdiscovery/service/reconfigure", 200, `{"status":"failed","status_msg":"Service \"hostwatch\" failed to start."}`)
	wantFailure(t, f.run("/interface/host-discovery", "reconfigure"), "failed to start")
}

func TestHostDiscoverySettings(t *testing.T) {
	t.Parallel()
	var f = hostDiscoveryFake(t)
	var r = f.run("/interface/host-discovery/settings", "print")
	wantExit(t, r, 0)
	var want = []string{"enabled:|yes", "promisc:|no", "verbose:|no", "interfaces:|lan", "skip-nets:", "expire-ipv4:|2h0m0s", "expire-ipv6:|default"}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var options = f.run("/interface/host-discovery/settings", "print", "options")
	wantExit(t, options, 0)
	if got := firewallGroupLines(options.stdout); !reflect.DeepEqual(got, []string{"KEY|NAME|SELECTED", "lan|LAN|yes", "wan|WAN|no"}) {
		t.Errorf("options: %q", got)
	}
	var asJSON = f.run("/interface/host-discovery/settings", "print", "json")
	wantContains(t, "json", asJSON.stdout, `"expire4_interval":"7200"`, `"interface":"lan"`)

	f.on("POST", hostDiscoverySettingsSetPath, 200, answerSaved)
	var set = f.run("/interface/host-discovery/settings", "set", "interfaces=lan,wan", "promisc", "expire-ipv4=4h", "expire-ipv6=",
		"skip-nets=10.99.0.0/16")
	wantExit(t, set, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", hostDiscoverySettingsSetPath), map[string]any{"hostdiscovery": map[string]any{
		"general": map[string]any{"interface": "lan,wan", "promisc": "1", "expire4_interval": "14400", "expire6_interval": "",
			"skip_nets": "10.99.0.0/16"}}})

	for _, args := range [][]string{{}, {"expire-ipv4=30m"}, {"expire-ipv6=1.5"}, {"enabled=maybe"}} {
		var f = hostDiscoveryFake(t)
		wantFailure(t, f.run(append([]string{"/interface/host-discovery/settings", "set"}, args...)...))
		wantNoMutations(t, f)
	}
}
