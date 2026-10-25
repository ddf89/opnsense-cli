package cli

import (
	"testing"
)

const vpnIpsecVtiUuid = "77100000-0000-4000-8000-000000000001"

func vpnIpsecVtiFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search("/api/ipsec/vti/search",
		map[string]any{"uuid": vpnIpsecVtiUuid, "enabled": "1", "reqid": "100", "local": "198.51.100.1", "remote": "192.0.2.1",
			"tunnel_local": "10.255.0.1", "tunnel_remote": "10.255.0.2", "tunnel_local2": "", "tunnel_remote2": "", "skip_fw": "0",
			"origin": "vti", "description": "to hq"},
		map[string]any{"uuid": "legacy-1", "enabled": "1", "reqid": "5", "local": "", "remote": "", "tunnel_local": "10.9.0.1",
			"tunnel_remote": "10.9.0.2", "tunnel_local2": "", "tunnel_remote2": "", "skip_fw": "0", "origin": "legacy", "description": "old"})
	return f
}

func TestVpnIpsecPool(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	var r = f.run("/vpn/ipsec/pool", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  no        mobile  198.51.100.128/25  -\n")

	f.on("POST", "/api/ipsec/pools/add", 200, answerAdded("p-new"))
	wantExit(t, f.run("/vpn/ipsec/pool", "add", "name=mobile6", "network=2001:db8:1::/64", "dns=2001:db8::53,192.0.2.53", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/pools/add"), map[string]any{"pool": map[string]any{
		"name": "mobile6", "addrs": "2001:db8:1::/64", "dns": "2001:db8::53,192.0.2.53", "enabled": "0"}})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		for _, args := range [][]string{
			{"name=mobile", "network=198.51.100.0/24"}, // exists
			{"name=two words", "network=198.51.100.0/24"},
			{"name=x", "network=198.51.100.1"},
			{"name=x"},
			{"name=x", "network=198.51.100.0/24", "dns=nope"},
		} {
			wantExit(t, f.run(append([]string{"/vpn/ipsec/pool", "add"}, args...)...), 1)
		}
		wantNoMutations(t, f)
	})
	t.Run("remove refused while a connection uses it", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		wantFailure(t, f.run("/vpn/ipsec/pool", "remove", "mobile"), `"roadwarrior"`, vpnIpsecConnRoad)
		wantNoMutations(t, f)
	})
}

func TestVpnIpsecVti(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecVtiFake(t)
	var r = f.run("/vpn/ipsec/vti", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  no        ipsec100  198.51.100.1  192.0.2.1  10.255.0.1 - 10.255.0.2  vti     to hq\n",
		"1  no        ipsec5    -             -          10.9.0.1 - 10.9.0.2      legacy  old\n")

	r = f.run("/vpn/ipsec/vti", "show", "ipsec100")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "uuid:            "+vpnIpsecVtiUuid+"\n", "tunnel-remote:   10.255.0.2\n", "skip-firewall:   no\n")

	f.on("POST", "/api/ipsec/vti/set/"+vpnIpsecVtiUuid, 200, answerSaved)
	wantExit(t, f.run("/vpn/ipsec/vti", "set", "to hq", "tunnel-local2=2001:db8::1", "tunnel-remote2=2001:db8::2", "skip-firewall"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/vti/set/"+vpnIpsecVtiUuid), map[string]any{"vti": map[string]any{
		"tunnel_local2": "2001:db8::1", "tunnel_remote2": "2001:db8::2", "skip_fw": "1"}})

	t.Run("legacy interfaces are read-only", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecVtiFake(t)
		wantFailure(t, f.run("/vpn/ipsec/vti", "set", "ipsec5", "description=x"), "legacy", "read-only")
		wantNoMutations(t, f)
	})
	t.Run("the reqid names the interface", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecVtiFake(t)
		f.on("GET", "/api/ipsec/vti/get", 200, `{"vti":{"enabled":"1","reqid":"","local":"","remote":"","tunnel_local":"","tunnel_remote":"","tunnel_local2":"","tunnel_remote2":"","skip_fw":"0","origin":"","description":""}}`)
		wantFailure(t, f.run("/vpn/ipsec/vti", "add", "reqid=100", "tunnel-local=10.0.0.1", "tunnel-remote=10.0.0.2"), "exists already", "ipsec100")
		wantFailure(t, f.run("/vpn/ipsec/vti", "add", "reqid=101", "tunnel-local=10.0.0.1"), "tunnel-remote")
		wantFailure(t, f.run("/vpn/ipsec/vti", "add", "reqid=0", "tunnel-local=10.0.0.1", "tunnel-remote=10.0.0.2"), "reqid")
		wantFailure(t, f.run("/vpn/ipsec/vti", "add", "reqid=101", "tunnel-local=10.0.0.0/30", "tunnel-remote=10.0.0.2"), "tunnel-local")
		wantNoMutations(t, f)
		f.on("POST", "/api/ipsec/vti/add", 200, answerAdded("v-new"))
		wantExit(t, f.run("/vpn/ipsec/vti", "add", "reqid=101", "tunnel-local=10.0.0.1", "tunnel-remote=10.0.0.2", "disabled"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/vti/add"), map[string]any{"vti": map[string]any{
			"reqid": "101", "tunnel_local": "10.0.0.1", "tunnel_remote": "10.0.0.2", "enabled": "0"}})
	})
}

func TestVpnIpsecManualSpd(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, true)
	var r = f.run("/vpn/ipsec/manual-spd", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  no        esp       -      site b - lan  10.0.0.0/24  -            nat lan\n")

	f.on("GET", "/api/ipsec/manual_spd/get", 200, `{"spd":{"enabled":"1","protocol":{"esp":{"value":"ESP","selected":1}},"reqid":"",`+
		`"connection_child":{"":{"value":"none","selected":1},"`+vpnIpsecChildUuid+`":{"value":"site b - lan","selected":0}},"source":"","destination":"","description":""}}`)
	f.on("POST", "/api/ipsec/manual_spd/add", 200, answerAdded("s-new"))
	wantExit(t, f.run("/vpn/ipsec/manual-spd", "add", "child=site b - lan", "source=198.51.100.0/24", "protocol=AH", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/manual_spd/add"), map[string]any{"spd": map[string]any{
		"connection_child": vpnIpsecChildUuid, "source": "198.51.100.0/24", "protocol": "ah", "enabled": "0"}})

	t.Run("either reqid or child", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, true)
		wantFailure(t, f.run("/vpn/ipsec/manual-spd", "add", "child=site b - lan", "reqid=5", "source=198.51.100.0/24"), "either reqid or child")
		wantNoCalls(t, f)
	})
}
