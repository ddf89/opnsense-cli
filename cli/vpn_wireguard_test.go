package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	wireguardTestServerSearch = "/api/wireguard/server/search_server"
	wireguardTestClientSearch = "/api/wireguard/client/search_client"
	wireguardTestKeyPair      = "/api/wireguard/server/key_pair"
	// RFC 7748 6.1 (Alice) and the private key of Bob as a second pair
	wireguardTestPrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	wireguardTestPublicKey  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	wireguardTestPsk        = "XU7lDKJaGCKz3HEIJvMJ6sCPZnwEwxmGu4ZYKr0Ux6w="
)

func wireguardTestInstanceRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "i-1", "enabled": "1", "name": "wg-office", "instance": "0", "pubkey": wireguardTestPublicKey,
		"privkey": wireguardTestPrivateKey, "port": "51820", "mtu": "1420", "dns": "", "tunneladdress": "10.9.0.1/24",
		"disableroutes": "0", "gateway": "", "carp_depend_on": "", "peers": "p-1", "%peers": "laptop", "debug": "0",
		"cnfFilename": "/usr/local/etc/wireguard/wg0.conf", "statFilename": "/usr/local/etc/wireguard/wg0.stat",
		"interface": "wg0", "endpoint": "vpn.example.com:51820", "peer_dns": "10.9.0.1",
	}, overrides)
}

func wireguardTestPeerRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "p-1", "enabled": "1", "name": "laptop", "pubkey": wireguardTestPublicKey, "psk": wireguardTestPsk,
		"tunneladdress": "10.9.0.2/32", "serveraddress": "", "serverport": "", "endpoint": "", "keepalive": "25",
		"servers": "i-1", "%servers": "wg-office",
	}, overrides)
}

func wireguardTestFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(wireguardTestServerSearch, wireguardTestInstanceRow(nil),
		wireguardTestInstanceRow(map[string]any{"uuid": "i-2", "name": "wg-home", "enabled": "0", "peers": "", "%peers": "", "interface": "wg1", "instance": "1"}))
	f.search(wireguardTestClientSearch, wireguardTestPeerRow(nil),
		wireguardTestPeerRow(map[string]any{"uuid": "p-2", "name": "phone", "enabled": "0", "servers": "", "%servers": "", "psk": ""}))
	f.on("GET", wireguardTestKeyPair, 200, `{"status":"ok","pubkey":"`+wireguardTestPublicKey+`","privkey":"`+wireguardTestPrivateKey+`"}`)
	f.on("GET", "/api/wireguard/client/psk", 200, `{"status":"ok","psk":"`+wireguardTestPsk+`"}`)
	f.on("GET", "/api/wireguard/client/get_server_info/i-1", 200, `{"status":"ok","endpoint":"vpn.example.com:51820","peer_dns":"10.9.0.1",`+
		`"mtu":"1420","pubkey":"`+wireguardTestPublicKey+`","address":"10.9.0.3/32"}`)
	return f
}

func TestWireguardInstancePrintMasksKeys(t *testing.T) {
	t.Parallel()
	var f = wireguardTestFake(t)
	var r = f.run("/vpn/wireguard/instance", "print")
	wantExit(t, r, 0)
	systemCronWantTable(t, r.stdout, []string{"#", "DISABLED", "NAME", "DEVICE", "PORT", "TUNNEL-ADDRESS", "PEERS"}, 2, "wg-office", "wg-home")
	for _, args := range [][]string{{"print", "detail"}, {"print", "json"}, {"show", "wg-office"}} {
		r = f.run(append([]string{"/vpn/wireguard/instance"}, args...)...)
		wantExit(t, r, 0)
		wantNotContains(t, "stdout", r.stdout, wireguardTestPrivateKey)
		wantContains(t, "stdout", r.stdout, wireguardTestPublicKey, "********")
	}
	wantNoMutations(t, f)
}

func TestWireguardInstanceAdd(t *testing.T) {
	t.Parallel()
	t.Run("generates a key pair", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		f.on("POST", "/api/wireguard/server/add_server", 200, answerAdded("i-new"))
		var r = f.run("/vpn/wireguard/instance", "add", "name=wg-new", "disabled", "port=51821", "tunnel-address=10.8.0.1/24,fd00:8::1/64", "peers=phone")
		wantExit(t, r, 0)
		if r.stdout != "i-new\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantNotContains(t, "output", r.stdout+r.stderr, wireguardTestPrivateKey)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/wireguard/server/add_server"), map[string]any{"server": map[string]any{
			"name": "wg-new", "enabled": "0", "port": "51821", "tunneladdress": "10.8.0.1/24,fd00:8::1/64", "peers": "p-2",
			"privkey": wireguardTestPrivateKey, "pubkey": wireguardTestPublicKey}})
	})
	t.Run("derives the public key", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		f.on("POST", "/api/wireguard/server/add_server", 200, answerAdded("i-new"))
		wantExit(t, f.run("/vpn/wireguard/instance", "add", "name=wg-new", "private-key="+wireguardTestPrivateKey), 0)
		var body = wantOneMutation(t, f, "POST", "/api/wireguard/server/add_server").json(t)["server"].(map[string]any)
		if body["pubkey"] != wireguardTestPublicKey {
			t.Errorf("body %v", body)
		}
		for _, call := range f.calls() {
			if call.Path == wireguardTestKeyPair {
				t.Error("a given private key must not generate a pair")
			}
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		wantFailure(t, f.run("/vpn/wireguard/instance", "add", "name=WG-OFFICE"), "exists already", "i-1")
		wantNoMutations(t, f)
	})
	t.Run("invalid input sends nothing", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		for _, arg := range []string{"name=bad name", "private-key=abc", "tunnel-address=10.0.0.300/24", "port=70000"} {
			var args = []string{"/vpn/wireguard/instance", "add", "name=wg-x", arg}
			wantExit(t, f.run(args...), 1)
		}
		wantNoCalls(t, f)
	})
	t.Run("validation names the argument", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		f.on("POST", "/api/wireguard/server/add_server", 200, answerValidation("server.gateway", "You have to enable Disable Routes option."))
		wantFailure(t, f.run("/vpn/wireguard/instance", "add", "name=wg-x", "gateway=10.0.0.1"), "gateway: You have to enable")
	})
}

func TestWireguardInstanceSetAndToggle(t *testing.T) {
	t.Parallel()
	var f = wireguardTestFake(t)
	f.on("POST", "/api/wireguard/server/set_server/i-1", 200, answerSaved)
	wantExit(t, f.run("/vpn/wireguard/instance", "set", "wg-office", "new-keys", "port="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/wireguard/server/set_server/i-1"), map[string]any{"server": map[string]any{
		"port": "", "privkey": wireguardTestPrivateKey, "pubkey": wireguardTestPublicKey}})

	var g = wireguardTestFake(t)
	g.on("POST", "/api/wireguard/server/set_server/i-2", 200, answerSaved)
	wantExit(t, g.run("/vpn/wireguard/instance", "enable", "wg-home"), 0)
	// set_server, never toggle_server (it ignores the state and flips)
	wantJSON(t, wantOneMutation(t, g, "POST", "/api/wireguard/server/set_server/i-2"), map[string]any{"server": map[string]any{"enabled": "1"}})
	var r = g.run("/vpn/wireguard/instance", "disable", "wg-home")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "already disabled")

	var h = wireguardTestFake(t)
	wantExit(t, h.run("/vpn/wireguard/instance", "set", "wg-office", "new-keys", "private-key="+wireguardTestPrivateKey), 1)
	wantExit(t, h.run("/vpn/wireguard/instance", "set", "wg-office"), 1)
	wantFailure(t, h.run("/vpn/wireguard/instance", "set", "wg-office", "name=wg-home"), "another instance")
	wantNoMutations(t, h)
}

func TestWireguardPeer(t *testing.T) {
	t.Parallel()
	t.Run("print and show mask the psk", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		var r = f.run("/vpn/wireguard/peer", "print", "instance=wg-office")
		wantExit(t, r, 0)
		systemCronWantTable(t, r.stdout, []string{"#", "DISABLED", "NAME", "INSTANCES", "TUNNEL-ADDRESS", "ENDPOINT", "KEEPALIVE"}, 2, "laptop")
		for _, args := range [][]string{{"print", "json"}, {"print", "detail"}, {"show", "laptop"}} {
			r = f.run(append([]string{"/vpn/wireguard/peer"}, args...)...)
			wantExit(t, r, 0)
			wantNotContains(t, "stdout", r.stdout, wireguardTestPsk)
		}
	})
	t.Run("add links to the instance", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		f.on("POST", "/api/wireguard/client/add_client", 200, answerAdded("p-new"))
		wantExit(t, f.run("/vpn/wireguard/peer", "add", "name=tablet", "public-key="+wireguardTestPublicKey, "tunnel-address=10.9.0.9/32",
			"instance=wg-office", "generate-psk", "endpoint-address=peer.example.com", "endpoint-port=51820"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/wireguard/client/add_client"), map[string]any{"client": map[string]any{
			"name": "tablet", "pubkey": wireguardTestPublicKey, "tunneladdress": "10.9.0.9/32", "servers": "i-1", "psk": wireguardTestPsk,
			"serveraddress": "peer.example.com", "serverport": "51820"}})
	})
	t.Run("set keeps the instances", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		f.on("POST", "/api/wireguard/client/set_client/p-1", 200, answerSaved)
		wantExit(t, f.run("/vpn/wireguard/peer", "set", "laptop", "keepalive="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/wireguard/client/set_client/p-1"), map[string]any{"client": map[string]any{
			"keepalive": "", "servers": "i-1"}})
	})
	t.Run("unknown instance", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		wantFailure(t, f.run("/vpn/wireguard/peer", "set", "laptop", "instances=nope"), "valid are: wg-office, wg-home")
		wantNoMutations(t, f)
	})
}

func TestWireguardPeerGenerate(t *testing.T) {
	t.Parallel()
	var f = wireguardTestFake(t)
	f.on("POST", "/api/wireguard/client/add_client", 200, answerAdded("p-new"))
	f.on("POST", "/api/wireguard/server/set_server/i-1", 200, answerSaved)
	var dir = t.TempDir()
	var r = runOpnIn(t, dir, f.env(), "/vpn/wireguard/peer", "generate", "name=tablet", "instance=wg-office", "keepalive=25", "psk",
		"endpoint=vpn2.example.com:51820")
	wantExit(t, r, 0)
	if r.stdout != "p-new\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	var content, err = os.ReadFile(filepath.Join(dir, "tablet.conf"))
	if err != nil {
		t.Fatal(err)
	}
	var want = "[Interface]\nPrivateKey = " + wireguardTestPrivateKey + "\nAddress = 10.9.0.3/32\nDNS = 10.9.0.1\nMTU = 1420\n\n[Peer]\nPublicKey = " +
		wireguardTestPublicKey + "\nPresharedKey = " + wireguardTestPsk + "\nEndpoint = vpn2.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
	if string(content) != want {
		t.Errorf("config:\n%s", content)
	}
	if info, _ := os.Stat(filepath.Join(dir, "tablet.conf")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode())
	}
	var mutations = f.mutations()
	if len(mutations) != 2 {
		t.Fatalf("mutations %v", mutations)
	}
	wantJSON(t, mutations[0], map[string]any{"client": map[string]any{"enabled": "1", "name": "tablet", "pubkey": wireguardTestPublicKey,
		"psk": wireguardTestPsk, "tunneladdress": "10.9.0.3/32", "keepalive": "25", "servers": "i-1"}})
	// the changed endpoint becomes the instance default, like the GUI
	wantJSON(t, mutations[1], map[string]any{"server": map[string]any{"endpoint": "vpn2.example.com:51820"}})

	t.Run("existing file", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		var dir = t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "tablet.conf"), []byte("x"), 0o600)
		wantFailure(t, runOpnIn(t, dir, f.env(), "/vpn/wireguard/peer", "generate", "name=tablet", "instance=wg-office"), "already exists")
		wantNoMutations(t, f)
	})
	t.Run("existing peer", func(t *testing.T) {
		t.Parallel()
		var f = wireguardTestFake(t)
		wantFailure(t, f.run("/vpn/wireguard/peer", "generate", "name=laptop", "instance=wg-office", "file=-"), "exists already")
		wantNoMutations(t, f)
	})
}

func TestWireguardPeerConfig(t *testing.T) {
	t.Parallel()
	var f = wireguardTestFake(t)
	wantFailure(t, f.run("/vpn/wireguard/peer", "config", "laptop", "file=-"), "does not store the private key")

	var g = newFakeOPN(t)
	g.search(wireguardTestServerSearch, wireguardTestInstanceRow(nil))
	g.search(wireguardTestClientSearch, wireguardTestPeerRow(map[string]any{"privkey": wireguardTestPrivateKey}))
	g.on("GET", "/api/wireguard/client/get_server_info/i-1", 200, `{"status":"ok","endpoint":"vpn.example.com:51820","peer_dns":"",`+
		`"mtu":"","pubkey":"`+wireguardTestPublicKey+`","address":"10.9.0.3/32","allowed_ips":"10.0.0.0/8"}`)
	var r = g.run("/vpn/wireguard/peer", "config", "laptop", "file=-")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "PrivateKey = "+wireguardTestPrivateKey, "Address = 10.9.0.2/32", "PresharedKey = "+wireguardTestPsk,
		"AllowedIPs = 10.0.0.0/8", "PersistentKeepalive = 25")
	wantNoMutations(t, g)
}

func TestWireguardStatusSettingsService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/wireguard/service/show", 200, `{"rows":[
		{"if":"wg0","type":"interface","public-key":"pub0","listen-port":"51820","endpoint":"51820","status":"up","name":"wg-office","latest-handshake-age":null,"peer-status":"offline","ifname":"wg-office"},
		{"if":"wg0","type":"peer","public-key":"pub1","endpoint":"198.51.100.7:40000","allowed-ips":"10.9.0.2/32","latest-handshake":1761400000,"transfer-rx":1234,"transfer-tx":5678000,"persistent-keepalive":"25","name":"laptop","latest-handshake-age":42,"peer-status":"online","ifname":"wg-office"}]}`)
	f.on("GET", "/api/wireguard/general/get", 200, `{"general":{"enabled":"0"}}`)
	f.on("POST", "/api/wireguard/general/set", 200, answerSaved)
	f.on("GET", "/api/wireguard/service/status", 200, `{"status":"stopped"}`)
	var r = f.run("/vpn/wireguard/status", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, []string{"#", "DEVICE", "TYPE", "NAME", "STATUS", "ENDPOINT", "HANDSHAKE-AGE", "SENT", "RECEIVED"},
		3, "wg-office", "laptop")
	if got := strings.Join(rows[2], "|"); got != "1|wg0|peer|laptop|online|198.51.100.7:40000|42s|5.7 MB|1.2 kB" {
		t.Errorf("peer row %q", got)
	}
	wantExit(t, f.run("/vpn/wireguard/status", "print", "type=peer"), 0)

	r = f.run("/vpn/wireguard/settings", "print")
	wantContains(t, "stdout", r.stdout, "enabled:  no")
	wantExit(t, f.run("/vpn/wireguard/settings", "set", "enabled=no"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/wireguard/general/set"), map[string]any{"general": map[string]any{"enabled": "0"}})
	r = f.run("/vpn/wireguard/service", "status")
	wantContains(t, "stdout", r.stdout, "status:  stopped")

	var g = newFakeOPN(t)
	for _, action := range []string{"stop", "restart"} {
		wantExit(t, g.run("/vpn/wireguard/service", action), 1)
	}
	wantNoCalls(t, g)
	g.on("POST", "/api/wireguard/service/stop", 200, `{"response":"OK"}`)
	g.on("POST", "/api/wireguard/service/reconfigure", 200, `{"result":"ok"}`)
	wantExit(t, g.run("/vpn/wireguard/service", "stop", "confirm=yes"), 0)
	wantExit(t, g.run("/vpn/wireguard/service", "apply"), 0)
}
