package cli

import (
	"strings"
	"testing"
)

const (
	vpnIpsecConnPath  = "/api/ipsec/connections/"
	vpnIpsecConnSite  = "c0a1b2c3-0000-4000-8000-000000000001"
	vpnIpsecConnRoad  = "c0a1b2c3-0000-4000-8000-000000000002"
	vpnIpsecLocalUuid = "10ca1000-0000-4000-8000-000000000001"
	vpnIpsecChildUuid = "c41d0000-0000-4000-8000-000000000001"
	vpnIpsecPoolUuid  = "9001aaaa-0000-4000-8000-000000000001"
	vpnIpsecKeyUuid   = "6e7aaaaa-0000-4000-8000-000000000001"
)

// vpnIpsecConnRow is a search_connection row of OPNsense 26.7
func vpnIpsecConnRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": vpnIpsecConnSite, "enabled": "1", "proposals": "default", "unique": "no", "%unique": "No (default)", "aggressive": "0",
		"version": "2", "%version": "IKEv2", "mobike": "1", "local_addrs": "198.51.100.1", "local_port": "", "remote_addrs": "192.0.2.1",
		"remote_port": "", "encap": "0", "reauth_time": "", "rekey_time": "", "over_time": "", "dpd_delay": "", "dpd_timeout": "",
		"pools": "", "send_certreq": "1", "send_cert": "", "keyingtries": "", "description": "site b", "local_ts": "", "remote_ts": "",
	}, overrides)
}

func vpnIpsecLocalRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": vpnIpsecLocalUuid, "enabled": "1", "connection": vpnIpsecConnSite, "%connection": "site b", "round": "0", "auth": "psk",
		"%auth": "Pre-Shared Key", "id": "fw.example.com", "eap_id": "", "certs": "", "pubkeys": "", "description": "site b local",
	}, overrides)
}

func vpnIpsecChildRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": vpnIpsecChildUuid, "enabled": "1", "connection": vpnIpsecConnSite, "%connection": "site b", "reqid": "", "esp_proposals": "default",
		"sha256_96": "0", "start_action": "start", "%start_action": "Start", "close_action": "none", "dpd_action": "clear", "mode": "tunnel",
		"%mode": "Tunnel", "policies": "1", "local_ts": "198.51.100.0/24", "remote_ts": "192.0.2.0/24", "rekey_time": "3600",
		"replay_window": "", "description": "lan",
	}, overrides)
}

const vpnIpsecConnForm = `{"connection":{"enabled":"1",` +
	`"proposals":{"default":{"value":"default","optgroup":"Internal","selected":1},"aes256gcm16-sha256-x25519":{"value":"aes256gcm16-sha256-curve25519 [DH31, Modern EC]","selected":0}},` +
	`"unique":{"no":{"value":"No (default)","selected":1},"never":{"value":"Never","selected":0},"keep":{"value":"Keep","selected":0},"replace":{"value":"Replace","selected":0}},` +
	`"aggressive":"0","version":[{"value":"IKEv1+IKEv2","selected":1},{"value":"IKEv1","selected":0},{"value":"IKEv2","selected":0}],"mobike":"1",` +
	`"local_addrs":{"":{"value":"","selected":1}},"local_port":{"":{"value":"500 (default)","selected":1},"4500":{"value":"4500 (NAT-T)","selected":0}},` +
	`"remote_addrs":{"":{"value":"","selected":1}},"remote_port":{"":{"value":"500 (default)","selected":1},"4500":{"value":"4500 (NAT-T)","selected":0}},` +
	`"encap":"0","reauth_time":"","rekey_time":"","over_time":"","dpd_delay":"","dpd_timeout":"",` +
	`"pools":{"radius":{"value":"radius","selected":0},"` + vpnIpsecPoolUuid + `":{"value":"mobile","selected":0}},"send_certreq":"1",` +
	`"send_cert":{"":{"value":"Default","selected":1},"ifasked":{"value":"If asked","selected":0}},"keyingtries":"","description":"",` +
	`"local_ts":"","remote_ts":"","org_uuid":null,"uuid":"d9aca420-3e36-43ef-92a6-33fb4b6923e7"}}`

const vpnIpsecLocalForm = `{"local":{"enabled":"1","connection":{"` + vpnIpsecConnSite + `":{"value":"site b","selected":0}},"round":"0",` +
	`"auth":{"psk":{"value":"Pre-Shared Key","selected":1},"pubkey":{"value":"Public Key","selected":0}},"id":"","eap_id":"",` +
	`"certs":{"6ade1fe2418b9":{"value":"Web GUI TLS certificate","selected":0}},` +
	`"pubkeys":{"` + vpnIpsecKeyUuid + `":{"value":"fw key","selected":0}},"description":""}}`

// vpnIpsecFake serves two connections, a local round and a child of "site b", a pool and a manual SPD entry
// using the child when spd is set
func vpnIpsecFake(t *testing.T, spd bool) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(vpnIpsecConnPath+"search_connection", vpnIpsecConnRow(nil),
		vpnIpsecConnRow(map[string]any{"uuid": vpnIpsecConnRoad, "description": "roadwarrior", "version": "0", "%version": "IKEv1+IKEv2",
			"pools": vpnIpsecPoolUuid, "enabled": "0"}))
	f.search(vpnIpsecConnPath+"search_local", vpnIpsecLocalRow(nil))
	f.search(vpnIpsecConnPath + "search_remote")
	f.search(vpnIpsecConnPath+"search_child", vpnIpsecChildRow(nil))
	f.search("/api/ipsec/pools/search", map[string]any{"uuid": vpnIpsecPoolUuid, "enabled": "1", "name": "mobile", "addrs": "198.51.100.128/25", "dns": ""})
	if spd {
		f.search("/api/ipsec/manual_spd/search", map[string]any{"uuid": "5bd00000-0000-4000-8000-000000000001", "enabled": "1", "protocol": "esp",
			"reqid": "", "connection_child": vpnIpsecChildUuid, "%connection_child": "site b - lan", "source": "10.0.0.0/24", "destination": "",
			"description": "nat lan", "origin": "spd"})
	} else {
		f.search("/api/ipsec/manual_spd/search")
	}
	f.on("GET", vpnIpsecConnPath+"get_connection", 200, vpnIpsecConnForm)
	f.on("GET", vpnIpsecConnPath+"get_local", 200, vpnIpsecLocalForm)
	f.on("GET", "/api/ipsec/pools/get", 200, `{"pool":{"enabled":"1","name":"","addrs":"","dns":{"":{"value":"","selected":1}}}}`)
	return f
}

func TestVpnIpsecConnectionPrint(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	var r = f.run("/vpn/ipsec/connection", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "#  DISABLED  VERSION      LOCAL         REMOTE     PROPOSALS  DESCRIPTION\n",
		"0  no        IKEv2        198.51.100.1  192.0.2.1  default    site b\n",
		"1  yes       IKEv1+IKEv2  198.51.100.1  192.0.2.1  default    roadwarrior\n")
	wantNoMutations(t, f)

	t.Run("detail and show render the arguments", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		var r = f.run("/vpn/ipsec/connection", "show", "ROADWARRIOR")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "uuid:               "+vpnIpsecConnRoad+"\n", "disabled:           yes\n", "version:            ike\n",
			"pools:              mobile\n", "local-port:         500\n", "send-cert:          default\n", "mobike:             yes\n")
		r = f.run("/vpn/ipsec/connection", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:               "+vpnIpsecConnSite+"\n", "\n1\n  uuid:               "+vpnIpsecConnRoad+"\n")
	})
	t.Run("json and search", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		var r = f.run("/vpn/ipsec/connection", "print", "json", "search=ROAD")
		wantExit(t, r, 0)
		if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"description":"roadwarrior"`) ||
			!strings.Contains(lines[0], `"%version":"IKEv1+IKEv2"`) {
			t.Errorf("unexpected json:\n%s", r.stdout)
		}
	})
}

func TestVpnIpsecConnectionAdd(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	f.on("POST", vpnIpsecConnPath+"add_connection", 200, answerAdded("new-uuid"))
	var r = f.run("/vpn/ipsec/connection", "add", "description=hq", "disabled", "version=IKEv2", "proposals=AES256GCM16-sha256-x25519,default",
		"local-addresses=198.51.100.1", "remote-addresses=192.0.2.9,hq.example.com", "remote-port=4500", "pools=Mobile,radius", "send-cert=if-asked",
		"udp-encapsulation", "rekey-time=14400", "unique=Replace")
	wantExit(t, r, 0)
	if r.stdout != "new-uuid\n" {
		t.Errorf("want the uuid, got %q", r.stdout)
	}
	var call = wantOneMutation(t, f, "POST", vpnIpsecConnPath+"add_connection")
	wantJSON(t, call, map[string]any{"connection": map[string]any{"description": "hq", "enabled": "0", "version": "2",
		"proposals": "aes256gcm16-sha256-x25519,default", "local_addrs": "198.51.100.1", "remote_addrs": "192.0.2.9,hq.example.com",
		"remote_port": "4500", "pools": vpnIpsecPoolUuid + ",radius", "send_cert": "ifasked", "encap": "1", "rekey_time": "14400", "unique": "replace"}})

	t.Run("existing description", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		wantFailure(t, f.run("/vpn/ipsec/connection", "add", "description=Site B"), "exists already", vpnIpsecConnSite)
		wantNoMutations(t, f)
	})
	t.Run("replace starts from the defaults", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"set_connection/"+vpnIpsecConnSite, 200, answerSaved)
		var r = f.run("/vpn/ipsec/connection", "add", "description=site b", "remote-addresses=192.0.2.2", "disabled", "replace")
		wantExit(t, r, 0)
		if r.stdout != vpnIpsecConnSite+"\n" || !strings.Contains(r.stderr, "replaced") {
			t.Errorf("unexpected output:\n%s", r)
		}
		var call = wantOneMutation(t, f, "POST", vpnIpsecConnPath+"set_connection/"+vpnIpsecConnSite)
		wantJSON(t, call, map[string]any{"connection": map[string]any{"enabled": "0", "proposals": "default", "unique": "no", "aggressive": "0",
			"version": "0", "mobike": "1", "local_addrs": "", "local_port": "", "remote_addrs": "192.0.2.2", "remote_port": "", "encap": "0",
			"reauth_time": "", "rekey_time": "", "over_time": "", "dpd_delay": "", "dpd_timeout": "", "pools": "", "send_certreq": "1",
			"send_cert": "", "keyingtries": "", "description": "site b"}})
	})
	t.Run("invalid input sends nothing", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"remote-addresses=192.0.2.1"}, // no description
			{"description=x", "version=3"},
			{"description=x", "rekey-time=-1"},
			{"description=x", "local-port=501"},
			{"description=x", "proposals=nope"},
			{"description=x", "pools=other"},
			{"description=x", "proposals="},
		} {
			var f = vpnIpsecFake(t, false)
			var r = f.run(append([]string{"/vpn/ipsec/connection", "add"}, args...)...)
			wantExit(t, r, 1)
			wantNoMutations(t, f)
		}
	})
	t.Run("validation errors name the arguments", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"add_connection", 200,
			`{"result":"failed","validations":{"connection.remote_addrs":"Entry \"x y\" is not a valid hostname, IP address or range.","connection.rekey_time":["Invalid integer value."]}}`)
		wantFailure(t, f.run("/vpn/ipsec/connection", "add", "description=hq", "remote-addresses=x y"),
			`remote-addresses: Entry "x y" is not a valid hostname`, "rekey-time: Invalid integer value.")
	})
}

func TestVpnIpsecConnectionSetRemoveToggle(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	f.on("POST", vpnIpsecConnPath+"set_connection/"+vpnIpsecConnRoad, 200, answerSaved)
	wantExit(t, f.run("/vpn/ipsec/connection", "set", "1", "dpd-delay=30", "mobike=no", "pools="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", vpnIpsecConnPath+"set_connection/"+vpnIpsecConnRoad),
		map[string]any{"connection": map[string]any{"dpd_delay": "30", "mobike": "0", "pools": ""}})

	t.Run("rename to an existing description", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		wantFailure(t, f.run("/vpn/ipsec/connection", "set", "roadwarrior", "description=SITE B"), "another connection", vpnIpsecConnSite)
		wantFailure(t, f.run("/vpn/ipsec/connection", "set", "roadwarrior"), "nothing to change")
		wantFailure(t, f.run("/vpn/ipsec/connection", "set", "nope", "dpd-delay=1"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"del_connection/"+vpnIpsecConnSite, 200, answerDeleted)
		wantExit(t, f.run("/vpn/ipsec/connection", "remove", "site b"), 0)
		wantOneMutation(t, f, "POST", vpnIpsecConnPath+"del_connection/"+vpnIpsecConnSite)
	})
	t.Run("remove refused while a manual SPD entry uses a child", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, true)
		wantFailure(t, f.run("/vpn/ipsec/connection", "remove", "site b"), `"nat lan"`, "manual SPD")
		wantNoMutations(t, f)
	})
	t.Run("enable and disable", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"toggle_connection/"+vpnIpsecConnRoad+"/1", 200, `{"result":"Enabled","changed":true}`)
		f.on("POST", vpnIpsecConnPath+"toggle_connection/"+vpnIpsecConnSite+"/1", 200, `{"result":"Enabled","changed":false}`)
		wantExit(t, f.run("/vpn/ipsec/connection", "enable", "roadwarrior"), 0)
		var r = f.run("/vpn/ipsec/connection", "enable", "0")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "already enabled")
		if calls := f.mutations(); len(calls) != 2 {
			t.Errorf("want two toggles, got %v", calls)
		}
	})
}

func TestVpnIpsecRounds(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	var r = f.run("/vpn/ipsec/local", "print", "connection=roadwarrior")
	wantExit(t, r, 0)
	if strings.Contains(r.stdout, "fw.example.com") {
		t.Errorf("the filter must drop the rounds of other connections:\n%s", r.stdout)
	}
	r = f.run("/vpn/ipsec/local", "print")
	wantContains(t, "stdout", r.stdout, "0  no        site b      0      psk   fw.example.com  site b local\n")

	t.Run("add resolves connection and references", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"add_local", 200, answerAdded("l-new"))
		var r = f.run("/vpn/ipsec/local", "add", "connection=Roadwarrior", "auth=pubkey", "pubkeys=FW KEY", "certs=6ade1fe2418b9", "id=fw.example.com", "disabled")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", vpnIpsecConnPath+"add_local"), map[string]any{"local": map[string]any{
			"connection": vpnIpsecConnRoad, "auth": "pubkey", "pubkeys": vpnIpsecKeyUuid, "certs": "6ade1fe2418b9", "id": "fw.example.com", "enabled": "0"}})
	})
	t.Run("the connection and round name a round", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		wantFailure(t, f.run("/vpn/ipsec/local", "add", "connection=site b", "id=x"), "exists already", "round 0 of \"site b\"")
		wantFailure(t, f.run("/vpn/ipsec/local", "add", "id=x"), "connection")
		wantFailure(t, f.run("/vpn/ipsec/local", "add", "connection=nope", "id=x"), "not found", "nope")
		wantFailure(t, f.run("/vpn/ipsec/local", "add", "connection=site b", "round=1", "pubkeys=other"), "pubkeys", "fw key")
		wantFailure(t, f.run("/vpn/ipsec/local", "add", "connection=site b", "round=11"), "round")
		wantNoMutations(t, f)
		f.on("POST", vpnIpsecConnPath+"add_local", 200, answerAdded("l-new"))
		wantExit(t, f.run("/vpn/ipsec/local", "add", "connection=site b", "round=1", "auth=eap-mschapv2"), 0)
	})
	t.Run("show and set", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		var r = f.run("/vpn/ipsec/local", "show", "site b local")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "connection:   site b\n", "round:        0\n", "auth:         psk\n")
		f.on("POST", vpnIpsecConnPath+"set_local/"+vpnIpsecLocalUuid, 200, answerSaved)
		wantExit(t, f.run("/vpn/ipsec/local", "set", "0", "connection=roadwarrior", "eap-id=%any"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", vpnIpsecConnPath+"set_local/"+vpnIpsecLocalUuid),
			map[string]any{"local": map[string]any{"connection": vpnIpsecConnRoad, "eap_id": "%any"}})
	})
}

func TestVpnIpsecChild(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecFake(t, false)
	f.on("GET", vpnIpsecConnPath+"get_child", 200, `{"child":{"enabled":"1","esp_proposals":{"default":{"value":"default","selected":1}},"mode":{"tunnel":{"value":"Tunnel","selected":1}},"rekey_time":"3600","description":""}}`)
	f.on("POST", vpnIpsecConnPath+"add_child", 200, answerAdded("ch-new"))
	var r = f.run("/vpn/ipsec/child", "add", "connection=site b", "description=dmz", "local-ts=198.51.100.64/26,2001:db8::/64",
		"remote-ts=192.0.2.0/24", "start-action=trap+start", "dpd-action=start", "policies=no", "reqid=100", "disabled")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", vpnIpsecConnPath+"add_child"), map[string]any{"child": map[string]any{
		"connection": vpnIpsecConnSite, "description": "dmz", "local_ts": "198.51.100.64/26,2001:db8::/64", "remote_ts": "192.0.2.0/24",
		"start_action": "trap|start", "dpd_action": "start", "policies": "0", "reqid": "100", "enabled": "0"}})

	r = f.run("/vpn/ipsec/child", "show", "lan")
	wantContains(t, "stdout", r.stdout, "start-action:   start\n", "local-ts:       198.51.100.0/24\n")

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		for _, args := range [][]string{
			{"connection=site b", "local-ts=nonsense"},
			{"connection=site b", "start-action=trap|start"},
			{"connection=site b", "replay-window=33"},
			{"connection=site b", "rekey-time="},
			{"connection=site b", "description=LAN"}, // exists in that connection
		} {
			wantExit(t, f.run(append([]string{"/vpn/ipsec/child", "add"}, args...)...), 1)
		}
		wantNoMutations(t, f)
	})
	t.Run("remove refused while a manual SPD entry uses it", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, true)
		wantFailure(t, f.run("/vpn/ipsec/child", "remove", "lan"), `"nat lan"`)
		wantNoMutations(t, f)
	})
	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecFake(t, false)
		f.on("POST", vpnIpsecConnPath+"del_child/"+vpnIpsecChildUuid, 200, answerDeleted)
		wantExit(t, f.run("/vpn/ipsec/child", "remove", "0"), 0)
		wantOneMutation(t, f, "POST", vpnIpsecConnPath+"del_child/"+vpnIpsecChildUuid)
	})
}
