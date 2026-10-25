package cli

import (
	"strings"
	"testing"
)

const vpnIpsecSettingsTestForm = `{"ipsec":{"general":{"enabled":"","preferred_oldsa":"0","disablevpnrules":"0",` +
	`"passthrough_networks":{"":{"value":"","selected":1}},"user_source":{"Local Database":{"value":"Local Database","selected":0}},` +
	`"local_group":{"":{"value":"none","selected":1},"1999":{"value":"admins","selected":0}}},` +
	`"charon":{"max_ikev1_exchanges":"","threads":"16","ikesa_table_size":"32","ikesa_table_segments":"4","init_limit_half_open":"1000",` +
	`"ignore_acquire_ts":"1","install_routes":"0","cisco_unity":"0","make_before_break":"0","retransmit_tries":"","retransmit_timeout":"",` +
	`"retransmit_base":"","retransmit_jitter":"","retransmit_limit":"","reqid_base":"",` +
	`"syslog":{"daemon":{"ike_name":"1","log_level":"0","ike":{"-1":{"value":"Absolutely silent","selected":0},"1":{"value":"default","selected":1},"2":{"value":"debug","selected":0}}}},` +
	`"plugins":{"attr":{"dns":{"":{"value":"","selected":1}},"x_28679":{"":{"value":"","selected":1},"14":{"value":"14 (2048 bits)","selected":0}}},` +
	`"eap-radius":{"servers":[],"accounting":"0","class_group":"0"},"xauth-pam":{"pam_service":"ipsec","session":"0","trim_email":"1"}}}}}`

func TestVpnIpsecSettings(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/ipsec/settings/get", 200, vpnIpsecSettingsTestForm)
	var r = f.run("/vpn/ipsec/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "threads:               16\n", "log-ike:               control\n", "local-group:           \n",
		"unity-pfs-group:       none\n", "pam-service:           ipsec\n")
	// fields this OPNsense does not have are not shown, the global switch is not a setting
	wantNotContains(t, "stdout", r.stdout, "retry-initiate-interval", "log-app", "enabled")

	r = f.run("/vpn/ipsec/settings", "print", "options=local-group")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "1999  admins  no\n")
	r = f.run("/vpn/ipsec/settings", "print", "json")
	wantContains(t, "stdout", r.stdout, `"charon.threads":"16"`)

	f.on("POST", "/api/ipsec/settings/set", 200, answerSaved)
	wantExit(t, f.run("/vpn/ipsec/settings", "set", "threads=32", "log-ike=debug", "local-group=admins", "mobile-dns=192.0.2.53",
		"unity-pfs-group=14", "prefer-old-sa"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/settings/set"), map[string]any{"ipsec": map[string]any{
		"general": map[string]any{"local_group": "1999", "preferred_oldsa": "1"},
		"charon": map[string]any{"threads": "32", "syslog": map[string]any{"daemon": map[string]any{"ike": "2"}},
			"plugins": map[string]any{"attr": map[string]any{"dns": "192.0.2.53", "x_28679": "14"}}}}})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", "/api/ipsec/settings/get", 200, vpnIpsecSettingsTestForm)
		for _, args := range [][]string{{}, {"threads=0"}, {"log-ike=loud"}, {"local-group=nobody"}, {"mobile-dns=x"}, {"enabled=yes"}, {"retransmit-timeout=1.2.3"}} {
			wantExit(t, f.run(append([]string{"/vpn/ipsec/settings", "set"}, args...)...), 1)
		}
		wantNoMutations(t, f)
		f.on("POST", "/api/ipsec/settings/set", 200, `{"result":"failed","validations":{"ipsec.charon.threads":"Invalid integer value."}}`)
		wantFailure(t, f.run("/vpn/ipsec/settings", "set", "threads=5"), "threads: Invalid integer value.")
	})
}

func TestVpnIpsecService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/ipsec/service/status", 200, `{"status":"running","widget":{}}`)
	f.on("GET", "/api/ipsec/legacy_subsystem/status", 200, `{"enabled":true,"isDirty":true}`)
	var r = f.run("/vpn/ipsec/service", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "enabled:          yes\n", "status:           running\n", "pending-changes:  yes\n")
	wantContains(t, "stderr", r.stderr, "service apply")

	t.Run("stop and restart need confirmation", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		for _, action := range []string{"stop", "restart"} {
			wantFailure(t, f.run("/vpn/ipsec/service", action), "confirm=yes")
		}
		wantNoCalls(t, f)
		f.on("POST", "/api/ipsec/service/stop", 200, `{"response":"OK"}`)
		wantExit(t, f.run("/vpn/ipsec/service", "stop", "confirm=yes"), 0)
		wantOneMutation(t, f, "POST", "/api/ipsec/service/stop")
	})
	t.Run("actions", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", "/api/ipsec/service/reconfigure", 200, `{"status":"ok"}`)
		f.on("POST", "/api/ipsec/service/start", 200, `{"response":"OK"}`)
		f.on("POST", "/api/ipsec/legacy_subsystem/apply_config", 200, `{"status":"ok","message":"applied"}`)
		for _, action := range []string{"reconfigure", "start", "apply"} {
			wantExit(t, f.run("/vpn/ipsec/service", action), 0)
		}
		if calls := f.mutations(); len(calls) != 3 {
			t.Errorf("want 3 POSTs, got %v", calls)
		}
		f.on("POST", "/api/ipsec/service/reconfigure", 200, `{"status":"failed","status_msg":"Service \"ipsec\" failed to start."}`)
		wantFailure(t, f.run("/vpn/ipsec/service", "reconfigure"), "failed to start")
	})
	t.Run("enable and disable", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", "/api/ipsec/connections/is_enabled", 200, `{"enabled":false}`)
		f.on("POST", "/api/ipsec/connections/toggle/1", 200, `{"status":"ok"}`)
		var r = f.run("/vpn/ipsec/service", "enable")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "reconfigure")
		wantOneMutation(t, f, "POST", "/api/ipsec/connections/toggle/1")
		r = f.run("/vpn/ipsec/service", "disable")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "already disabled")
		if calls := f.mutations(); len(calls) != 1 {
			t.Errorf("disable of a disabled IPsec must not post: %v", calls)
		}
	})
}

func TestVpnIpsecStatus(t *testing.T) {
	t.Parallel()
	const sadId = "0123456789abcdef0123456789abcdef"
	var newStatusFake = func(t *testing.T) *fakeOPN {
		var f = newFakeOPN(t)
		f.on("GET", "/api/ipsec/service/status", 200, `{"status":"running"}`)
		f.on("GET", "/api/ipsec/sessions/search_phase1", 200, `{"rows":[`+
			`{"name":"`+vpnIpsecConnSite+`","phase1desc":"site b","connected":true,"routed":true,"version":"IKEv2","local-addrs":"198.51.100.1",`+
			`"remote-addrs":"192.0.2.1","local-id":"fw.example.com","remote-id":"192.0.2.1","bytes-in":1200,"bytes-out":3400,"install-time":12},`+
			`{"name":"con2","phase1desc":"legacy","connected":false,"routed":true,"version":"IKEv1","local-addrs":"","remote-addrs":"","bytes-in":0,"bytes-out":0}],"total":2}`)
		f.on("POST", "/api/ipsec/sessions/search_phase2", 200, `{"rows":[{"name":"`+vpnIpsecChildUuid+`","phase2desc":"lan","state":"INSTALLED","mode":"TUNNEL",`+
			`"protocol":"ESP","local-ts":"198.51.100.0/24","remote-ts":"192.0.2.0/24","spi-in":"c1f0aa01","spi-out":"c2f0aa02","encr-alg":"AES_GCM_16",`+
			`"encr-keysize":256,"bytes-in":1000,"bytes-out":2000}]}`)
		f.on("GET", "/api/ipsec/sad/search", 200, `{"rows":[{"src":"No","dst":"SAD","satype":null,"spi":null,"nat":"ntries","id":"910a25ff497965ab5bed6120daa20baa"},`+
			`{"src":"192.0.2.1","dst":"198.51.100.1","satype":"esp","spi":"c1f0aa01","mode":"tunnel","reqid":5,"alg_enc":"aes-gcm-16","id":"`+sadId+`","phase1desc":"site b","phase2desc":"lan"}]}`)
		f.on("GET", "/api/ipsec/spd/search", 200, `{"rows":[{"src":"198.51.100.0/24","dst":"192.0.2.0/24","src_port":"any","upperspec":"any","dir":"out",`+
			`"type":"ipsec","proto":"esp","mode":"tunnel","src-dst":["198.51.100.1","192.0.2.1"],"level":"unique","reqid":"5","id":"`+sadId+`"}]}`)
		f.on("GET", "/api/ipsec/leases/search", 200, `{"rows":[{"pool":"mobile","address":"198.51.100.130","online":true,"user":"alice"},`+
			`{"pool":"other","address":"198.51.100.200","online":false,"user":"bob"}]}`)
		f.on("GET", "/api/ipsec/leases/pools", 200, `{"pools":{"mobile":{"name":"mobile","net":"198.51.100.128","online":1,"offline":0,"size":126}}}`)
		return f
	}
	var f = newStatusFake(t)
	var r = f.run("/vpn/ipsec/session", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  yes        site b   IKEv2    198.51.100.1  192.0.2.1  fw.example.com  192.0.2.1  1200      3400\n", "1  no         legacy")
	r = f.run("/vpn/ipsec/session", "phase2", "site b")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "lan    INSTALLED  TUNNEL  ESP", "AES_GCM_16-256")
	r = f.run("/vpn/ipsec/sad", "print")
	wantExit(t, r, 0)
	if strings.Contains(r.stdout, "SAD") && strings.Count(r.stdout, "\n") != 2 {
		t.Errorf("the \"No SAD entries\" row must be dropped:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "0  192.0.2.1  198.51.100.1  esp       c1f0aa01  tunnel  5      aes-gcm-16")
	r = f.run("/vpn/ipsec/spd", "print")
	wantContains(t, "stdout", r.stdout, "0  out  198.51.100.0/24  192.0.2.0/24  any        ipsec  esp       tunnel  198.51.100.1 - 192.0.2.1  5")
	r = f.run("/vpn/ipsec/lease", "print", "online")
	wantContains(t, "stdout", r.stdout, "mobile  198.51.100.130  yes     alice")
	wantNotContains(t, "stdout", r.stdout, "bob")
	r = f.run("/vpn/ipsec/lease", "pools")
	wantContains(t, "stdout", r.stdout, "mobile  198.51.100.128  1       0        126")
	// phase 2 is read with a POST, nothing else is posted
	wantOneMutation(t, f, "POST", "/api/ipsec/sessions/search_phase2")

	t.Run("connect, disconnect and remove need confirmation", func(t *testing.T) {
		t.Parallel()
		var f = newStatusFake(t)
		for _, args := range [][]string{{"/vpn/ipsec/session", "connect", "0"}, {"/vpn/ipsec/session", "disconnect", "0"},
			{"/vpn/ipsec/sad", "remove", "0"}, {"/vpn/ipsec/spd", "remove", sadId}} {
			wantFailure(t, f.run(args...), "confirm=yes")
		}
		wantNoCalls(t, f)
		f.on("POST", "/api/ipsec/sessions/connect/con2", 200, `{"result":"ok"}`)
		f.on("POST", "/api/ipsec/sessions/disconnect/"+vpnIpsecConnSite, 200, `{"result":"ok"}`)
		f.on("POST", "/api/ipsec/sad/delete/"+sadId, 200, `{"status":"found","items":[],"result":"ok"}`)
		f.on("POST", "/api/ipsec/spd/delete/"+sadId, 200, `{"status":"not_found","items":[],"result":"ok"}`)
		wantExit(t, f.run("/vpn/ipsec/session", "connect", "legacy", "confirm=yes"), 0)
		wantExit(t, f.run("/vpn/ipsec/session", "disconnect", vpnIpsecConnSite, "confirm=yes"), 0)
		var r = f.run("/vpn/ipsec/session", "disconnect", "con2", "confirm=yes") // not connected
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "not connected")
		wantExit(t, f.run("/vpn/ipsec/sad", "remove", "0", "confirm=yes"), 0)
		wantFailure(t, f.run("/vpn/ipsec/spd", "remove", sadId, "confirm=yes"), "not found")
		if calls := f.mutations(); len(calls) != 4 {
			t.Errorf("want 4 POSTs, got %v", calls)
		}
	})
}
