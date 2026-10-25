package cli

import (
	"strings"
	"testing"
)

const (
	openvpnInstanceSearchPath  = "/api/openvpn/instances/search"
	openvpnInstanceGetPath     = "/api/openvpn/instances/get"
	openvpnInstanceAddPath     = "/api/openvpn/instances/add"
	openvpnInstanceSetPath     = "/api/openvpn/instances/set/"
	openvpnInstanceDelPath     = "/api/openvpn/instances/del/"
	openvpnInstanceTogglePath  = "/api/openvpn/instances/toggle/"
	openvpnInstanceServicePath = "/api/openvpn/service/"
)

// openvpnInstanceRow is a search row as OPNsense 26.7 returns it (a disabled server)
func openvpnInstanceRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "vpnid": "1", "enabled": "1", "dev_type": "tun", "%dev_type": "TUN", "verb": "3", "%verb": "3 (Normal)",
		"proto": "udp", "%proto": "UDP", "port": "1194", "port-share": "", "local": "", "topology": "subnet", "remote": "",
		"role": "server", "%role": "Server", "server": "10.8.0.0/24", "server_ipv6": "", "nopool": "0", "bridge_gateway": "",
		"bridge_pool": "", "route": "", "push_route": "192.168.1.0/24", "push_excluded_routes": "", "cert": "", "crl": "",
		"ca": "", "cert_depth": "", "remote_cert_tls": "0", "verify_client_cert": "require", "use_ocsp": "0", "auth": "",
		"data-ciphers": "", "data-ciphers-fallback": "", "tls_key": "", "authmode": "", "local_group": "", "various_flags": "",
		"various_push_flags": "", "push_inactive": "", "username_as_common_name": "0", "strictusercn": "0", "%strictusercn": "No",
		"username": "", "password": "", "maxclients": "", "keepalive_interval": "", "keepalive_timeout": "", "reneg-sec": "",
		"auth-gen-token": "", "auth-gen-token-renewal": "", "auth-gen-token-secret": "", "provision_exclusive": "0",
		"redirect_gateway": "", "route_metric": "", "register_dns": "0", "dns_domain": "", "dns_domain_search": "",
		"dns_servers": "", "ntp_servers": "", "tun_mtu": "", "fragment": "", "mssfix": "0", "carp_depend_on": "",
		"description": "", "compress_migrate": "0", "ifconfig-pool-persist": "0", "http-proxy": "", "verify-x509-name": "",
	}, overrides)
}

// openvpnInstanceRows: a server "office" using CA/cert/static key, a disabled client "home" with a password and
// the decoys "office 2" and a duplicate description "dup"
func openvpnInstanceRows() []map[string]any {
	return []map[string]any{
		openvpnInstanceRow(map[string]any{"uuid": "i-office", "description": "office", "ca": "ca0001", "cert": "crt001",
			"tls_key": "k-office", "authmode": "Local Database,Radius", "strictusercn": "2", "data-ciphers": "AES-256-GCM,CHACHA20-POLY1305",
			"auth-gen-token-secret": "c2VjcmV0"}),
		openvpnInstanceRow(map[string]any{"uuid": "i-home", "vpnid": "2", "enabled": "0", "role": "client", "%role": "Client",
			"server": "", "push_route": "", "remote": "vpn.example.com:1194", "username": "bob", "password": "hunter2", "description": "home"}),
		openvpnInstanceRow(map[string]any{"uuid": "i-office-2", "vpnid": "3", "description": "office 2"}),
		openvpnInstanceRow(map[string]any{"uuid": "i-d1", "vpnid": "4", "description": "dup"}),
		openvpnInstanceRow(map[string]any{"uuid": "i-d2", "vpnid": "5", "description": "dup"}),
	}
}

// openvpnInstanceGetAnswer is get without uuid (trimmed): the defaults of a new instance with the option lists
const openvpnInstanceGetAnswer = `{"instance":{"vpnid":"","enabled":"1",` +
	`"dev_type":{"tun":{"value":"TUN","selected":1},"tap":{"value":"TAP","selected":0},"ovpn":{"value":"DCO","selected":0}},` +
	`"verb":[{"value":"0","selected":0},{"value":"1","selected":0},{"value":"2","selected":0},{"value":"3 (Normal)","selected":1}],` +
	`"proto":{"udp":{"value":"UDP","selected":1},"tcp":{"value":"TCP","selected":0}},"port":"",` +
	`"role":{"client":{"value":"Client","selected":0},"server":{"value":"Server","selected":1}},"server":"",` +
	`"push_route":{"":{"value":"","selected":1}},` +
	`"cert":{"":{"value":"None","selected":1},"crt001":{"value":"office server","selected":0},"crt002":{"value":"twin","selected":0},"crt003":{"value":"twin","selected":0}},` +
	`"crl":{"":{"value":"None","selected":1}},` +
	`"ca":{"":{"value":" - Use from certificate","selected":1},"ca0001":{"value":"Office CA","selected":0}},` +
	`"verify_client_cert":{"none":{"value":"none","selected":0},"require":{"value":"require","selected":1}},` +
	`"tls_key":{"":{"value":"None","selected":1},"k-office":{"value":"office key [crypt (Encrypt and authenticate all control channel packets)]","selected":0}},` +
	`"authmode":{"Local Database":{"value":"Local Database","selected":0},"Radius":{"value":"Radius","selected":0}},` +
	`"local_group":{"":{"value":"None","selected":1},"1999":{"value":"admins","selected":0}},` +
	`"strictusercn":[{"value":"No","selected":1},{"value":"Yes","selected":0},{"value":"Yes (case insensitive)","selected":0}],` +
	`"password":"","description":"","carp_depend_on":{"":{"value":"None","selected":1}}}}`

// openvpnInstanceStaticKeyRows are the static keys for tls-key=
func openvpnInstanceStaticKeyRows() []map[string]any {
	return []map[string]any{
		{"uuid": "k-office", "description": "office key", "mode": "crypt", "%mode": "crypt (...)", "key": openvpnStaticKeyTestKey},
		{"uuid": "k-old", "description": "old key", "mode": "auth", "%mode": "auth (...)", "key": openvpnStaticKeyTestKey},
	}
}

func openvpnInstanceFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(openvpnInstanceSearchPath, rows...)
	f.search(openvpnStaticKeySearchPath, openvpnInstanceStaticKeyRows()...)
	f.on("GET", openvpnInstanceGetPath, 200, openvpnInstanceGetAnswer)
	f.search(openvpnClientOverrideSearchPath)
	return f
}

var openvpnInstanceHeader = []string{"#", "DISABLED", "VPNID", "ROLE", "PROTOCOL", "PORT", "DEV", "TUNNEL", "REMOTE", "DESCRIPTION"}

// openvpnWantFields parses "name: value" lines (aligned, optionally indented) and asserts the name / value pairs
func openvpnWantFields(t *testing.T, output string, pairs ...string) {
	t.Helper()
	var fields = map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if name, value, found := strings.Cut(strings.TrimSpace(line), ":"); found {
			if _, seen := fields[name]; !seen {
				fields[name] = strings.TrimSpace(value)
			}
		}
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		if got, found := fields[pairs[i]]; !found || got != pairs[i+1] {
			t.Errorf("field %s: got %q (present %v), want %q\n%s", pairs[i], got, found, pairs[i+1], output)
		}
	}
}

func TestOpenvpnInstancePrint(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	var r = f.run("/vpn/openvpn/instance", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, openvpnInstanceHeader, 9, "office", "home", "office 2", "dup", "dup")
	if len(rows) > 2 {
		if got := strings.Join(rows[1], "|"); got != "0|no|1|server|udp|1194|tun|10.8.0.0/24|-|office" {
			t.Errorf("row office: %q", got)
		}
		if got := strings.Join(rows[2], "|"); got != "1|yes|2|client|udp|1194|tun|-|vpn.example.com:1194|home" {
			t.Errorf("row home: %q", got)
		}
	}
	wantNotContains(t, "stdout", r.stdout, "hunter2", "c2VjcmV0")
	wantSearchPhrases(t, f, openvpnInstanceSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantExit(t, f.run("/vpn/openvpn/instance", "print", "search=offi ce"), 0)
		wantSearchPhrases(t, f, openvpnInstanceSearchPath, "offi ce")
	})
	t.Run("json masks the secrets", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		var r = f.run("/vpn/openvpn/instance", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 5 {
			t.Fatalf("want 5 lines:\n%s", r.stdout)
		}
		wantContains(t, "json", lines[1], `"uuid":"i-home"`, `"password":"********"`, `"username":"bob"`, `"%role":"Client"`)
		wantContains(t, "json", lines[0], `"auth-gen-token-secret":"********"`, `"password":""`)
		wantNotContains(t, "json", r.stdout, "hunter2", "c2VjcmV0")
	})
	t.Run("detail resolves references and masks secrets", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		var r = f.run("/vpn/openvpn/instance", "print", "detail")
		wantExit(t, r, 0)
		var blocks = strings.Split(r.stdout, "\n\n")
		if len(blocks) != 5 || !strings.HasPrefix(blocks[0], "0\n") || !strings.HasPrefix(blocks[1], "1\n") {
			t.Fatalf("want 5 numbered blocks:\n%s", r.stdout)
		}
		openvpnWantFields(t, blocks[0], "uuid", "i-office", "ca", "Office CA", "cert", "office server", "tls-key", "office key",
			"authentication", "Local Database,Radius", "strict-user-cn", "case-insensitive", "auth-gen-token-secret", "********",
			"data-ciphers", "AES-256-GCM,CHACHA20-POLY1305", "password", "")
		openvpnWantFields(t, blocks[1], "uuid", "i-home", "password", "********")
		wantNotContains(t, "stdout", r.stdout, "hunter2", "c2VjcmV0")
	})
}

func TestOpenvpnInstanceShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"i-home", "HOME", "1"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
			var r = f.run("/vpn/openvpn/instance", "show", selector)
			wantExit(t, r, 0)
			openvpnWantFields(t, r.stdout, "uuid", "i-home", "description", "home", "disabled", "yes", "role", "client", "vpn-id", "2",
				"remote", "vpn.example.com:1194", "username", "bob", "password", "********", "strict-user-cn", "no", "verbosity", "3",
				"protocol", "udp", "mssfix", "no", "tls-key", "")
			wantNotContains(t, "stdout", r.stdout, "hunter2")
			wantNoMutations(t, f)
		})
	}
	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "show", "dup"), "i-d1", "i-d2")
	})
	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "show", "offic"), "not found")
	})
}

func TestOpenvpnInstanceAdd(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	f.on("POST", openvpnInstanceAddPath, 200, answerAdded("i-new"))
	var r = f.run("/vpn/openvpn/instance", "add", "description=road warrior", "disabled", "protocol=UDP4", "port=1195",
		"tunnel-network=10.9.0.0/24", "ca=office ca", "cert=Office Server", "tls-key=office key", "authentication=local database,Radius",
		"local-group=admins", "data-ciphers=aes-256-gcm,chacha20-poly1305", "local-networks=192.168.1.0/24,10.0.0.0/8",
		"dns-servers=10.0.0.53", "strict-user-cn=yes", "verify-client-cert=require", "keepalive-interval=10", "keepalive-timeout=60",
		"redirect-gateway=def1,bypass-dhcp", "password=s3cret", "mssfix", "verbosity=4", "cert-depth=1")
	wantExit(t, r, 0)
	if r.stdout != "i-new\n" {
		t.Errorf("stdout %q, want the uuid", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", openvpnInstanceAddPath), map[string]any{"instance": map[string]any{
		"vpnid": "", "description": "road warrior", "enabled": "0", "proto": "udp4", "port": "1195", "server": "10.9.0.0/24",
		"ca": "ca0001", "cert": "crt001", "tls_key": "k-office", "authmode": "Local Database,Radius", "local_group": "1999",
		"data-ciphers": "AES-256-GCM,CHACHA20-POLY1305", "push_route": "192.168.1.0/24,10.0.0.0/8", "dns_servers": "10.0.0.53",
		"strictusercn": "1", "verify_client_cert": "require", "keepalive_interval": "10", "keepalive_timeout": "60",
		"redirect_gateway": "def1,bypass-dhcp", "password": "s3cret", "mssfix": "1", "verb": "4", "cert_depth": "1",
	}})

	t.Run("references by key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		f.on("POST", openvpnInstanceAddPath, 200, answerAdded("i-new"))
		wantExit(t, f.run("/vpn/openvpn/instance", "add", "description=x", "ca=ca0001", "tls-key=k-old", "cert="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnInstanceAddPath), map[string]any{"instance": map[string]any{
			"vpnid": "", "description": "x", "ca": "ca0001", "tls_key": "k-old", "cert": ""}})
	})
	t.Run("validation messages of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		f.on("POST", openvpnInstanceAddPath, 200, answerValidation("instance.server", "At least one IPv4 or IPv6 tunnel network is required."))
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=x"), "tunnel-network: At least one", "tunnel network is required")
	})
	t.Run("existing description", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=OFFICE", "port=1"), "exists already", "i-office", "replace")
		wantNoMutations(t, f)
	})
	t.Run("duplicates are not replaced", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=dup", "replace"), "i-d1", "i-d2")
		wantNoMutations(t, f)
	})
	t.Run("replace resets to the defaults and keeps the vpnid", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.on("POST", openvpnInstanceSetPath+"i-office", 200, answerSaved)
		var r = f.run("/vpn/openvpn/instance", "add", "description=office", "tunnel-network=10.7.0.0/24", "disabled", "replace")
		wantExit(t, r, 0)
		if r.stdout != "i-office\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced")
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnInstanceSetPath+"i-office"), map[string]any{"instance": map[string]any{
			"enabled": "0", "dev_type": "tun", "verb": "3", "proto": "udp", "port": "", "role": "server", "server": "10.7.0.0/24",
			"push_route": "", "cert": "", "crl": "", "ca": "", "verify_client_cert": "require", "tls_key": "", "authmode": "",
			"local_group": "", "strictusercn": "0", "password": "", "description": "office", "carp_depend_on": "",
		}})
	})
	t.Run("unknown reference", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=x", "ca=nope"), "ca \"nope\"", "\"Office CA\"")
		wantNoMutations(t, f)
	})
	t.Run("ambiguous reference", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=x", "cert=twin"), "crt002", "crt003")
		wantNoMutations(t, f)
	})
	t.Run("unknown static key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		wantFailure(t, f.run("/vpn/openvpn/instance", "add", "description=x", "tls-key=nope"), "tls-key \"nope\"")
		wantNoMutations(t, f)
	})
	for name, args := range map[string][]string{
		"description required":     {"port=1"},
		"empty description":        {"description="},
		"tunnel network":           {"description=x", "tunnel-network=10.0.0.1"},
		"ipv6 tunnel network":      {"description=x", "tunnel-network6=10.0.0.0/24"},
		"port":                     {"description=x", "port=70000"},
		"role":                     {"description=x", "role=peer"},
		"protocol":                 {"description=x", "protocol=sctp"},
		"cipher":                   {"description=x", "data-ciphers=AES-256-GCM,ROT13"},
		"verbosity":                {"description=x", "verbosity=12"},
		"keepalive pair":           {"description=x", "keepalive-interval=10", "keepalive-timeout=15"},
		"keepalive cleared alone":  {"description=x", "keepalive-interval=", "keepalive-timeout=15"},
		"newline in description":   {"description=a\nb"},
		"route":                    {"description=x", "local-networks=10.0.0.0"},
		"dns server":               {"description=x", "dns-servers=dns.example.com"},
		"empty vpn-id":             {"description=x", "vpn-id="},
		"empty role":               {"description=x", "role="},
		"auth token secret":        {"description=x", "auth-gen-token-secret=a!b"},
		"strict user cn":           {"description=x", "strict-user-cn=maybe"},
		"max clients":              {"description=x", "max-clients=0"},
		"tun mtu":                  {"description=x", "tun-mtu=10"},
		"redirect gateway options": {"description=x", "redirect-gateway=everything"},
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()
			var f = openvpnInstanceFake(t)
			wantFailure(t, f.run(append([]string{"/vpn/openvpn/instance", "add"}, args...)...))
			wantNoCalls(t, f)
		})
	}
}

func TestOpenvpnInstanceSet(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	f.on("POST", openvpnInstanceSetPath+"i-home", 200, answerSaved)
	wantExit(t, f.run("/vpn/openvpn/instance", "set", "home", "remote=a.example.com:1194,b.example.com", "password=", "tls-key=",
		"description=house", "disabled=no", "route-metric=10"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", openvpnInstanceSetPath+"i-home"), map[string]any{"instance": map[string]any{
		"remote": "a.example.com:1194,b.example.com", "password": "", "tls_key": "", "description": "house", "enabled": "1", "route_metric": "10",
	}})
	if calls := f.calls(); len(calls) > 0 {
		for _, call := range calls {
			if call.Path == openvpnInstanceGetPath {
				t.Errorf("set without references must not load the options: %v", call)
			}
		}
	}

	t.Run("the # of a filtered print in a script", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.on("POST", openvpnInstanceSetPath+"i-office-2", 200, answerSaved)
		wantExit(t, f.runScript("/vpn/openvpn/instance\nprint search=office\nset 1 port=1196\n"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnInstanceSetPath+"i-office-2"), map[string]any{"instance": map[string]any{"port": "1196"}})
	})
	t.Run("nothing to change", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "set", "home"), "nothing to change")
		wantNoCalls(t, f)
	})
	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "set", "nope", "port=1"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("rename onto another instance", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "set", "home", "description=Office"), "i-office")
		wantNoMutations(t, f)
	})
	t.Run("validation messages of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.on("POST", openvpnInstanceSetPath+"i-office", 200,
			answerValidation("instance.server", "Server directive must define a subnet of /29 or lower unless topology equals p2p."))
		// the field is named by its argument
		wantFailure(t, f.run("/vpn/openvpn/instance", "set", "office", "tunnel-network=10.8.0.0/30"), "tunnel-network: Server directive", "/29")
	})
}

func TestOpenvpnInstanceRemove(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	f.on("POST", openvpnInstanceDelPath+"i-office-2", 200, answerDeleted)
	var r = f.run("/vpn/openvpn/instance", "remove", "office 2")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", openvpnInstanceDelPath+"i-office-2")

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		wantFailure(t, f.run("/vpn/openvpn/instance", "remove", "9"), "not found")
		wantNoMutations(t, f)
	})
	t.Run("refused while client specific overrides use it", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.search(openvpnClientOverrideSearchPath,
			openvpnClientOverrideRow(map[string]any{"uuid": "o-bob", "common_name": "bob", "servers": "i-office,I-OFFICE-2"}),
			openvpnClientOverrideRow(map[string]any{"uuid": "o-carol", "common_name": "carol", "servers": "i-office"}),
			openvpnClientOverrideRow(map[string]any{"uuid": "o-all", "common_name": "dave"}))
		wantFailure(t, f.run("/vpn/openvpn/instance", "remove", "office 2"), "client specific overrides bob (o-bob)", "servers=")
		wantNotContains(t, "output", f.run("/vpn/openvpn/instance", "remove", "office 2").stderr, "carol", "dave")
		wantNoMutations(t, f)
	})
}

func TestOpenvpnInstanceEnableDisable(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	f.on("POST", openvpnInstanceTogglePath+"i-home/1", 200, `{"result":"Enabled","changed":true}`)
	var r = f.run("/vpn/openvpn/instance", "enable", "home")
	wantExit(t, r, 0)
	if r.stdout != "" || r.stderr != "" {
		t.Errorf("enable must be silent:\n%s", r)
	}
	wantOneMutation(t, f, "POST", openvpnInstanceTogglePath+"i-home/1")

	t.Run("already disabled", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.on("POST", openvpnInstanceTogglePath+"i-home/0", 200, `{"result":"Disabled","changed":false}`)
		var r = f.run("/vpn/openvpn/instance", "disable", "home")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "already disabled")
		wantOneMutation(t, f, "POST", openvpnInstanceTogglePath+"i-home/0")
	})
}

func TestOpenvpnInstanceService(t *testing.T) {
	t.Parallel()
	for _, action := range []string{"start", "stop", "restart"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
			f.on("POST", openvpnInstanceServicePath+action+"_service/i-office", 200, `{"result":"ok"}`)
			var args = []string{"/vpn/openvpn/instance", action, "office"}
			if action != "start" {
				args = append(args, "confirm=yes")
			}
			var r = f.run(args...)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("%s must be silent: %q", action, r.stdout)
			}
			var call = wantOneMutation(t, f, "POST", openvpnInstanceServicePath+action+"_service/i-office")
			if call.Body != "" {
				t.Errorf("want no body, got %q", call.Body)
			}
		})
		t.Run(action+" refuses disabled instances", func(t *testing.T) {
			t.Parallel()
			var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
			var args = []string{"/vpn/openvpn/instance", action, "home"}
			if action != "start" {
				args = append(args, "confirm=yes")
			}
			wantFailure(t, f.run(args...), "disabled")
			wantNoMutations(t, f)
		})
	}
	for _, action := range []string{"stop", "restart"} {
		t.Run(action+" needs confirmation", func(t *testing.T) {
			t.Parallel()
			var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
			wantExit(t, f.run("/vpn/openvpn/instance", action, "office"), 1)
			wantNoMutations(t, f)
		})
	}
	t.Run("the service answers failed", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
		f.on("POST", openvpnInstanceServicePath+"start_service/i-office", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/vpn/openvpn/instance", "start", "office"), "failed")
	})
}

func TestOpenvpnInstanceApply(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t)
	f.on("POST", openvpnInstanceServicePath+"reconfigure", 200, `{"result":"ok"}`)
	var r = f.run("/vpn/openvpn/instance", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", openvpnInstanceServicePath+"reconfigure")

	t.Run("empty answer", func(t *testing.T) {
		t.Parallel()
		var f = openvpnInstanceFake(t)
		wantFailure(t, f.run("/vpn/openvpn/instance", "apply"), "empty response")
	})
}

func TestOpenvpnInstanceComplete(t *testing.T) {
	t.Parallel()
	var f = openvpnInstanceFake(t, openvpnInstanceRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string]string{
		"/vpn/openvpn/instance show ho":                       "home",
		"/vpn/openvpn/instance set office ca=Off":             "Office CA",
		"/vpn/openvpn/instance set office tls-key=off":        "office key",
		"/vpn/openvpn/instance set office local-group=adm":    "admins",
		"/vpn/openvpn/instance set office authentication=Rad": "Radius",
	} {
		var candidates, _ = session.Complete(line)
		var found bool
		for _, candidate := range candidates {
			if strings.Contains(candidate, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: candidates %q lack %q", line, candidates, want)
		}
	}
}
