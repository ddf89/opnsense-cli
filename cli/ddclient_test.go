package cli

import (
	"strings"
	"testing"
)

const (
	ddclientSearchPath  = "/api/dyndns/accounts/search_item"
	ddclientAccountUuid = "17a38f84-c8e2-4d2e-8b23-1798774db7ea"
	ddclientOtherUuid   = "27a38f84-c8e2-4d2e-8b23-1798774db7eb"
	ddclientSecret      = "pa55-n0t-sh0wn"
	ddclientOptions     = `{"account":{"enabled":"1","service":{"dyndns2":{"value":"dyndns2","selected":0},` +
		`"cloudflare":{"value":"Cloudflare","selected":0}},"protocol":{"":{"value":"None","selected":1},"get":{"value":"Custom GET","selected":0}},` +
		`"checkip":{"web_icanhazip":{"value":"icanhazip","selected":0},"if":{"value":"Interface [IPv4]","selected":0}},` +
		`"interface":{"":{"value":"None","selected":1},"wan":{"value":"WAN","selected":0}},"password":""}}`
)

func ddclientRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": ddclientAccountUuid, "enabled": "0", "service": "dyndns2", "server": "", "username": "me", "password": ddclientSecret,
		"%password": "", "resourceId": "", "hostnames": "home.example.com,www.example.com", "wildcard": "0", "zone": "",
		"checkip": "web_icanhazip", "%checkip": "icanhazip", "dynipv6host": "", "checkip_timeout": "10", "force_ssl": "1",
		"ttl": "300", "interface": "", "description": "home", "current_ip": "192.0.2.7", "current_mtime": "2026-10-26T10:00:00+00:00",
	}, overrides)
}

func ddclientFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(ddclientSearchPath, ddclientRow(nil), ddclientRow(map[string]any{"uuid": ddclientOtherUuid, "enabled": "1",
		"description": "office", "service": "cloudflare", "password": "", "current_ip": "", "current_mtime": "", "checkip": "if",
		"interface": "wan", "%interface": "WAN"}))
	f.on("GET", "/api/dyndns/accounts/get_item", 200, ddclientOptions)
	f.on("GET", "/api/dyndns/accounts/get_item/"+ddclientAccountUuid, 200, `{"account":{"protocol":{"":{"value":"None","selected":0},`+
		`"get":{"value":"Custom GET","selected":1}},"password":""}}`)
	f.on("GET", "/api/dyndns/accounts/get_item/"+ddclientOtherUuid, 200, `{"account":{"protocol":{"":{"value":"None","selected":1}}}}`)
	return f
}

func TestDdclientAccountPrint(t *testing.T) {
	t.Parallel()
	var f = ddclientFake(t)
	var r = f.run("/ddclient/account", "print")
	wantExit(t, r, 0)
	wantContains(t, "print", r.stdout, "DISABLED", "CURRENT-IP", "UPDATED", "home.example.com, www.example.com", "192.0.2.7",
		"2026-10-26T10:00:00+00:00", "office")
	var show = f.run("/ddclient/account", "show", "HOME")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "password:", "(set)", "protocol:", "get", "current-ip:", "check-ip:", "icanhazip")
	var detail = f.run("/ddclient/account", "print", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "detail", detail.stdout, "(set)", "(none)", "updated:")
	var json = f.run("/ddclient/account", "print", "json")
	wantExit(t, json, 0)
	if lines := strings.Split(strings.TrimSpace(json.stdout), "\n"); len(lines) != 2 || !strings.Contains(lines[0], `"current_ip":"192.0.2.7"`) {
		t.Errorf("json %q", json.stdout)
	}
	for _, out := range []string{r.stdout, show.stdout, detail.stdout, json.stdout} {
		wantNotContains(t, "output", out, ddclientSecret, `"password"`)
	}
	var options = f.run("/ddclient/account", "print", "options=check-ip")
	wantExit(t, options, 0)
	wantContains(t, "options", options.stdout, "web_icanhazip", "Interface [IPv4]")
	wantNoMutations(t, f)
}

func TestDdclientAccountAdd(t *testing.T) {
	t.Parallel()
	var f = ddclientFake(t)
	f.on("POST", "/api/dyndns/accounts/add_item", 200, answerAdded("new-uuid"))
	f.on("POST", "/api/dyndns/accounts/set_item/"+ddclientAccountUuid, 200, answerSaved)
	var r = f.run("/ddclient/account", "add", "description=lab", "service=DynDNS2", "username=me", "password=s3cret",
		"hostnames=lab.example.com, lab2.example.org", "check-ip=web_icanhazip", "disabled", "ttl=60")
	wantExit(t, r, 0)
	wantContains(t, "add", r.stdout, "new-uuid")
	wantJSON(t, f.mutations()[0], map[string]any{"account": map[string]any{"description": "lab", "enabled": "0", "service": "dyndns2",
		"username": "me", "password": "s3cret", "hostnames": "lab.example.com,lab2.example.org", "checkip": "web_icanhazip", "ttl": "60"}})

	wantFailure(t, f.run("/ddclient/account", "add", "description=Home", "service=dyndns2", "hostnames=h.example.com", "check-ip=if",
		"interface=wan"), "exists already", ddclientAccountUuid)
	wantExit(t, f.run("/ddclient/account", "add", "description=home", "service=cloudflare", "hostnames=h.example.com", "check-ip=if",
		"interface=wan", "zone=example.com", "replace"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"account": map[string]any{"description": "home", "enabled": "1", "service": "cloudflare",
		"protocol": "", "server": "", "username": "", "resourceId": "", "wildcard": "0", "zone": "example.com", "hostnames": "h.example.com",
		"checkip": "if", "interface": "wan", "dynipv6host": "", "checkip_timeout": "10", "force_ssl": "1", "ttl": "300"}})
	if got := len(f.mutations()); got != 2 {
		t.Errorf("mutations %v", f.mutations())
	}

	var refused = ddclientFake(t)
	var required = []string{"description=x", "service=dyndns2", "hostnames=x.example.com", "check-ip=web_icanhazip"}
	for _, args := range [][]string{
		{"description=x", "service=dyndns2", "hostnames=x.example.com"},
		append([]string{"service=nosuch"}, required[0], required[2], required[3]),
		append([]string{"check-ip=web_dyndns"}, required[:3]...),
		append([]string{"interface=opt9"}, required...),
		append([]string{"password="}, required...),
		append([]string{"username=bad user"}, required...),
		append([]string{"ttl=0"}, required...),
		append([]string{"check-ip-timeout=5"}, required...),
		append([]string{"dynamic-ipv6-host=1000"}, required...),
		append([]string{"protocol=ftp"}, required...),
		{"description=", "service=dyndns2", "hostnames=x.example.com", "check-ip=web_icanhazip"},
		{"description=x", "service=dyndns2", "hostnames=bad host.example.com", "check-ip=web_icanhazip"},
	} {
		wantFailure(t, refused.run(append([]string{"/ddclient/account", "add"}, args...)...))
	}
	wantFailure(t, refused.run("/ddclient/account", "add", "description=x", "service=nosuch", "hostnames=x.example.com", "check-ip=web_icanhazip"),
		`service: unknown value "nosuch"`, "options=service")
	wantFailure(t, refused.run("/ddclient/account", "add", "description=x", "service=dyndns2", "hostnames=x.example.com", "check-ip=if6"),
		"needs an interface")
	wantNoMutations(t, refused)
}

func TestDdclientAccountChange(t *testing.T) {
	t.Parallel()
	var f = ddclientFake(t)
	f.on("POST", "/api/dyndns/accounts/set_item/"+ddclientAccountUuid, 200, answerSaved)
	f.on("POST", "/api/dyndns/accounts/set_item/"+ddclientOtherUuid, 200, answerSaved)
	f.on("POST", "/api/dyndns/accounts/del_item/"+ddclientOtherUuid, 200, answerDeleted)
	wantExit(t, f.run("/ddclient/account", "set", "home", "hostnames=new.example.com", "server=", "password=n3w", "force-ssl=no"), 0)
	wantJSON(t, f.mutations()[0], map[string]any{"account": map[string]any{"hostnames": "new.example.com", "server": "",
		"password": "n3w", "force_ssl": "0"}})
	wantExit(t, f.run("/ddclient/account", "enable", "home"), 0)
	wantJSON(t, f.mutations()[1], map[string]any{"account": map[string]any{"enabled": "1"}})
	wantExit(t, f.run("/ddclient/account", "disable", ddclientOtherUuid), 0)
	wantJSON(t, f.mutations()[2], map[string]any{"account": map[string]any{"enabled": "0"}})
	wantExit(t, f.run("/ddclient/account", "remove", "1"), 0)
	if got := f.mutations(); len(got) != 4 || got[3].Path != "/api/dyndns/accounts/del_item/"+ddclientOtherUuid {
		t.Errorf("mutations %v", got)
	}

	var refused = ddclientFake(t)
	wantFailure(t, refused.run("/ddclient/account", "set", "home", "description=OFFICE"), "another account", ddclientOtherUuid)
	wantFailure(t, refused.run("/ddclient/account", "set", "home"), "nothing to change")
	wantFailure(t, refused.run("/ddclient/account", "set", "nosuch", "ttl=60"), "not found")
	wantFailure(t, refused.run("/ddclient/account", "set", "home", "check-ip=nope"), "unknown value")
	wantFailure(t, refused.run("/ddclient/account", "set", "home", "password="), "can not be cleared")
	wantFailure(t, refused.run("/ddclient/account", "set", "home", "check-ip=if"), "check-ip=if needs an interface")
	wantFailure(t, refused.run("/ddclient/account", "set", "office", "interface="), "check-ip=if needs an interface")
	wantNoMutations(t, refused)
}

func TestDdclientAccountRefresh(t *testing.T) {
	t.Parallel()
	var f = ddclientFake(t)
	f.on("POST", "/api/dyndns/accounts/force_refresh/"+ddclientOtherUuid, 200, `{"status":"ok"}`)
	wantFailure(t, f.run("/ddclient/account", "refresh", "office"), "confirm=yes")
	wantNoCalls(t, f)
	wantExit(t, f.run("/ddclient/account", "refresh", "office", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", "/api/dyndns/accounts/force_refresh/"+ddclientOtherUuid)

	var native = ddclientFake(t)
	native.on("POST", "/api/dyndns/accounts/force_refresh/"+ddclientAccountUuid, 500,
		`{"errorMessage":"Force refresh requires the native backend to be enabled.","errorTitle":"Error"}`)
	var r = native.run("/ddclient/account", "refresh", "home", "confirm=yes")
	wantFailure(t, r, "requires the native backend")
	wantContains(t, "stderr", r.stderr, "is disabled")
}

func TestDdclientSettings(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/dyndns/settings/get", 200, `{"ddclient":{"general":{"enabled":"1","verbose":"0","allowipv6":"0",`+
		`"daemon_delay":"300","backend":{"ddclient":{"value":"ddclient","selected":0},"opnsense":{"value":"native","selected":1}}}}}`)
	f.on("POST", "/api/dyndns/settings/set", 200, answerSaved)
	var r = f.run("/ddclient/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "print", r.stdout, "enabled:", "yes", "interval:", "300", "backend:", "native")
	var json = f.run("/ddclient/settings", "print", "json")
	wantExit(t, json, 0)
	wantContains(t, "json", json.stdout, `"backend":"opnsense"`, `"daemon_delay":"300"`)
	wantExit(t, f.run("/ddclient/settings", "print", "options=backend"), 0)
	wantExit(t, f.run("/ddclient/settings", "set", "interval=600", "backend=native", "verbose", "enabled=no"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/dyndns/settings/set"), map[string]any{"ddclient": map[string]any{"general": map[string]any{
		"daemon_delay": "600", "backend": "opnsense", "verbose": "1", "enabled": "0"}}})

	var refused = newFakeOPN(t)
	for _, args := range [][]string{{"interval=0"}, {"interval="}, {"backend=other"}, {}} {
		wantFailure(t, refused.run(append([]string{"/ddclient/settings", "set"}, args...)...))
	}
	wantNoCalls(t, refused)
}

func TestDdclientService(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/dyndns/service/status", 200, `{"status":"running","widget":{}}`)
	for _, action := range []string{"start", "stop", "restart"} {
		f.on("POST", "/api/dyndns/service/"+action, 200, `{"response":"OK"}`)
	}
	f.on("POST", "/api/dyndns/service/reconfigure", 200, `{"status":"ok"}`)
	var r = f.run("/ddclient/service", "status")
	wantExit(t, r, 0)
	wantContains(t, "status", r.stdout, "status:", "running")
	for _, action := range []string{"start", "stop", "restart", "reconfigure"} {
		wantExit(t, f.run("/ddclient/service", action), 0)
	}
	if got := len(f.mutations()); got != 4 {
		t.Errorf("mutations %v", f.mutations())
	}
}

func TestDdclientNotInstalled(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	for _, path := range []string{ddclientSearchPath, "/api/dyndns/settings/get", "/api/dyndns/service/status"} {
		f.on("GET", path, 404, `{"errorMessage":"Endpoint not found"}`)
	}
	f.on("GET", "/api/dyndns/accounts/get_item", 404, `{"errorMessage":"Endpoint not found"}`)
	for _, args := range [][]string{
		{"/ddclient/account", "print"}, {"/ddclient/settings", "print"}, {"/ddclient/service", "status"},
		{"/ddclient/account", "add", "description=x", "service=dyndns2", "hostnames=x.example.com", "check-ip=web_icanhazip"},
	} {
		wantFailure(t, f.run(args...), "os-ddclient is not installed", "/system/firmware/plugin install os-ddclient")
	}
	wantNoMutations(t, f)

	var unauthorized = newFakeOPN(t)
	unauthorized.on("GET", "/api/dyndns/service/status", 401, `{"status":401,"message":"Authentication Failed"}`)
	var r = unauthorized.run("/ddclient/service", "status")
	wantFailure(t, r, "Authentication Failed")
	wantNotContains(t, "output", r.stderr, "not installed")
}
