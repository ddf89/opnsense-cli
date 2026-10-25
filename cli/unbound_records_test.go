package cli

import (
	"reflect"
	"strings"
	"testing"
)

func unboundRecordsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search("/api/unbound/settings/search_acl",
		map[string]any{"uuid": "a-guests", "enabled": "1", "name": "guests", "action": "refuse", "%action": "Refuse",
			"networks": "192.168.20.0/24,fd00:20::/64", "description": "guest wifi"},
		map[string]any{"uuid": "a-lab", "enabled": "0", "name": "lab", "action": "allow", "networks": "192.0.2.0/24", "description": ""},
	)
	f.search("/api/unbound/settings/search_forward",
		map[string]any{"uuid": "f-corp", "enabled": "1", "type": "forward", "%type": "Forward", "domain": "corp.example", "server": "10.0.0.53",
			"port": "", "verify": "", "forward_tcp_upstream": "0", "forward_first": "0", "description": "corp"},
	)
	f.search("/api/unbound/settings/search_dot",
		map[string]any{"uuid": "d-quad9", "enabled": "1", "type": "dot", "%type": "DNS over TLS", "domain": "", "server": "9.9.9.9",
			"port": "853", "verify": "dns.quad9.net", "forward_tcp_upstream": "0", "forward_first": "0", "description": "quad9"},
	)
	f.search("/api/unbound/settings/search_dnsbl",
		map[string]any{"uuid": "b-ads", "enabled": "1", "type": "ag,hgz002", "%type": "AdGuard List, NORMAL", "lists": "",
			"allowlists": "ok.example", "blocklists": "", "wildcards": "", "source_nets": "", "address": "", "nxdomain": "0",
			"cache_ttl": "72000", "description": "ads"},
	)
	f.search("/api/unbound/settings/search_host_override",
		unboundRow(map[string]any{"uuid": "h-web", "hostname": "web", "domain": "example.lan", "rr": "A"}),
		unboundRow(map[string]any{"uuid": "h-web6", "hostname": "web", "domain": "example.lan", "rr": "AAAA", "server": "fd00::80"}),
		unboundRow(map[string]any{"uuid": "h-mail", "hostname": "mail", "domain": "example.lan", "rr": "A"}),
	)
	f.search("/api/unbound/settings/search_host_alias",
		map[string]any{"uuid": "al-www", "enabled": "1", "host": "h-web", "%host": "web.example.lan", "hostname": "www", "domain": "example.lan", "description": ""},
	)
	f.on("GET", "/api/unbound/settings/get_dnsbl", 200, `{"blocklist":{"type":{"ag":{"value":"AdGuard List","optgroup":"General","selected":0},
		"hgz002":{"value":"NORMAL","optgroup":"Hagezi","selected":0},"el":{"value":"EasyList","optgroup":"General","selected":0}}}}`)
	return f
}

func TestUnboundAcl(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/add_acl", 200, answerAdded("a-new"))
	f.on("POST", "/api/unbound/settings/set_acl/a-lab", 200, answerSaved)

	var r = f.run("/unbound/acl", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DISABLED|NAME|ACTION|NETWORKS|DESCRIPTION",
		"0|no|guests|refuse|192.168.20.0/24, fd00:20::/64|guest wifi", "1|yes|lab|allow|192.0.2.0/24|-"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	wantFailure(t, f.run("/unbound/acl", "add", "name=x"), "networks")
	wantFailure(t, f.run("/unbound/acl", "add", "name=x", "networks=192.0.2.1"), "CIDR")
	wantFailure(t, f.run("/unbound/acl", "add", "name=Guests", "networks=192.0.2.0/24"), "exists already", "a-guests")
	wantNoMutations(t, f)

	wantExit(t, f.run("/unbound/acl", "add", "name=iot", "action=DENY_NON_LOCAL", "networks=192.0.2.0/25,192.0.2.128/25", "disabled"), 0)
	wantExit(t, f.run("/unbound/acl", "enable", "lab"), 0)
	var already = f.run("/unbound/acl", "enable", "guests")
	wantExit(t, already, 0)
	wantContains(t, "stderr", already.stderr, "already enabled")
	var calls = f.mutations()
	if len(calls) != 2 {
		t.Fatalf("want 2 mutations, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"acl": map[string]any{"name": "iot", "action": "deny_non_local",
		"networks": "192.0.2.0/25,192.0.2.128/25", "enabled": "0"}})
	wantJSON(t, calls[1], map[string]any{"acl": map[string]any{"enabled": "1"}})
}

func TestUnboundAclDefaultAction(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/settings/get", 200, `{"unbound":{"acls":{"default_action":{"allow":{"value":"Allow","selected":1},"deny":{"value":"Deny","selected":0}},"acl":[]}}}`)
	f.on("POST", "/api/unbound/settings/set", 200, answerSaved)
	var r = f.run("/unbound/acl", "default-action")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"default-action:|allow"}) {
		t.Errorf("default-action: %q", got)
	}
	wantFailure(t, f.run("/unbound/acl", "default-action", "drop"), "must be one of")
	wantNoMutations(t, f)
	wantExit(t, f.run("/unbound/acl", "default-action", "Refuse"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/unbound/settings/set"),
		map[string]any{"unbound": map[string]any{"acls": map[string]any{"default_action": "refuse"}}})
}

func TestUnboundForwardPrintListsBothTypes(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	var r = f.run("/unbound/forward", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DISABLED|TYPE|DOMAIN|SERVER|PORT|VERIFY|DESCRIPTION",
		"0|no|forward|corp.example|10.0.0.53|-|-|corp", "1|no|dot|-|9.9.9.9|853|dns.quad9.net|quad9"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var show = f.run("/unbound/forward", "show", "9.9.9.9")
	wantExit(t, show, 0)
	wantContains(t, "show", show.stdout, "d-quad9", "verify:", "dns.quad9.net")
	wantNoMutations(t, f)
}

func TestUnboundForwardAdd(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/add_forward", 200, answerAdded("f-new"))
	f.on("POST", "/api/unbound/settings/add_dot", 200, answerAdded("d-new"))
	wantExit(t, f.run("/unbound/forward", "add", "domain=lab.example", "server=192.0.2.53"), 0)
	wantExit(t, f.run("/unbound/forward", "add", "type=dot", "server=192.0.2.54", "verify=dns.lab.example", "disabled"), 0)
	var calls = f.mutations()
	if len(calls) != 2 || calls[0].Path != "/api/unbound/settings/add_forward" || calls[1].Path != "/api/unbound/settings/add_dot" {
		t.Fatalf("unexpected mutations %v", calls)
	}
	// the type is given by the endpoint
	wantJSON(t, calls[0], map[string]any{"dot": map[string]any{"domain": "lab.example", "server": "192.0.2.53"}})
	wantJSON(t, calls[1], map[string]any{"dot": map[string]any{"server": "192.0.2.54", "verify": "dns.lab.example", "enabled": "0"}})

	var g = unboundRecordsFake(t)
	wantFailure(t, g.run("/unbound/forward", "add", "domain=corp.example", "server=10.0.0.53"), "exists already", "f-corp")
	wantFailure(t, g.run("/unbound/forward", "add", "server=dns.example"), "IPv4 or IPv6")
	wantFailure(t, g.run("/unbound/forward", "add", "type=doh", "server=192.0.2.1"), "must be one of")
	wantNoMutations(t, g)
}

func TestUnboundForwardSetConvertsType(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/set_dot/f-corp", 200, answerSaved)
	f.on("POST", "/api/unbound/settings/set_dot/d-quad9", 200, answerSaved)
	wantExit(t, f.run("/unbound/forward", "set", "corp", "type=dot", "port=853"), 0)
	wantExit(t, f.run("/unbound/forward", "set", "quad9", "description=quad nine"), 0)
	var calls = f.mutations()
	if len(calls) != 2 || calls[0].Path != "/api/unbound/settings/set_dot/f-corp" {
		t.Fatalf("unexpected mutations %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"dot": map[string]any{"port": "853"}})
	// without type= the entry keeps its type: a dot entry is updated through set_dot
	if calls[1].Path != "/api/unbound/settings/set_dot/d-quad9" {
		t.Errorf("a dot entry must be updated with set_dot, got %s", calls[1].Path)
	}
}

func TestUnboundForwardSystemNameservers(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/settings/get", 200, `{"unbound":{"forwarding":{"enabled":"1"}}}`)
	f.on("GET", "/api/unbound/settings/get_nameservers", 200, `["10.0.2.3","192.0.2.53"]`)
	f.on("POST", "/api/unbound/settings/set", 200, answerSaved)
	var r = f.run("/unbound/forward", "system-nameservers")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"use:|yes", "nameservers:|10.0.2.3, 192.0.2.53"}) {
		t.Errorf("system-nameservers: %q", got)
	}
	wantNoMutations(t, f)
	wantExit(t, f.run("/unbound/forward", "system-nameservers", "use=no"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/unbound/settings/set"),
		map[string]any{"unbound": map[string]any{"forwarding": map[string]any{"enabled": "0"}}})
}

func TestUnboundBlocklist(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/add_dnsbl", 200, answerAdded("b-new"))
	var r = f.run("/unbound/blocklist", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DISABLED|DESCRIPTION|TYPE|SOURCE-NETS|NXDOMAIN", "0|no|ads|AdGuard List, NORMAL|-|no"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantFailure(t, f.run("/unbound/blocklist", "add", "description=kids", "type=ag,nope"), "unknown list", "nope")
	wantFailure(t, f.run("/unbound/blocklist", "add", "description=ADS", "type=ag"), "exists already")
	wantFailure(t, f.run("/unbound/blocklist", "add", "type=ag"), "description")
	wantFailure(t, f.run("/unbound/blocklist", "add", "description=x", "source-nets=lan"), "addresses or networks")
	wantNoMutations(t, f)

	wantExit(t, f.run("/unbound/blocklist", "add", "description=kids", "type=AG,EL", "source-nets=192.0.2.0/24", "nxdomain", "wildcards=games.example"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/unbound/settings/add_dnsbl"), map[string]any{"blocklist": map[string]any{
		"description": "kids", "type": "ag,el", "source_nets": "192.0.2.0/24", "nxdomain": "1", "wildcards": "games.example"}})
}

func TestUnboundBlocklistCommands(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/update_blocklist", 200, `{"status":"OK"}`)
	f.on("POST", "/api/unbound/service/dnsbl", 200, `{"status":"OK\n\n"}`)
	f.on("POST", "/api/unbound/diagnostics/test_blocklist", 200, `{"status":"OK","action":"Block","policy":{"description":"ads","source_nets":[],"nxdomain":false}}`)

	var types = f.run("/unbound/blocklist", "types", "search=general")
	wantExit(t, types, 0)
	if got := dnsLines(types.stdout); !reflect.DeepEqual(got, []string{"KEY|NAME|GROUP", "ag|AdGuard List|General", "el|EasyList|General"}) {
		t.Errorf("types: %q", got)
	}

	var test = f.run("/unbound/blocklist", "test", "tracker.example", "source=192.0.2.7")
	wantExit(t, test, 0)
	wantContains(t, "test", test.stdout, "action:", "Block", "policy.description:", "ads", "policy.nxdomain:", "false")

	wantExit(t, f.run("/unbound/blocklist", "allow", "ads", "domain=ok2.example"), 0)
	wantExit(t, f.run("/unbound/blocklist", "update"), 0)
	var calls = f.mutations()
	if len(calls) != 3 {
		t.Fatalf("want 3 mutations, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"domain": "tracker.example", "src": "192.0.2.7"})
	wantJSON(t, calls[1], map[string]any{"domain": "ok2.example", "type": "allowlists", "uuid": "b-ads"})
	if calls[2].Path != "/api/unbound/service/dnsbl" {
		t.Errorf("update must POST service/dnsbl, got %v", calls[2])
	}

	var g = unboundRecordsFake(t)
	g.on("POST", "/api/unbound/diagnostics/test_blocklist", 200, `{"status":"error"}`)
	wantFailure(t, g.run("/unbound/blocklist", "test", "tracker.example"), "update")
	wantFailure(t, g.run("/unbound/blocklist", "block", "nope", "domain=x.example"), "not found")
}

func TestUnboundHostAlias(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	f.on("POST", "/api/unbound/settings/add_host_alias", 200, answerAdded("al-new"))
	f.on("POST", "/api/unbound/settings/set_host_alias/al-www", 200, answerSaved)
	f.on("POST", "/api/unbound/settings/del_host_alias/al-www", 200, answerDeleted)

	var r = f.run("/unbound/host-alias", "print")
	wantExit(t, r, 0)
	var want = []string{"#|DISABLED|HOSTNAME|DOMAIN|HOST|DESCRIPTION", "0|no|www|example.lan|web.example.lan|-"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	// web.example.lan has an A and an AAAA record
	wantFailure(t, f.run("/unbound/host-alias", "add", "host=web.example.lan", "hostname=w3", "domain=example.lan"), "matches", "h-web", "h-web6")
	wantFailure(t, f.run("/unbound/host-alias", "add", "host=nope.example.lan", "domain=example.lan"), "host override", "nope")
	wantFailure(t, f.run("/unbound/host-alias", "add", "host=mail.example.lan", "hostname=WWW", "domain=example.lan"), "exists already")
	wantNoMutations(t, f)

	wantExit(t, f.run("/unbound/host-alias", "add", "host=web.example.lan/aaaa", "hostname=w3", "domain=example.lan"), 0)
	wantExit(t, f.run("/unbound/host-alias", "set", "www.example.lan", "host=mail.example.lan"), 0)
	wantExit(t, f.run("/unbound/host-alias", "remove", "0"), 0)
	var calls = f.mutations()
	if len(calls) != 3 {
		t.Fatalf("want 3 mutations, got %v", calls)
	}
	wantJSON(t, calls[0], map[string]any{"alias": map[string]any{"host": "h-web6", "hostname": "w3", "domain": "example.lan"}})
	wantJSON(t, calls[1], map[string]any{"alias": map[string]any{"host": "h-mail"}})
	if calls[2].Path != "/api/unbound/settings/del_host_alias/al-www" {
		t.Errorf("unexpected remove %v", calls[2])
	}
}

func TestUnboundRecordsSetNeedsAField(t *testing.T) {
	t.Parallel()
	var f = unboundRecordsFake(t)
	for _, menu := range []string{"/unbound/acl", "/unbound/forward", "/unbound/blocklist", "/unbound/host-alias"} {
		var r = f.run(menu, "set", "0")
		wantFailure(t, r, "nothing to change")
		if !strings.Contains(r.stderr, "=") {
			t.Errorf("%s: the hint should name a field: %s", menu, r.stderr)
		}
	}
	wantNoCalls(t, f)
}
