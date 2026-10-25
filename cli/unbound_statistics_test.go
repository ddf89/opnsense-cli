package cli

import (
	"reflect"
	"strings"
	"testing"
)

const unboundSettingsGetAnswer = `{"unbound":{
	"general":{"enabled":"1","port":"53","stats":"0","active_interface":{"lan":{"value":"LAN","selected":1},"wan":{"value":"WAN","selected":0}},
		"dnssec":"1","dns64":"0","dns64prefix":"","noarecords":"0","regdhcp":"0","regdhcpdomain":"","regdhcpstatic":"1","noreglladdr6":"0",
		"noregrecords":"0","txtsupport":"0","cacheflush":"0","safesearch":"0",
		"local_zone_type":{"transparent":{"value":"transparent","selected":1},"static":{"value":"static","selected":0}},
		"outgoing_interface":{"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}},"enable_wpad":"0"},
	"advanced":{"hideidentity":"1","hideversion":"0","prefetch":"0","logverbosity":[{"value":"Level 0","selected":0},{"value":"Level 1 (Default)","selected":1},{"value":"Level 2","selected":0}],
		"valloglevel":[{"value":"Level 0 (Default)","selected":1}],"privatedomain":{"":{"value":"","selected":1}},
		"privateaddress":{"10.0.0.0/8":{"value":"10.0.0.0/8","selected":1},"192.168.0.0/16":{"value":"192.168.0.0/16","selected":1}},
		"insecuredomain":{"":{"value":"","selected":1}},"msgcachesize":"4m","cachemaxttl":""},
	"acls":{"default_action":{"allow":{"value":"Allow","selected":1}},"acl":[]},"dnsbl":{"blocklist":[]},"forwarding":{"enabled":"0"},
	"dots":{"dot":[]},"hosts":{"host":[]},"aliases":{"alias":[]}}}`

func unboundSettingsFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/settings/get", 200, unboundSettingsGetAnswer)
	f.on("POST", "/api/unbound/settings/set", 200, answerSaved)
	return f
}

func TestUnboundSettingsPrint(t *testing.T) {
	t.Parallel()
	var f = unboundSettingsFake(t)
	var r = f.run("/unbound/settings", "print")
	wantExit(t, r, 0)
	var lines = strings.Join(dnsLines(r.stdout), "\n")
	wantContains(t, "print", lines+"\n", "enabled:|yes\n", "interface:|lan\n", "dnssec:|yes\n", "register-dhcp-static:|yes\n",
		"local-zone-type:|transparent\n", "statistics:|no\n")

	var advanced = f.run("/unbound/advanced", "print")
	wantExit(t, advanced, 0)
	wantContains(t, "advanced", strings.Join(dnsLines(advanced.stdout), "\n")+"\n", "hide-identity:|yes\n", "log-verbosity:|1\n",
		"private-address:|10.0.0.0/8,192.168.0.0/16\n", "msg-cache-size:|4m\n")

	var options = f.run("/unbound/advanced", "print", "options=log-verbosity")
	wantExit(t, options, 0)
	if got := dnsLines(options.stdout); !reflect.DeepEqual(got, []string{"KEY|NAME|SELECTED", "0|Level 0|no", "1|Level 1 (Default)|yes", "2|Level 2|no"}) {
		t.Errorf("options: %q", got)
	}
	wantNoMutations(t, f)
}

func TestUnboundSettingsSet(t *testing.T) {
	t.Parallel()
	var f = unboundSettingsFake(t)
	wantExit(t, f.run("/unbound/settings", "set", "statistics", "interface=", "local-zone-type=STATIC"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/unbound/settings/set"), map[string]any{"unbound": map[string]any{
		"general": map[string]any{"stats": "1", "active_interface": "", "local_zone_type": "static"}}})

	var g = unboundSettingsFake(t)
	wantExit(t, g.run("/unbound/advanced", "set", "prefetch", "log-verbosity=2", "private-domain=lan.example, corp.example", "rrset-cache-size=8M"), 0)
	wantJSON(t, wantOneMutation(t, g, "POST", "/api/unbound/settings/set"), map[string]any{"unbound": map[string]any{
		"advanced": map[string]any{"prefetch": "1", "logverbosity": "2", "privatedomain": "lan.example,corp.example", "rrsetcachesize": "8M"}}})
}

func TestUnboundSettingsSetValidation(t *testing.T) {
	t.Parallel()
	var f = unboundSettingsFake(t)
	wantFailure(t, f.run("/unbound/settings", "set"), "nothing to change")
	wantFailure(t, f.run("/unbound/settings", "set", "interface=lan,opt7"), "unknown value", "opt7")
	wantFailure(t, f.run("/unbound/settings", "set", "local-zone-type=static,deny"), "takes one value")
	wantFailure(t, f.run("/unbound/advanced", "set", "msg-cache-size=lots"), "size like 4m")
	wantFailure(t, f.run("/unbound/advanced", "set", "private-address=10.0.0.1"), "CIDR")
	wantFailure(t, f.run("/unbound/advanced", "set", "log-verbosity=9"), "unknown value")
	wantNoMutations(t, f)
}

func TestUnboundServiceCommands(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/unbound/service/start", 200, `{"response":"OK"}`)
	f.on("POST", "/api/unbound/service/stop", 200, `{"response":"OK"}`)
	f.on("POST", "/api/unbound/service/reconfigure", 200, `{"status":"ok"}`)
	f.on("POST", "/api/unbound/service/reconfigure_general", 200, `{"status":"ok"}`)

	wantFailure(t, f.run("/unbound/service", "stop"), "confirm")
	wantNoCalls(t, f)

	wantExit(t, f.run("/unbound/service", "start"), 0)
	wantExit(t, f.run("/unbound/service", "stop", "confirm=yes"), 0)
	wantExit(t, f.run("/unbound/service", "reconfigure"), 0)
	wantExit(t, f.run("/unbound/service", "reconfigure", "general"), 0)
	var paths []string
	for _, call := range f.mutations() {
		paths = append(paths, call.Path)
	}
	var want = []string{"/api/unbound/service/start", "/api/unbound/service/stop", "/api/unbound/service/reconfigure", "/api/unbound/service/reconfigure_general"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("got %q, want %q", paths, want)
	}
}

func TestUnboundStatisticsPrint(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/overview/is_enabled", 200, `{"enabled":"1"}`)
	f.on("GET", "/api/unbound/overview/totals/3", 200, `{"total":10,"blocklist_size":250,"passed":8,
		"resolved":{"total":6,"pcnt":"60.00"},"blocked":{"total":2,"pcnt":"20.00"},"local":{"total":0,"pcnt":0},"start_time":1761400000,
		"top":{"a.example":{"total":3,"pcnt":"37.50"},"b.example":{"total":5,"pcnt":"62.50"}},
		"top_blocked":{"ads.example":{"total":2,"pcnt":"100.00","blocklist":"AdGuard List"}}}`)
	var r = f.run("/unbound/statistics", "print", "top=3")
	wantExit(t, r, 0)
	var want = []string{"recording:|yes", "since:|2025-10-25 13:46:40", "total:|10", "passed:|8", "resolved:|6 (60.00%)",
		"blocked:|2 (20.00%)", "local:|0 (0.00%)", "blocklist-size:|250",
		"TOP DOMAIN|QUERIES|PERCENT", "b.example|5|62.50", "a.example|3|37.50",
		"TOP BLOCKED|QUERIES|PERCENT|BLOCKLIST", "ads.example|2|100.00|AdGuard List"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantFailure(t, f.run("/unbound/statistics", "print", "top=0"), "from 1 to 1000")
	wantNoMutations(t, f)
}

func TestUnboundStatisticsDisabled(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/overview/is_enabled", 200, `{"enabled":"0"}`)
	f.on("GET", "/api/unbound/overview/totals/10", 200, `[]`)
	var r = f.run("/unbound/statistics", "print")
	wantExit(t, r, 0)
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, []string{"recording:|no"}) {
		t.Errorf("print: %q", got)
	}
	wantContains(t, "stderr", r.stderr, "statistics=yes")
}

func TestUnboundStatisticsQueries(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	var rows []map[string]any
	for _, domain := range []string{"a.example", "ads.example", "c.example"} {
		var row = map[string]any{"uuid": nil, "time": 1761400000, "client": "192.168.1.10", "family": "ip4", "type": "A", "domain": domain,
			"action": "Pass", "source": "Recursion", "blocklist": nil, "rcode": "NOERROR", "resolve_time_ms": 12, "dnssec_status": "Unchecked",
			"ttl": 300, "policy": "", "status": 0}
		if domain == "ads.example" {
			row["action"], row["blocklist"], row["policy"], row["source"] = "Block", "AdGuard List", "ads", "Local"
		}
		rows = append(rows, row)
	}
	f.search("/api/unbound/overview/search_queries", rows...)
	var r = f.run("/unbound/statistics", "queries", "limit=2")
	wantExit(t, r, 0)
	var want = []string{"TIME|CLIENT|TYPE|DOMAIN|ACTION|SOURCE|RCODE|MS|BLOCKLIST",
		"2025-10-25 13:46:40|192.168.1.10|A|a.example|Pass|Recursion|NOERROR|12|-",
		"2025-10-25 13:46:40|192.168.1.10|A|ads.example|Block|Local|NOERROR|12|AdGuard List (ads)"}
	if got := dnsLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("queries:\n got  %q\n want %q", got, want)
	}
	var searched = f.run("/unbound/statistics", "queries", "search=ads", "json")
	wantExit(t, searched, 0)
	if lines := strings.Split(strings.TrimSpace(searched.stdout), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"domain":"ads.example"`) {
		t.Errorf("json: %q", searched.stdout)
	}
	wantSearchPhrases(t, f, "/api/unbound/overview/search_queries", "", "ads")
}

func TestUnboundStatisticsHistoryCountersReset(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/overview/rolling/12/0", 200, `{"1761400600":{"total":2,"passed":1,"blocked":1,"dropped":0,"resolved":1,"local":1,"cached":0},
		"1761400000":{"total":1,"passed":1,"blocked":0,"dropped":0,"resolved":0,"local":0,"cached":1}}`)
	f.on("GET", "/api/unbound/diagnostics/stats", 200, `{"status":"ok","data":{"total":{"num":{"queries":"18","cachehits":"10"}},"time":{"up":"5.5"}}}`)
	f.on("POST", "/api/unbound/overview/reset", 200, `{"status":"OK\n\n"}`)

	var history = f.run("/unbound/statistics", "history", "hours=12")
	wantExit(t, history, 0)
	var want = []string{"START|TOTAL|PASSED|BLOCKED|DROPPED|RESOLVED|LOCAL|CACHED",
		"2025-10-25 13:46:40|1|1|0|0|0|0|1", "2025-10-25 13:56:40|2|1|1|0|1|1|0"}
	if got := dnsLines(history.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("history:\n got  %q\n want %q", got, want)
	}
	wantFailure(t, f.run("/unbound/statistics", "history", "hours=6"), "must be one of")

	var counters = f.run("/unbound/statistics", "counters", "search=total.num")
	wantExit(t, counters, 0)
	if got := dnsLines(counters.stdout); !reflect.DeepEqual(got, []string{"total.num.cachehits:|10", "total.num.queries:|18"}) {
		t.Errorf("counters: %q", got)
	}

	wantFailure(t, f.run("/unbound/statistics", "reset"), "confirm")
	wantNoMutations(t, f)
	wantExit(t, f.run("/unbound/statistics", "reset", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", "/api/unbound/overview/reset")
}

func TestUnboundDiagnostics(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/unbound/diagnostics/dumpcache", 200, `{"status":"ok","data":[
		{"host":"example.com.","ttl":"300","type":"IN","rrtype":"A","value":"192.0.2.1"},
		{"host":"example.org.","ttl":"60","type":"IN","rrtype":"AAAA","value":"2001:db8::1"}]}`)
	f.on("GET", "/api/unbound/diagnostics/listlocalzones", 200, `{"status":"ok","data":[{"zone":"lan.","type":"transparent"},{"zone":"10.in-addr.arpa.","type":"static"}]}`)
	f.on("GET", "/api/unbound/diagnostics/listinsecure", 200, `{"status":"ok","data":["corp.example."]}`)
	f.on("GET", "/api/unbound/diagnostics/dumpinfra", 200, `{"status":"ok","data":[{"ip":"192.0.2.53","host":"org.","ttl":"250","ping":"62","rtt":"594","rto":"594","lame":true}]}`)
	f.on("GET", "/api/unbound/diagnostics/listlocaldata", 200, `{"status":"failed"}`)

	var cache = f.run("/unbound/diagnostics", "cache", "search=org")
	wantExit(t, cache, 0)
	if got := dnsLines(cache.stdout); !reflect.DeepEqual(got, []string{"NAME|TTL|TYPE|VALUE", "example.org.|60|AAAA|2001:db8::1"}) {
		t.Errorf("cache: %q", got)
	}
	var zones = f.run("/unbound/diagnostics", "local-zones")
	wantExit(t, zones, 0)
	if got := dnsLines(zones.stdout); !reflect.DeepEqual(got, []string{"ZONE|TYPE", "lan.|transparent", "10.in-addr.arpa.|static"}) {
		t.Errorf("local-zones: %q", got)
	}
	var insecure = f.run("/unbound/diagnostics", "insecure")
	wantExit(t, insecure, 0)
	if strings.TrimSpace(insecure.stdout) != "corp.example." {
		t.Errorf("insecure: %q", insecure.stdout)
	}
	var infra = f.run("/unbound/diagnostics", "infra")
	wantExit(t, infra, 0)
	if got := dnsLines(infra.stdout); !reflect.DeepEqual(got, []string{"ZONE|SERVER|RTT|RTO|PING|TTL|LAME", "org.|192.0.2.53|594|594|62|250|yes"}) {
		t.Errorf("infra: %q", got)
	}
	wantFailure(t, f.run("/unbound/diagnostics", "local-data"), "is Unbound running")
	wantNoMutations(t, f)
}
