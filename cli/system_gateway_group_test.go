package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	systemGatewayGroupSearchPath   = "/api/routing/group_settings/search"
	systemGatewayGroupGetPath      = "/api/routing/group_settings/get"
	systemGatewayGroupAddPath      = "/api/routing/group_settings/add"
	systemGatewayGroupSetPath      = "/api/routing/group_settings/set/"
	systemGatewayGroupDelPath      = "/api/routing/group_settings/del/"
	systemGatewayGroupReconfigPath = "/api/routing/group_settings/reconfigure"
)

// systemGatewayGroupStatus is a member status object of search as OPNsense 26.7 returns it
func systemGatewayGroupStatus(name string, address string, status string, text string) map[string]any {
	return map[string]any{"name": name, "address": address, "status": status, "loss": "0.0 %", "delay": "1.5 ms",
		"stddev": "~", "monitor": address, "status_translated": text, "label": "success"}
}

// systemGatewayGroupRow is a search row as OPNsense 26.7 returns it: GW_A, GW_B in tier 1 and GW_C in tier 3
func systemGatewayGroupRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "name": "multiwan", "item": "GW_A,GW_B", "%item": "GW_A - 10.0.0.1, GW_B - 10.0.0.2", "item2": "",
		"item3": "GW_C", "%item3": "GW_C - 10.0.0.3", "item4": "", "item5": "", "trigger": "down", "%trigger": "Member Down",
		"poolopts": "", "%poolopts": "Default", "descr": "main uplinks",
		"gateways": map[string]any{
			"1": []any{
				systemGatewayGroupStatus("GW_A", "10.0.0.1", "none", "Online"),
				systemGatewayGroupStatus("GW_B", "10.0.0.2", "down", "Offline"),
			},
			"2": []any{},
			"3": []any{map[string]any{"name": "GW_C", "label": "danger", "status_translated": "Disabled or inactive"}},
			"4": []any{}, "5": []any{},
		},
	}, overrides)
}

// systemGatewayGroupGet is get without uuid, with the gateway options (trimmed)
const systemGatewayGroupGet = `{"gateway_group":{"name":"",` +
	`"item":{"GW_A":{"value":"GW_A - 10.0.0.1","selected":0},"GW_B":{"value":"GW_B - 10.0.0.2","selected":0},` +
	`"GW_C":{"value":"GW_C - 10.0.0.3","selected":0},"WAN_DHCP":{"value":"WAN_DHCP - 10.0.2.2","selected":0}},` +
	`"item2":{"GW_A":{"value":"GW_A - 10.0.0.1","selected":0}},` +
	`"trigger":{"down":{"value":"Member Down","selected":1}},"poolopts":{"":{"value":"Default","selected":1}},"descr":""}}`

func systemGatewayGroupRows() []map[string]any {
	return []map[string]any{
		systemGatewayGroupRow(map[string]any{"uuid": "g-multi"}),
		systemGatewayGroupRow(map[string]any{"uuid": "g-backup", "name": "backup", "item": "", "%item": "", "item2": "GW_C",
			"item3": "", "trigger": "downlosslatency", "poolopts": "round-robin sticky-address", "descr": "",
			"gateways": map[string]any{"1": []any{}, "2": []any{systemGatewayGroupStatus("GW_C", "10.0.0.3", "none", "Online")},
				"3": []any{}, "4": []any{}, "5": []any{}}}),
	}
}

func systemGatewayGroupFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(systemGatewayGroupSearchPath, rows...)
	f.on("GET", systemGatewayGroupGetPath, 200, systemGatewayGroupGet)
	return f
}

// systemGatewayGroupLines returns the non empty output lines, trimmed and with runs of spaces reduced to "|"
func systemGatewayGroupLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, strings.Join(systemCronColumnSeparator.Split(line, -1), "|"))
		}
	}
	return lines
}

func TestSystemGatewayGroupPrint(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	var r = f.run("/system/gateway/group", "print")
	wantExit(t, r, 0)
	// the tiers cell contains two spaces between tiers, so it is split like a column here
	var want = []string{
		"#|NAME|TIERS|TRIGGER|POOL|STATUS|DESCRIPTION",
		"0|multiwan|1: GW_A, GW_B|3: GW_C|member-down|default|1 Disabled or inactive, 1 Offline, 1 Online|main uplinks",
		"1|backup|2: GW_C|packet-loss-or-latency|round-robin-sticky|1 Online|-",
	}
	if got := systemGatewayGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	wantContains(t, "stdout", r.stdout, "1: GW_A, GW_B  3: GW_C")
	wantSearchPhrases(t, f, systemGatewayGroupSearchPath, "")
	wantNoMutations(t, f)

	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		var r = f.run("/system/gateway/group", "print", "search=back")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "backup")
		wantNotContains(t, "stdout", r.stdout, "multiwan")
		wantSearchPhrases(t, f, systemGatewayGroupSearchPath, "back")
	})

	t.Run("json is the raw rows", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		var r = f.run("/system/gateway/group", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 2 {
			t.Fatalf("want 2 lines, got %q", r.stdout)
		}
		var first map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["item"] != "GW_A,GW_B" || first["gateways"] == nil {
			t.Errorf("want the raw row, got %v (%v)", first, err)
		}
	})

	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		var r = f.run("/system/gateway/group", "print", "detail")
		wantExit(t, r, 0)
		var lines = systemGatewayGroupLines(r.stdout)
		for _, want := range []string{"0", "uuid:|g-multi", "tier1:|GW_A, GW_B", "tier2:", "tier3:|GW_C", "trigger:|member-down",
			"pool:|default", "member GW_A:|Online, 10.0.0.1, loss 0.0 %, delay 1.5 ms", "member GW_C:|Disabled or inactive",
			"1", "uuid:|g-backup", "trigger:|packet-loss-or-latency", "pool:|round-robin-sticky"} {
			var found = false
			for _, line := range lines {
				if line == want {
					found = true
				}
			}
			if !found {
				t.Errorf("detail lacks line %q:\n%s", want, r.stdout)
			}
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t)
		var r = f.run("/system/gateway/group", "print")
		wantExit(t, r, 0)
		if got := systemGatewayGroupLines(r.stdout); len(got) != 1 {
			t.Errorf("want only the header, got %q", got)
		}
	})
}

func TestSystemGatewayGroupShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"0", "g-multi", "multiwan", "MULTIWAN"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
			var r = f.run("/system/gateway/group", "show", selector)
			wantExit(t, r, 0)
			var want = []string{
				"uuid:|g-multi", "name:|multiwan", "tier1:|GW_A, GW_B", "tier2:", "tier3:|GW_C", "tier4:", "tier5:",
				"trigger:|member-down", "pool:|default", "description:|main uplinks",
				"member GW_A:|Online, 10.0.0.1, loss 0.0 %, delay 1.5 ms", "member GW_B:|Offline, 10.0.0.2, loss 0.0 %, delay 1.5 ms",
				"member GW_C:|Disabled or inactive",
			}
			var got = systemGatewayGroupLines(r.stdout)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("show:\n got  %q\n want %q", got, want)
			}
			wantNoMutations(t, f)
		})
	}

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "show", "multi"), "not found")
		wantFailure(t, f.run("/system/gateway/group", "show", "5"), "not found")
	})
}

func TestSystemGatewayGroupAdd(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	f.on("POST", systemGatewayGroupAddPath, 200, answerAdded("g-new"))
	var r = f.run("/system/gateway/group", "add", "name=failover", "tier1=GW_A", "tier2=GW_B,GW_C", "description=wan failover")
	wantExit(t, r, 0)
	if r.stdout != "g-new\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupAddPath), map[string]any{"gateway_group": map[string]any{
		"name": "failover", "item": "GW_A", "item2": "GW_B,GW_C", "item3": "", "item4": "", "item5": "",
		"trigger": "down", "poolopts": "", "descr": "wan failover",
	}})
	wantSearchPhrases(t, f, systemGatewayGroupSearchPath, "failover")

	t.Run("trigger and pool are mapped", func(t *testing.T) {
		t.Parallel()
		for word, want := range map[[2]string][2]string{
			{"member-down", "default"}:                       {"down", ""},
			{"packet-loss", "round-robin"}:                   {"downloss", "round-robin"},
			{"high-latency", "round-robin-sticky"}:           {"downlatency", "round-robin sticky-address"},
			{"Packet-Loss-Or-Latency", "ROUND-ROBIN-STICKY"}: {"downlosslatency", "round-robin sticky-address"},
		} {
			var f = systemGatewayGroupFake(t)
			f.on("POST", systemGatewayGroupAddPath, 200, answerAdded("g-new"))
			wantExit(t, f.run("/system/gateway/group", "add", "name=g1", "tier3=GW_A", "trigger="+word[0], "pool="+word[1]), 0)
			wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupAddPath), map[string]any{"gateway_group": map[string]any{
				"name": "g1", "item": "", "item2": "", "item3": "GW_A", "item4": "", "item5": "",
				"trigger": want[0], "poolopts": want[1], "descr": "",
			}})
		}
	})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{
			{"name=g1"},
			{"name=g1", "tier1="},
			{"name=g 1", "tier1=GW_A"},
			{"name=" + strings.Repeat("g", 33), "tier1=GW_A"},
			{"name=g1", "tier1=GW_A,GW_A"},
			{"name=g1", "tier2=GW A"},
			{"name=g1", "tier1=GW_A", "trigger=loss"},
			{"name=g1", "tier1=GW_A", "pool=sticky"},
			{"tier1=GW_A"},
		} {
			var f = systemGatewayGroupFake(t)
			wantFailure(t, f.run(append([]string{"/system/gateway/group", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("unknown gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t)
		var r = f.run("/system/gateway/group", "add", "name=g1", "tier1=GW_A", "tier4=GW_X")
		wantFailure(t, r, `tier4: unknown gateway "GW_X"`, "GW_A, GW_B, GW_C, WAN_DHCP")
		wantNoMutations(t, f)
	})

	t.Run("name of a gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t)
		wantFailure(t, f.run("/system/gateway/group", "add", "name=wan_dhcp", "tier1=GW_A"), "WAN_DHCP is the name of a gateway")
		wantNoMutations(t, f)
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "add", "name=multiwan", "tier1=GW_A"), "exists already", "g-multi", "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		f.on("POST", systemGatewayGroupSetPath+"g-multi", 200, answerSaved)
		var r = f.run("/system/gateway/group", "add", "name=multiwan", "tier1=GW_B", "trigger=high-latency", "replace")
		wantExit(t, r, 0)
		if r.stdout != "g-multi\n" {
			t.Errorf("want the uuid on stdout, got %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced")
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupSetPath+"g-multi"), map[string]any{"gateway_group": map[string]any{
			"item": "GW_B", "item2": "", "item3": "", "item4": "", "item5": "",
			"trigger": "downlatency", "poolopts": "", "descr": "",
		}})
	})

	t.Run("replace can not clear tier 1", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "add", "name=multiwan", "tier2=GW_B", "replace"), "tier 1", "can not be cleared")
		wantNoMutations(t, f)
	})

	t.Run("validation error of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t)
		f.on("POST", systemGatewayGroupAddPath, 200, answerValidation("gateway_group.item", "Option [GW_A] not in list."))
		wantFailure(t, f.run("/system/gateway/group", "add", "name=g1", "tier1=GW_A"), "gateway_group.item", "not in list")
	})
}

func TestSystemGatewayGroupSet(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	f.on("POST", systemGatewayGroupSetPath+"g-backup", 200, answerSaved)
	var r = f.run("/system/gateway/group", "set", "backup", "tier2=GW_A,GW_C", "tier5=WAN_DHCP", "pool=round-robin", "description=")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupSetPath+"g-backup"), map[string]any{"gateway_group": map[string]any{
		"item2": "GW_A,GW_C", "item5": "WAN_DHCP", "poolopts": "round-robin", "descr": "",
	}})

	t.Run("by # and clearing a tier", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		f.on("POST", systemGatewayGroupSetPath+"g-multi", 200, answerSaved)
		wantExit(t, f.run("/system/gateway/group", "set", "0", "tier3=", "trigger=packet-loss"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupSetPath+"g-multi"), map[string]any{"gateway_group": map[string]any{
			"item3": "", "trigger": "downloss",
		}})
	})

	t.Run("the unchanged name is accepted", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		f.on("POST", systemGatewayGroupSetPath+"g-multi", 200, answerSaved)
		wantExit(t, f.run("/system/gateway/group", "set", "multiwan", "name=multiwan"), 0)
		wantNoMutations(t, f)
		wantExit(t, f.run("/system/gateway/group", "set", "multiwan", "name=multiwan", "description=x"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemGatewayGroupSetPath+"g-multi"), map[string]any{"gateway_group": map[string]any{"descr": "x"}})
	})

	t.Run("rename is refused", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "set", "multiwan", "name=other", "description=x"), "can not be renamed")
		wantNoMutations(t, f)
	})

	t.Run("nothing to change", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		var r = f.run("/system/gateway/group", "set", "multiwan")
		wantFailure(t, r, "error: set: nothing to change")
		wantNotContains(t, "stderr", r.stderr, "set: set:")
		r = f.run("/system/gateway/group", "add", "name=g1", "description=no tiers")
		wantFailure(t, r, "error: add: a gateway group needs at least one gateway")
		wantNotContains(t, "stderr", r.stderr, "add: add:")
		wantNoCalls(t, f)
	})

	t.Run("unknown gateway", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "set", "multiwan", "tier2=GW_A,nope"), `tier2: unknown gateway "nope"`)
		wantNoMutations(t, f)
	})

	t.Run("clearing tier 1 is refused", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "set", "multiwan", "tier1="), "tier 1", "can not be cleared")
		wantNoMutations(t, f)
	})

	t.Run("no member left is refused", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "set", "backup", "tier2="), "at least one gateway")
		wantNoMutations(t, f)
	})

	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "set", "nope", "description=x"), "not found")
		wantFailure(t, f.run("/system/gateway/group", "set", "7", "description=x"), "not found")
		wantNoMutations(t, f)
	})
}

func TestSystemGatewayGroupRemove(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	f.on("POST", systemGatewayGroupDelPath+"g-backup", 200, answerDeleted)
	var r = f.run("/system/gateway/group", "remove", "backup")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemGatewayGroupDelPath+"g-backup")

	t.Run("in use", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		f.on("POST", systemGatewayGroupDelPath+"g-multi", 500,
			`{"errorMessage":"Gateway group multiwan in use by rule lan to internet (4b0b1f5c-0000-4000-8000-000000000000)","errorTitle":""}`)
		wantFailure(t, f.run("/system/gateway/group", "remove", "0"), "multiwan in use by rule lan to internet")
	})

	t.Run("vanished meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		f.on("POST", systemGatewayGroupDelPath+"g-multi", 200, answerNotFound)
		wantFailure(t, f.run("/system/gateway/group", "remove", "g-multi"), "not found")
	})

	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
		wantFailure(t, f.run("/system/gateway/group", "remove", "nope"), "not found")
		wantNoMutations(t, f)
	})
}

func TestSystemGatewayGroupApply(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t)
	f.on("POST", systemGatewayGroupReconfigPath, 200, `{"status":"ok"}`)
	var r = f.run("/system/gateway/group", "apply")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("apply must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", systemGatewayGroupReconfigPath)

	t.Run("failure status", func(t *testing.T) {
		t.Parallel()
		var f = systemGatewayGroupFake(t)
		f.on("POST", systemGatewayGroupReconfigPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/gateway/group", "apply"), "failed")
	})
}

func TestSystemGatewayGroupScriptUsesPrintIndexes(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	f.on("POST", systemGatewayGroupDelPath+"g-backup", 200, answerDeleted)
	var r = f.runScript("/system/gateway/group\nprint search=back\nremove 0\n")
	wantExit(t, r, 0)
	wantOneMutation(t, f, "POST", systemGatewayGroupDelPath+"g-backup")
}

func TestSystemGatewayGroupComplete(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t, systemGatewayGroupRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/gateway/group remove b":             {"backup"},
		"/system/gateway/group set item=":            {"item=backup", "item=multiwan"},
		"/system/gateway/group add tier1=GW_A,":      {"tier1=GW_A,GW_A", "tier1=GW_A,GW_B", "tier1=GW_A,GW_C", "tier1=GW_A,WAN_DHCP"},
		"/system/gateway/group set 0 tier3=w":        {"tier3=WAN_DHCP"},
		"/system/gateway/group add trigger=packet":   {"trigger=packet-loss", "trigger=packet-loss-or-latency"},
		"/system/gateway/group add pool=round-robin": {"pool=round-robin", "pool=round-robin-sticky"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}

func TestSystemGatewayGroupHelp(t *testing.T) {
	t.Parallel()
	var f = systemGatewayGroupFake(t)
	var r = f.run("/system/gateway/group", "add", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "name=<string>", "tier1=<list>", "tier5=<list>",
		"trigger=member-down|packet-loss|high-latency|packet-loss-or-latency", "pool=default|round-robin|round-robin-sticky",
		"replace", "/system/gateway/group apply")
	wantNoCalls(t, f)

	var menu = f.run("/system/gateway/group", "?")
	wantExit(t, menu, 0)
	wantContains(t, "stdout", menu.stdout, "print", "show", "add", "set", "remove", "apply")
}
