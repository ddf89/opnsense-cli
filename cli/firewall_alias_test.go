package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Rows are shaped like OPNsense 26.7 (AliasController::searchItemAction): built-in aliases have their name as uuid

const (
	firewallAliasSearchPath  = "/api/firewall/alias/search_item"
	firewallAliasAddPath     = "/api/firewall/alias/add_item"
	firewallAliasSetPath     = "/api/firewall/alias/set_item/"
	firewallAliasDelPath     = "/api/firewall/alias/del_item/"
	firewallAliasTogglePath  = "/api/firewall/alias/toggle_item/"
	firewallAliasCatPath     = "/api/firewall/alias/list_categories"
	firewallAliasExportPath  = "/api/firewall/alias/export"
	firewallAliasImportPath  = "/api/firewall/alias/import"
	firewallAliasGroupsPath  = "/api/firewall/alias/list_user_groups"
	firewallAliasHostsUuid   = "5d4719b1-641f-452a-af64-c2b265517c65"
	firewallAliasPortsUuid   = "2e30a184-6fb0-427c-8306-93c84e4f710f"
	firewallAliasWebCategory = "a1137869-be43-4bed-b740-7c9592a74950"

	firewallAliasCategoriesAnswer = `{"rows":[{"uuid":"` + firewallAliasWebCategory + `","name":"web","color":"ff0000","used":1},` +
		`{"uuid":"c2c2c2c2-0000-4000-8000-000000000002","name":"vpn","color":"","used":0}]}`
)

func firewallAliasRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "enabled": "1", "name": "", "type": "host", "%type": "Host(s)", "path_expression": "", "proto": "",
		"interface": "", "counters": "0", "updatefreq": "", "content": "", "password": "", "username": "", "authtype": "",
		"expire": "", "categories": "", "current_items": "", "last_updated": "", "eval_nomatch": "", "eval_match": "",
		"description": "", "categories_uuid": []any{},
	}, overrides)
}

func firewallAliasFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallAliasSearchPath,
		firewallAliasRow(map[string]any{"uuid": firewallAliasHostsUuid, "name": "a8fw_hosts", "enabled": "0", "proto": "IPv4",
			"content": "10.9.9.1\n10.9.9.2\n10.9.9.3\n10.9.9.4", "categories": firewallAliasWebCategory, "current_items": "4",
			"password": "secret", "description": "web servers", "categories_uuid": []any{firewallAliasWebCategory}}),
		firewallAliasRow(map[string]any{"uuid": firewallAliasPortsUuid, "name": "a8fw_ports", "type": "port", "content": "80\n443",
			"description": "web ports"}),
		firewallAliasRow(map[string]any{"uuid": "bogons", "name": "bogons", "type": "external", "current_items": "1",
			"description": "bogon networks (internal)"}),
		firewallAliasRow(map[string]any{"uuid": "__lan_network", "name": "__lan_network", "type": "internal", "current_items": "0",
			"description": "lan net"}),
	)
	f.on("GET", firewallAliasCatPath, 200, firewallAliasCategoriesAnswer)
	f.on("GET", firewallAliasGroupsPath, 200, `{"1999":{"name":"admins","gid":"1999"},"2000":{"name":"vpnusers","gid":"2000"}}`)
	return f
}

var firewallAliasHeader = []string{"#", "NAME", "TYPE", "CONTENT", "ENTRIES", "DISABLED", "CATEGORIES", "DESCRIPTION"}

func TestFirewallAliasPrint(t *testing.T) {
	t.Parallel()
	var f = firewallAliasFake(t)
	var r = f.run("/firewall/alias", "print")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, firewallAliasHeader, 1, "a8fw_hosts", "a8fw_ports", "bogons", "__lan_network")
	if len(rows) == 5 {
		if got := strings.Join(rows[1], "|"); got != "0|a8fw_hosts|host|10.9.9.1,10.9.9.2,10.9.9.3,... (4)|4|yes|web|web servers" {
			t.Errorf("row 0: %s", got)
		}
		if got := strings.Join(rows[3], "|"); got != "2|bogons|external|-|1|no|-|bogon networks (internal)" {
			t.Errorf("row 2: %s", got)
		}
	}
	wantNoMutations(t, f)

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"type=PORT"}, []string{"a8fw_ports"}},
		{[]string{"type=internal"}, []string{"__lan_network"}},
		{[]string{"category=WEB"}, []string{"a8fw_hosts"}},
		{[]string{"search=bogon"}, []string{"bogons"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasFake(t)
			var r = f.run(append([]string{"/firewall/alias", "print"}, tc.args...)...)
			wantExit(t, r, 0)
			systemBackupWantTable(t, r.stdout, firewallAliasHeader, 1, tc.want...)
		})
	}
	t.Run("no categories, no category lookup", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantExit(t, f.run("/firewall/alias", "print", "type=port"), 0)
		systemBackupWantNoCallTo(t, f, firewallAliasCatPath)
	})
	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		var r = f.run("/firewall/alias", "print", "detail", "search=a8fw_hosts")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  name:", "content:          10.9.9.1,10.9.9.2,10.9.9.3,10.9.9.4", "password:         ********",
			"categories:       web", "built-in:         no")
		wantNotContains(t, "stdout", r.stdout, "secret")
	})
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		var r = f.run("/firewall/alias", "print", "json", "type=port")
		wantExit(t, r, 0)
		var row map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &row); err != nil || row["uuid"] != firewallAliasPortsUuid || row["content"] != "80\n443" {
			t.Errorf("json: %v %q", err, r.stdout)
		}
	})
}

func TestFirewallAliasShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"0", "a8fw_hosts", "A8FW_HOSTS", firewallAliasHostsUuid} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasFake(t)
			var r = f.run("/firewall/alias", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "name:             a8fw_hosts\n", "disabled:         yes\n", "proto:            IPv4\n", "entries:          4\n")
		})
	}
	t.Run("built-in", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		var r = f.run("/firewall/alias", "show", "bogons")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "uuid:             bogons\n", "built-in:         yes\n")
	})
	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "show", "nope"), "not found", "nope")
	})
}

func TestFirewallAliasAdd(t *testing.T) {
	t.Parallel()
	const newUuid = "9a9a9a9a-0000-4000-8000-000000000009"

	t.Run("fields", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasAddPath, 200, answerAdded(newUuid))
		var r = f.run("/firewall/alias", "add", "name=a8fw_geo", "type=GeoIP", "content=NL,DE", "proto=ipv4,IPv6",
			"categories=Web,vpn", "counters", "description=countries", "disabled")
		wantExit(t, r, 0)
		if strings.TrimSpace(r.stdout) != newUuid {
			t.Errorf("stdout %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasAddPath), map[string]any{"alias": map[string]any{
			"name": "a8fw_geo", "type": "geoip", "content": "NL\nDE", "proto": "IPv4,IPv6",
			"categories": firewallAliasWebCategory + ",c2c2c2c2-0000-4000-8000-000000000002", "counters": "1",
			"description": "countries", "enabled": "0",
		}})
	})
	t.Run("enabled by default, authgroup names become gids", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasAddPath, 200, answerAdded(newUuid))
		wantExit(t, f.run("/firewall/alias", "add", "name=a8fw_vpn", "type=authgroup", "content=VPNUSERS,1999"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasAddPath), map[string]any{"alias": map[string]any{
			"name": "a8fw_vpn", "type": "authgroup", "content": "2000\n1999", "enabled": "1",
		}})
	})
	t.Run("replace sends every field", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasSetPath+firewallAliasPortsUuid, 200, answerSaved)
		var r = f.run("/firewall/alias", "add", "name=a8fw_ports", "type=port", "content=8080:8090", "replace")
		wantExit(t, r, 0)
		if strings.TrimSpace(r.stdout) != firewallAliasPortsUuid {
			t.Errorf("stdout %q", r.stdout)
		}
		wantContains(t, "stderr", r.stderr, "replaced")
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasSetPath+firewallAliasPortsUuid), map[string]any{"alias": map[string]any{
			"name": "a8fw_ports", "type": "port", "content": "8080:8090", "enabled": "1", "proto": "", "interface": "",
			"updatefreq": "", "path_expression": "", "authtype": "", "username": "", "password": "", "expire": "",
			"counters": "0", "categories": "", "description": "",
		}})
	})
	t.Run("validation messages use the argument names", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasAddPath, 200, `{"result":"failed","validations":{"alias.path_expression":"bad","alias.name":"Reserved protocol or service names may not be used"}}`)
		var r = f.run("/firewall/alias", "add", "name=http", "type=urljson", "content=https://example.com/x.json")
		wantFailure(t, r, "path-expression: bad", "name: Reserved")
		wantNotContains(t, "output", r.stderr, "alias.")
	})
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"name exists", []string{"name=a8fw_ports", "type=port", "content=80"}, []string{"exists already", "replace"}},
		{"built-in", []string{"name=bogons", "type=host", "content=10.0.0.1", "replace"}, []string{"built-in"}},
		{"name required", []string{"type=host"}, []string{"name"}},
		{"invalid name", []string{"name=1abc", "type=host"}, []string{"name", "letter"}},
		{"internal type", []string{"name=a8fw_x", "type=internal"}, []string{"type", "internal"}},
		{"port alias needs content", []string{"name=a8fw_x", "type=port"}, []string{"content="}},
		{"invalid port", []string{"name=a8fw_x", "type=port", "content=80,70000"}, []string{"70000", "port"}},
		{"invalid country", []string{"name=a8fw_x", "type=geoip", "content=nl"}, []string{`"nl"`, "country"}},
		{"invalid mac", []string{"name=a8fw_x", "type=mac", "content=00:11:zz"}, []string{"MAC"}},
		{"invalid asn", []string{"name=a8fw_x", "type=asn", "content=AS123"}, []string{"AS number"}},
		{"dynipv6host needs an interface", []string{"name=a8fw_x", "type=dynipv6host", "content=::1000"}, []string{"interface="}},
		{"interface only for dynipv6host", []string{"name=a8fw_x", "type=host", "interface=lan"}, []string{"dynipv6host"}},
		{"invalid proto", []string{"name=a8fw_x", "type=geoip", "content=NL", "proto=IPv5"}, []string{"proto"}},
		{"invalid expire", []string{"name=a8fw_x", "type=external", "expire=10"}, []string{"expire", "60"}},
		{"invalid updatefreq", []string{"name=a8fw_x", "type=urltable", "updatefreq=daily"}, []string{"updatefreq"}},
		{"unknown category", []string{"name=a8fw_x", "type=host", "categories=nope"}, []string{"category", "nope"}},
		{"unknown group", []string{"name=a8fw_x", "type=authgroup", "content=nope"}, []string{"group", "nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/alias", "add"}, tc.args...)...), tc.want...)
			wantNoMutations(t, f)
		})
	}
}

func TestFirewallAliasSet(t *testing.T) {
	t.Parallel()
	var setHosts = firewallAliasSetPath + firewallAliasHostsUuid

	t.Run("only the given fields", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", setHosts, 200, answerSaved)
		var r = f.run("/firewall/alias", "set", "a8fw_hosts", "name=a8fw_web", "content=10.0.0.1,10.0.0.0/24", "categories=", "disabled=no")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("set is silent: %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", setHosts), map[string]any{"alias": map[string]any{
			"name": "a8fw_web", "content": "10.0.0.1\n10.0.0.0/24", "categories": "", "enabled": "1",
		}})
	})
	t.Run("content is checked against the stored type", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "set", "a8fw_ports", "content=99999"), "99999")
		wantNoMutations(t, f)
	})
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"nothing to set", []string{"0"}, []string{"nothing to set"}},
		{"built-in", []string{"bogons", "description=x"}, []string{"built-in"}},
		{"unknown", []string{"nope", "description=x"}, []string{"not found"}},
		{"interface on a host alias", []string{"0", "interface=lan"}, []string{"dynipv6host"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/alias", "set"}, tc.args...)...), tc.want...)
			wantNoMutations(t, f)
		})
	}
}

func TestFirewallAliasRemoveEnableApply(t *testing.T) {
	t.Parallel()
	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasDelPath+firewallAliasPortsUuid, 200, answerDeleted)
		var r = f.run("/firewall/alias", "remove", "a8fw_ports")
		wantExit(t, r, 0)
		wantOneMutation(t, f, "POST", firewallAliasDelPath+firewallAliasPortsUuid)
		if r.stdout != "" {
			t.Errorf("stdout %q", r.stdout)
		}
	})
	t.Run("remove in use", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasDelPath+firewallAliasPortsUuid, 500,
			`{"errorMessage":"Cannot delete alias a8fw_ports. Currently in use by \n[filter.rules.rule.1] allow web","errorTitle":"Alias in use"}`)
		wantFailure(t, f.run("/firewall/alias", "remove", "1"), "Cannot delete alias a8fw_ports", "in use")
	})
	t.Run("remove built-in", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "remove", "__lan_network"), "built-in")
		wantNoMutations(t, f)
	})
	t.Run("enable", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasTogglePath+firewallAliasHostsUuid+"/1", 200, `{"result":"Enabled","changed":true}`)
		wantExit(t, f.run("/firewall/alias", "enable", "a8fw_hosts"), 0)
		wantOneMutation(t, f, "POST", firewallAliasTogglePath+firewallAliasHostsUuid+"/1")
	})
	t.Run("disable a disabled alias", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		var r = f.run("/firewall/alias", "disable", "a8fw_hosts")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "already disabled")
		wantNoMutations(t, f)
	})
	t.Run("apply", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", "/api/firewall/alias/reconfigure", 200, `{"status":"ok"}`)
		var r = f.run("/firewall/alias", "apply")
		wantExit(t, r, 0)
		wantOneMutation(t, f, "POST", "/api/firewall/alias/reconfigure")
	})
}

func TestFirewallAliasExport(t *testing.T) {
	t.Parallel()
	const export = "{\n    \"aliases\": {\n        \"alias\": {\n            \"" + firewallAliasHostsUuid + "\": {\"name\": \"a8fw_hosts\", \"type\": \"host\"}\n        }\n    }\n}"

	t.Run("user aliases to stdout", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("GET", firewallAliasExportPath, 200, export)
		var r = f.run("/firewall/alias", "export")
		wantExit(t, r, 0)
		if r.stdout != export+"\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		var found bool
		for _, call := range f.calls() {
			if call.Path == firewallAliasExportPath {
				found = call.Query.Get("ids") == firewallAliasHostsUuid+","+firewallAliasPortsUuid
			}
		}
		if !found {
			t.Errorf("want the user aliases as ids: %v", f.calls())
		}
	})
	t.Run("items to a file", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("GET", firewallAliasExportPath, 200, export)
		var dir = t.TempDir()
		var r = runOpnIn(t, dir, f.env(), "/firewall/alias", "export", "items=a8fw_hosts,bogons", "file=aliases.json")
		wantExit(t, r, 0)
		var data, err = os.ReadFile(filepath.Join(dir, "aliases.json"))
		if err != nil || string(data) != export+"\n" {
			t.Errorf("file %q %v", data, err)
		}
		if info, _ := os.Stat(filepath.Join(dir, "aliases.json")); info == nil || info.Mode().Perm() != 0o600 {
			t.Errorf("want mode 0600 (URL passwords): %v", info)
		}
		wantFailure(t, runOpnIn(t, dir, f.env(), "/firewall/alias", "export", "file=aliases.json"), "already exists", "add overwrite")
		wantExit(t, runOpnIn(t, dir, f.env(), "/firewall/alias", "export", "file=aliases.json", "overwrite"), 0)
	})
	t.Run("no user aliases does not export everything", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.search(firewallAliasSearchPath, firewallAliasRow(map[string]any{"uuid": "bogons", "name": "bogons", "type": "external"}))
		var r = f.run("/firewall/alias", "export")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, `"alias": {}`)
		systemBackupWantNoCallTo(t, f, firewallAliasExportPath)
	})
	t.Run("overwrite with stdout is refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "export", "overwrite"), "overwrite has no effect")
		wantNoCalls(t, f)
		wantFailure(t, f.run("/firewall/alias", "export", "file=x.json", "force"), "force")
		wantNoCalls(t, f)
	})
	t.Run("unknown item", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "export", "items=nope"), "not found")
		systemBackupWantNoCallTo(t, f, firewallAliasExportPath)
	})
}

func TestFirewallAliasImport(t *testing.T) {
	t.Parallel()
	var write = func(t *testing.T, content string) string {
		var dir = t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "aliases.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	const file = `{"geoip":{"url":""},"aliases":{"alias":{` +
		`"u1":{"name":"a8fw_new","type":"host","content":"10.1.1.1","enabled":"0","current_items":"3"},` +
		`"u2":{"name":"a8fw_ports","type":"port","content":"22"},` +
		`"bogons":{"name":"bogons","type":"external"},` +
		`"__lan_network":{"name":"__lan_network","type":"internal"}}}}`

	t.Run("existing names need replace, built-ins are skipped", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasImportPath, 200, `{"existing":1,"new":1,"status":"ok"}`)
		var dir = write(t, file)
		var r = runOpnIn(t, dir, f.env(), "/firewall/alias", "import", "file=aliases.json")
		wantFailure(t, r, "a8fw_ports", "replace")
		wantNoMutations(t, f)

		r = runOpnIn(t, dir, f.env(), "/firewall/alias", "import", "file=aliases.json", "replace")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "skipped the built-in alias bogons", "skipped the built-in alias __lan_network", "1 new and 1 changed")
		var body = wantOneMutation(t, f, "POST", firewallAliasImportPath).json(t)
		var want = map[string]any{"data": map[string]any{"aliases": map[string]any{"alias": map[string]any{
			"u1": map[string]any{"name": "a8fw_new", "type": "host", "content": "10.1.1.1", "enabled": "0"},
			"u2": map[string]any{"name": "a8fw_ports", "type": "port", "content": "22"},
		}}}}
		if !reflect.DeepEqual(body, want) {
			var got, _ = json.Marshal(body)
			t.Errorf("body %s", got)
		}
	})
	t.Run("validation messages name the alias", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		f.on("POST", firewallAliasImportPath, 200, `{"existing":0,"new":1,"status":"failed","validations":{"u1.path_expression":"bad"}}`)
		var dir = write(t, `{"aliases":{"alias":{"u1":{"name":"a8fw_new","type":"urljson"}}}}`)
		wantFailure(t, runOpnIn(t, dir, f.env(), "/firewall/alias", "import", "file=aliases.json"), "a8fw_new.path-expression: bad")
	})
	for _, tc := range []struct {
		name    string
		content string
		want    []string
	}{
		{"not json", `nope`, []string{"not an alias export"}},
		{"no aliases", `{"aliases":{"alias":[]}}`, []string{"no aliases to import"}},
		{"only built-ins", `{"aliases":{"alias":{"x":{"name":"bogons","type":"external"}}}}`, []string{"no aliases to import"}},
		{"no name", `{"aliases":{"alias":{"x":{"type":"host"}}}}`, []string{"no name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasFake(t)
			wantFailure(t, runOpnIn(t, write(t, tc.content), f.env(), "/firewall/alias", "import", "file=aliases.json"), tc.want...)
			wantNoMutations(t, f)
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasFake(t)
		wantFailure(t, f.run("/firewall/alias", "import", "file=nope.json"), "nope.json")
		wantNoCalls(t, f)
	})
}

func TestFirewallAliasLookups(t *testing.T) {
	t.Parallel()
	var f = firewallAliasFake(t)
	f.on("GET", "/api/firewall/alias/list_countries", 200, `{"EU":{"name":"Unclassified","region":"Europe"},"NL":{"name":"Netherlands","region":"Europe"},"AQ":{"name":"Antarctica","region":null}}`)
	var r = f.run("/firewall/alias", "categories")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"NAME", "COLOR", "ALIASES"}, 0, "web", "vpn")
	r = f.run("/firewall/alias", "countries")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"CODE", "NAME", "REGION"}, 0, "AQ", "EU", "NL")
	r = f.run("/firewall/alias", "countries", "search=nether", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"code":"NL","name":"Netherlands","region":"Europe"}` {
		t.Errorf("json %q", r.stdout)
	}
}

func TestFirewallAliasComplete(t *testing.T) {
	t.Parallel()
	var f = firewallAliasFake(t)
	f.on("GET", "/api/firewall/alias/get_item", 200, `{"alias":{"interface":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0},"wan":{"value":"WAN","selected":0}}}}`)
	f.on("GET", "/api/firewall/alias_util/aliases", 200, `["a8fw_hosts","bogons"]`)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/firewall/alias show a8":                 {"a8fw_hosts", "a8fw_ports"},
		"/firewall/alias add categories=w":        {"categories=web"},
		"/firewall/alias add interface=":          {"interface=lan", "interface=wan"},
		"/firewall/alias/table print b":           {"bogons"},
		"/firewall/alias export items=__":         {"items=__lan_network"},
		"/firewall/alias print type=net":          {"type=network", "type=networkgroup"},
		"/firewall/alias/table add a8fw_hosts ad": {"address="},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
