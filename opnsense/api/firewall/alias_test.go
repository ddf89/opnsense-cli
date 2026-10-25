package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

// Answers are shaped like OPNsense 26.7 (AliasController, AliasUtilController)

type aliasTestCall struct {
	Method string
	Path   string // escaped path with query
	Body   string
}

type aliasTestAnswer struct {
	Status int
	Body   string
}

// aliasTestApi starts a test server answering with answers["METHOD /escaped/path"] (an OPNsense like 404 otherwise)
// and records all calls
func aliasTestApi(t *testing.T, answers map[string]aliasTestAnswer) (*FirewallApi, func() []aliasTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []aliasTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		var path = r.URL.EscapedPath()
		mu.Lock()
		var full = path
		if r.URL.RawQuery != "" {
			full += "?" + r.URL.RawQuery
		}
		calls = append(calls, aliasTestCall{r.Method, full, string(body)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var answer, ok = answers[r.Method+" "+path]
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
			return
		}
		if answer.Status != 0 {
			w.WriteHeader(answer.Status)
		}
		_, _ = io.WriteString(w, answer.Body)
	}))
	t.Cleanup(server.Close)
	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &FirewallApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "k", ApiSecret: "s"}}, func() []aliasTestCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]aliasTestCall(nil), calls...)
	}
}

func aliasTestOk(body string) aliasTestAnswer {
	return aliasTestAnswer{Body: body}
}

func aliasTestPosts(calls []aliasTestCall) []aliasTestCall {
	var posts []aliasTestCall
	for _, call := range calls {
		if call.Method != "GET" {
			posts = append(posts, call)
		}
	}
	return posts
}

const (
	aliasTestUuid  = "5d4719b1-641f-452a-af64-c2b265517c65"
	aliasTestGroup = "d637f44c-3f87-46e0-b23c-8bfb17767310"

	aliasTestSearchPath = "GET /api/firewall/alias/search_item"

	// aliasTestSearch: a stored host alias, a network group and the built-in bogons and __lan_network
	aliasTestSearch = `{"rows":[` +
		`{"uuid":"` + aliasTestUuid + `","enabled":"0","name":"a8fw_hosts","type":"host","%type":"Host(s)","path_expression":"","proto":"IPv4",` +
		`"interface":"","counters":"1","updatefreq":"0.5","content":"10.9.9.1\n10.9.9.2","password":"","username":"","authtype":"",` +
		`"expire":"","categories":"a1137869-be43-4bed-b740-7c9592a74950","current_items":"","last_updated":"","eval_nomatch":"",` +
		`"description":"probe hosts","categories_uuid":["a1137869-be43-4bed-b740-7c9592a74950"]},` +
		`{"uuid":"` + aliasTestGroup + `","enabled":"1","name":"a8fw_group","type":"networkgroup","content":"a8fw_hosts\n__lan_network",` +
		`"categories":"","current_items":"3","description":"group","categories_uuid":[]},` +
		`{"uuid":"bogons","enabled":"1","name":"bogons","type":"external","content":"","expire":"","current_items":"1",` +
		`"description":"bogon networks (internal)","categories_uuid":[]},` +
		`{"uuid":"__lan_network","enabled":"1","name":"__lan_network","type":"internal","content":"","current_items":"0",` +
		`"description":"lan net","categories_uuid":[]}` +
		`],"rowCount":4,"total":4,"current":1}`
)

func aliasTestBody(t *testing.T, call aliasTestCall) map[string]string {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal([]byte(call.Body), &body); err != nil || body["alias"] == nil || len(body) != 1 {
		t.Fatalf("body of %s is not {\"alias\":{...}}: %v %q", call.Path, err, call.Body)
	}
	return body["alias"]
}

func TestAliasList(t *testing.T) {
	var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{aliasTestSearchPath: aliasTestOk(aliasTestSearch)})
	var raw, aliases, err = api.AliasListRaw("")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 || len(aliases) != 4 {
		t.Fatalf("want 4 aliases, got %d", len(aliases))
	}
	var hosts = aliases[0]
	if hosts.Name != "a8fw_hosts" || hosts.Proto != "IPv4" || hosts.Updatefreq != "0.5" || hosts.BuiltIn() ||
		!reflect.DeepEqual(hosts.ContentList(), []string{"10.9.9.1", "10.9.9.2"}) || len(hosts.CategoriesUuid) != 1 {
		t.Errorf("hosts: %+v", hosts)
	}
	if !aliases[2].BuiltIn() || !aliases[3].BuiltIn() || aliases[1].BuiltIn() {
		t.Errorf("built-in detection: %+v", aliases)
	}
	if len(aliases[2].ContentList()) != 0 || aliases[2].CategoriesUuid == nil {
		t.Errorf("bogons: %+v", aliases[2])
	}

	if alias, err := api.AliasGet("BOGONS"); err != nil || alias.Name != "bogons" {
		t.Errorf("get: %+v %v", alias, err)
	}
	if _, err := api.AliasGet("00000000-0000-0000-0000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if alias, err := api.AliasGetByName("a8fw_group"); err != nil || alias.Uuid != aliasTestGroup {
		t.Errorf("by name: %+v %v", alias, err)
	}
	if _, err := api.AliasGetByName("A8FW_GROUP"); !coreapi.IsNotFound(err) {
		t.Errorf("names are case-sensitive, got %v", err)
	}
}

func TestAliasValidName(t *testing.T) {
	for _, name := range []string{"a", "_ab", "a_", "a8fw_1a2b3c4d_hosts", "A1", strings.Repeat("a", 31)} {
		if err := AliasValidName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"", "_", "__lan", "1abc", "a-b", "a b", strings.Repeat("a", 32), "ä"} {
		if err := AliasValidName(name); err == nil {
			t.Errorf("%q is valid", name)
		}
	}
}

func TestAliasCreate(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"POST /api/firewall/alias/add_item": aliasTestOk(`{"result":"saved","uuid":"` + aliasTestUuid + `"}`),
	})
	var uuid, err = api.AliasCreate(AliasFields{"name": "a8fw_x", "type": "host", "content": "10.0.0.1\n10.0.0.2", "enabled": "0"})
	if err != nil || uuid != aliasTestUuid {
		t.Fatalf("uuid %q err %v", uuid, err)
	}
	if body := aliasTestBody(t, calls()[0]); body["content"] != "10.0.0.1\n10.0.0.2" || body["enabled"] != "0" || len(body) != 4 {
		t.Errorf("body %v", body)
	}

	t.Run("validation", func(t *testing.T) {
		var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{
			"POST /api/firewall/alias/add_item": aliasTestOk(`{"result":"failed","validations":{"alias.name":"An alias with this name already exists."}}`),
		})
		var _, err = api.AliasCreate(AliasFields{"name": "a8fw_x", "type": "host"})
		var validation *coreapi.ValidationError
		if !errors.As(err, &validation) || validation.Validations["name"] != "An alias with this name already exists." {
			t.Errorf("want a validation error keyed by field, got %v", err)
		}
	})
	t.Run("refused before sending", func(t *testing.T) {
		var api, calls = aliasTestApi(t, nil)
		for _, fields := range []AliasFields{{"name": "x", "type": "internal"}, {"name": "x", "bogus": "1"}} {
			if _, err := api.AliasCreate(fields); err == nil {
				t.Errorf("%v: want an error", fields)
			}
		}
		if len(calls()) != 0 {
			t.Errorf("calls: %v", calls())
		}
	})
}

func TestAliasUpdate(t *testing.T) {
	var setPath = "POST /api/firewall/alias/set_item/" + aliasTestUuid
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		aliasTestSearchPath: aliasTestOk(aliasTestSearch),
		setPath:             aliasTestOk(`{"result":"saved"}`),
	})
	if err := api.AliasUpdate(aliasTestUuid, AliasFields{"description": "new", "content": ""}); err != nil {
		t.Fatal(err)
	}
	var posts = aliasTestPosts(calls())
	if len(posts) != 1 || !reflect.DeepEqual(aliasTestBody(t, posts[0]), map[string]string{"description": "new", "content": ""}) {
		t.Errorf("posts: %v", posts)
	}

	t.Run("replace sends every field", func(t *testing.T) {
		var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{aliasTestSearchPath: aliasTestOk(aliasTestSearch), setPath: aliasTestOk(`{"result":"saved"}`)})
		if err := api.AliasReplace(aliasTestUuid, AliasFields{"name": "a8fw_hosts", "type": "port", "content": "80"}); err != nil {
			t.Fatal(err)
		}
		var body = aliasTestBody(t, aliasTestPosts(calls())[0])
		if len(body) != len(AliasFieldNames) || body["type"] != "port" || body["proto"] != "" || body["counters"] != "0" || body["enabled"] != "1" {
			t.Errorf("body %v", body)
		}
	})
	t.Run("unknown and built-in are not sent", func(t *testing.T) {
		var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{aliasTestSearchPath: aliasTestOk(aliasTestSearch)})
		if err := api.AliasUpdate("00000000-0000-0000-0000-000000000000", AliasFields{"description": "x"}); !coreapi.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
		// OPNsense answers "saved" for built-in aliases without changing them
		if err := api.AliasUpdate("bogons", AliasFields{"description": "x"}); err == nil || !strings.Contains(err.Error(), "built-in") {
			t.Errorf("want built-in error, got %v", err)
		}
		if posts := aliasTestPosts(calls()); len(posts) != 0 {
			t.Errorf("posts: %v", posts)
		}
	})
}

func TestAliasRemove(t *testing.T) {
	var delPath = "POST /api/firewall/alias/del_item/" + aliasTestUuid
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		aliasTestSearchPath: aliasTestOk(aliasTestSearch),
		delPath:             aliasTestOk(`{"result":"deleted"}`),
	})
	if err := api.AliasRemove(aliasTestUuid); err != nil {
		t.Fatal(err)
	}
	if posts := aliasTestPosts(calls()); len(posts) != 1 || posts[0].Path != strings.TrimPrefix(delPath, "POST ") {
		t.Errorf("posts: %v", posts)
	}

	t.Run("in use", func(t *testing.T) {
		var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{
			aliasTestSearchPath: aliasTestOk(aliasTestSearch),
			delPath: {Status: 500, Body: `{"errorMessage":"Cannot delete alias a8fw_hosts. Currently in use by \n[aliases.alias.` + aliasTestGroup +
				`] group","errorTitle":"Alias in use"}`},
		})
		var err = api.AliasRemove(aliasTestUuid)
		var httpErr *coreapi.HttpError
		if !errors.As(err, &httpErr) || !strings.Contains(err.Error(), "Currently in use") {
			t.Errorf("want the in use error, got %v", err)
		}
	})
	t.Run("built-in", func(t *testing.T) {
		var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{aliasTestSearchPath: aliasTestOk(aliasTestSearch)})
		if err := api.AliasRemove("__lan_network"); err == nil || !strings.Contains(err.Error(), "built-in") {
			t.Errorf("want built-in error, got %v", err)
		}
		if posts := aliasTestPosts(calls()); len(posts) != 0 {
			t.Errorf("posts: %v", posts)
		}
	})
}

func TestAliasSetEnabled(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		aliasTestSearchPath: aliasTestOk(aliasTestSearch),
		"POST /api/firewall/alias/toggle_item/" + aliasTestUuid + "/1":  aliasTestOk(`{"result":"Enabled","changed":true}`),
		"POST /api/firewall/alias/toggle_item/" + aliasTestGroup + "/0": aliasTestOk(`{"result":"failed"}`),
	})
	if changed, err := api.AliasSetEnabled(aliasTestUuid, true); err != nil || !changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if changed, err := api.AliasSetEnabled(aliasTestUuid, false); err != nil || changed {
		t.Errorf("already disabled: %v %v", changed, err)
	}
	if _, err := api.AliasSetEnabled(aliasTestGroup, false); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if _, err := api.AliasSetEnabled("bogons", false); err == nil {
		t.Error("built-in can not be toggled")
	}
	var posts = aliasTestPosts(calls())
	if len(posts) != 2 || posts[0].Body != "{}\n" {
		t.Errorf("posts: %v", posts)
	}
}

func TestAliasReconfigureAndUpdate(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"POST /api/firewall/alias/reconfigure":    aliasTestOk(`{"status":"ok"}`),
		"POST /api/firewall/alias/update/bogons":  aliasTestOk(`{"status":"ok","message":"Update completed"}`),
		"POST /api/firewall/alias/update/geoip":   aliasTestOk(`{"status":"failed","message":"Error updating action"}`),
		"GET /api/firewall/alias/list_categories": aliasTestOk(`{"rows":[{"uuid":"c1","name":"web","color":"ff0000","used":2}]}`),
	})
	if err := api.AliasReconfigure(); err != nil {
		t.Error(err)
	}
	if err := api.AliasUpdateTables("bogons"); err != nil {
		t.Error(err)
	}
	if err := api.AliasUpdateTables("geoip"); err == nil || !strings.Contains(err.Error(), "Error updating action") {
		t.Errorf("want failure, got %v", err)
	}
	if err := api.AliasUpdateTables("nope"); err == nil {
		t.Error("want an error")
	}
	if categories, err := api.AliasCategories(); err != nil || len(categories) != 1 || categories[0].Used != 2 {
		t.Errorf("categories %+v %v", categories, err)
	}
	for _, call := range aliasTestPosts(calls()) {
		if call.Body != "{}\n" {
			t.Errorf("%s needs a {} body, got %q", call.Path, call.Body)
		}
	}

	var failing, _ = aliasTestApi(t, map[string]aliasTestAnswer{"POST /api/firewall/alias/reconfigure": aliasTestOk(`{"status":"failed"}`)})
	if err := failing.AliasReconfigure(); err == nil {
		t.Error("want an error")
	}
}

func TestAliasLookups(t *testing.T) {
	var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{
		"GET /api/firewall/alias/list_countries":   aliasTestOk(`{"EU":{"name":"Unclassified","region":"Europe"},"NL":{"name":"Netherlands","region":"Europe"},"AQ":{"name":"Antarctica","region":null}}`),
		"GET /api/firewall/alias/list_user_groups": aliasTestOk(`{"2000":{"name":"vpn","gid":"2000"},"1999":{"name":"admins","gid":"1999"},"500":{"name":"x","gid":"500"}}`),
		"GET /api/firewall/alias/get_item":         aliasTestOk(`{"alias":{"interface":{"":{"value":"None","selected":1},"wan":{"value":"WAN","selected":0},"lan":{"value":"LAN","selected":0}},"name":""}}`),
	})
	var countries, err = api.AliasCountries()
	if err != nil || len(countries) != 3 || countries[0].Code != "AQ" || countries[0].Region != "" || countries[2] != (AliasCountry{"NL", "Netherlands", "Europe"}) {
		t.Errorf("countries %+v %v", countries, err)
	}
	groups, err := api.AliasUserGroups()
	if err != nil || len(groups) != 3 || groups[0].Gid != "500" || groups[1].Name != "admins" {
		t.Errorf("groups %+v %v", groups, err)
	}
	options, err := api.AliasFieldOptions("interface")
	if err != nil || !reflect.DeepEqual(options, []string{"lan", "wan"}) {
		t.Errorf("options %v %v", options, err)
	}
	if _, err := api.AliasFieldOptions("name"); err == nil {
		t.Error("name has no options")
	}

	var empty, _ = aliasTestApi(t, map[string]aliasTestAnswer{"GET /api/firewall/alias/list_user_groups": aliasTestOk(`[]`)})
	if groups, err := empty.AliasUserGroups(); err != nil || len(groups) != 0 {
		t.Errorf("no groups: %v %v", groups, err)
	}
}

func TestAliasExportImport(t *testing.T) {
	const export = `{
    "aliases": {
        "alias": {
            "` + aliasTestUuid + `": {"enabled": "0", "name": "a8fw_hosts", "type": "host", "content": "10.9.9.1\n10.9.9.2", "current_items": "", "eval_match": "", "description": "probe hosts"}
        }
    }
}`
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"GET /api/firewall/alias/export":  aliasTestOk(export),
		"POST /api/firewall/alias/import": aliasTestOk(`{"existing":1,"new":2,"status":"ok"}`),
	})
	var raw, err = api.AliasExport([]string{aliasTestUuid, aliasTestGroup})
	if err != nil || string(raw) != export {
		t.Fatalf("export %s %v", raw, err)
	}
	if got := calls()[0].Path; got != "/api/firewall/alias/export?ids="+aliasTestUuid+"%2C"+aliasTestGroup {
		t.Errorf("export path %s", got)
	}
	if _, err := api.AliasExport(nil); err != nil || calls()[1].Path != "/api/firewall/alias/export" {
		t.Errorf("full export: %v %v", err, calls()[1])
	}

	aliases, err := AliasParseExport(raw)
	if err != nil || len(aliases) != 1 || aliases[aliasTestUuid]["content"] != "10.9.9.1\n10.9.9.2" {
		t.Fatalf("parse %v %v", aliases, err)
	}
	result, err := api.AliasImport(aliases)
	if err != nil || result != (AliasImportResult{New: 2, Existing: 1}) {
		t.Fatalf("import %+v %v", result, err)
	}
	var body map[string]map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal([]byte(aliasTestPosts(calls())[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	var sent = body["data"]["aliases"]["alias"][aliasTestUuid]
	if sent["name"] != "a8fw_hosts" || sent["enabled"] != "0" || len(sent) != 5 {
		t.Errorf("volatile fields must be left out: %v", sent)
	}

	t.Run("validation", func(t *testing.T) {
		var api, _ = aliasTestApi(t, map[string]aliasTestAnswer{
			"POST /api/firewall/alias/import": aliasTestOk(`{"existing":0,"new":1,"status":"failed","validations":{"x1.content":"Entry \"nope\" is not a valid hostname, IP address or range."}}`),
		})
		var _, err = api.AliasImport(map[string]AliasFields{"x1": {"name": "a8fw_x", "type": "host", "content": "nope"}})
		var validation *coreapi.ValidationError
		if !errors.As(err, &validation) || validation.Validations["x1.content"] == "" {
			t.Errorf("want validation error, got %v", err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		var api, calls = aliasTestApi(t, nil)
		if _, err := api.AliasImport(nil); err == nil {
			t.Error("empty import")
		}
		if _, err := api.AliasImport(map[string]AliasFields{"x": {"type": "host"}}); err == nil {
			t.Error("alias without name")
		}
		if len(calls()) != 0 {
			t.Errorf("calls %v", calls())
		}
	})
	t.Run("parse", func(t *testing.T) {
		for input, want := range map[string]int{
			`{"aliases":{"alias":[]}}`:                                                           0,
			`{"geoip":{"url":""},"aliases":{"alias":{}}}`:                                        0,
			`{"aliases":{"alias":{"a":{"name":"x","enabled":1,"counters":true,"expire":null}}}}`: 1,
		} {
			if aliases, err := AliasParseExport([]byte(input)); err != nil || len(aliases) != want {
				t.Errorf("%s: %v %v", input, aliases, err)
			}
		}
		var aliases, _ = AliasParseExport([]byte(`{"aliases":{"alias":{"a":{"name":"x","enabled":1,"counters":true,"expire":null}}}}`))
		if !reflect.DeepEqual(aliases["a"], AliasFields{"name": "x", "enabled": "1", "counters": "1", "expire": ""}) {
			t.Errorf("values %v", aliases["a"])
		}
		for _, input := range []string{`[]`, `{}`, `nope`, `{"aliases":{"alias":"x"}}`, `{"aliases":{"alias":{"a":{"name":["x"]}}}}`} {
			if _, err := AliasParseExport([]byte(input)); err == nil {
				t.Errorf("%s: want an error", input)
			}
		}
	})
}

func TestAliasTables(t *testing.T) {
	var api, calls = aliasTestApi(t, map[string]aliasTestAnswer{
		"GET /api/firewall/alias_util/aliases":           aliasTestOk(`["bogons","a8fw_hosts","__lan_network"]`),
		"GET /api/firewall/alias_util/list/bogons":       aliasTestOk(`{"total":2,"rowCount":2,"current":1,"rows":[{"ip":"0.0.0.0\/8"},{"ip":"127.0.0.0\/8"}]}`),
		"GET /api/firewall/alias_util/list/a8fw_hosts":   aliasTestOk(`{"total":0,"rowCount":0,"current":1,"rows":[]}`),
		"GET /api/firewall/alias_util/list/nope":         aliasTestOk(`{"total":0,"rowCount":0,"current":1,"rows":[]}`),
		"GET /api/firewall/alias/get_table_size":         aliasTestOk(`{"status":"ok","size":3007500,"used":5,"details":{"bogons":{"count":2,"updated":"2026-10-25T10:00:00","eval_match":0},"__lan_network":{"count":1,"updated":null}}}`),
		"POST /api/firewall/alias_util/add/a8fw_hosts":   aliasTestOk(`{"status":"done"}`),
		"POST /api/firewall/alias_util/add/BAD":          aliasTestOk(`{"status":"not_an_address"}`),
		"POST /api/firewall/alias_util/add/nope":         aliasTestOk(`{"status":"failed","status_msg":"nonexistent alias nope"}`),
		"POST /api/firewall/alias_util/delete/bogons":    aliasTestOk(`{"status":"done"}`),
		"POST /api/firewall/alias_util/flush/a8fw_hosts": aliasTestOk(`{"status":"done"}`),
		"POST /api/firewall/alias_util/find_references":  aliasTestOk(`{"status":"ok","matches":["bogons","__lan_network"]}`),
	})
	if tables, err := api.AliasTables(); err != nil || len(tables) != 3 {
		t.Errorf("tables %v %v", tables, err)
	}
	if entries, err := api.AliasTableEntries("bogons"); err != nil || !reflect.DeepEqual(entries, []string{"0.0.0.0/8", "127.0.0.0/8"}) {
		t.Errorf("entries %v %v", entries, err)
	}
	if entries, err := api.AliasTableEntries("a8fw_hosts"); err != nil || len(entries) != 0 {
		t.Errorf("empty table %v %v", entries, err)
	}
	if _, err := api.AliasTableEntries("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	sizes, err := api.AliasTableSize()
	if err != nil || sizes.Size != 3007500 || sizes.Used != 5 || sizes.Details["bogons"] != (AliasTableStat{2, "2026-10-25T10:00:00"}) || sizes.Details["__lan_network"].Count != 1 {
		t.Errorf("sizes %+v %v", sizes, err)
	}

	if err := api.AliasTableAdd("a8fw_hosts", "10.0.0.1"); err != nil {
		t.Error(err)
	}
	if err := api.AliasTableAdd("BAD", "x"); err == nil || !strings.Contains(err.Error(), "not an address") {
		t.Errorf("want not an address, got %v", err)
	}
	if err := api.AliasTableAdd("nope", "10.0.0.1"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if err := api.AliasTableDelete("bogons", "10.0.0.0/8"); err != nil {
		t.Error(err)
	}
	if err := api.AliasTableFlush("a8fw_hosts"); err != nil {
		t.Error(err)
	}
	var before = len(aliasTestPosts(calls()))
	if err := api.AliasTableDelete("nope", "10.0.0.1"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if err := api.AliasTableFlush("nope"); !coreapi.IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
	if after := len(aliasTestPosts(calls())); after != before {
		t.Errorf("unknown tables must not be posted: %v", aliasTestPosts(calls())[before:])
	}
	matches, err := api.AliasFindReferences("192.168.1.10")
	if err != nil || !reflect.DeepEqual(matches, []string{"__lan_network", "bogons"}) {
		t.Errorf("matches %v %v", matches, err)
	}

	var bodies = map[string]string{}
	for _, call := range aliasTestPosts(calls()) {
		bodies[call.Path] = call.Body
	}
	for path, want := range map[string]string{
		"/api/firewall/alias_util/add/a8fw_hosts":   `{"address":"10.0.0.1"}`,
		"/api/firewall/alias_util/delete/bogons":    `{"address":"10.0.0.0/8"}`,
		"/api/firewall/alias_util/flush/a8fw_hosts": `{}`,
		"/api/firewall/alias_util/find_references":  `{"ip":"192.168.1.10"}`,
	} {
		if strings.TrimSpace(bodies[path]) != want {
			t.Errorf("%s: body %q, want %s", path, bodies[path], want)
		}
	}

	var broken, _ = aliasTestApi(t, map[string]aliasTestAnswer{
		"GET /api/firewall/alias_util/aliases":          aliasTestOk(`null`),
		"POST /api/firewall/alias_util/find_references": aliasTestOk(`{"status":"Not an IP address!"}`),
		"GET /api/firewall/alias/get_table_size":        aliasTestOk(`{"status":"failed"}`),
	})
	if _, err := broken.AliasTables(); err == nil {
		t.Error("null tables")
	}
	if _, err := broken.AliasFindReferences("x"); err == nil || !strings.Contains(err.Error(), "Not an IP address") {
		t.Errorf("want error, got %v", err)
	}
	if _, err := broken.AliasTableSize(); err == nil {
		t.Error("failed table size")
	}
}
