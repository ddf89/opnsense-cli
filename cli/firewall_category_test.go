package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	firewallCategorySearchPath = "/api/firewall/category/search_item"
	firewallCategoryAddPath    = "/api/firewall/category/add_item"
	firewallCategorySetPath    = "/api/firewall/category/set_item/"
	firewallCategoryDelPath    = "/api/firewall/category/del_item/"
)

// firewallCategoryRows are search_item rows as OPNsense 26.7 returns them (sorted by name)
func firewallCategoryRows() []map[string]any {
	return []map[string]any{
		{"uuid": "c-auto", "name": "from rules", "auto": "1", "color": ""},
		{"uuid": "c-web", "name": "web", "auto": "0", "color": "ff00AA"},
		{"uuid": "c-web2", "name": "web servers", "auto": "0", "color": ""},
	}
}

func firewallCategoryFake(t *testing.T, rows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallCategorySearchPath, rows...)
	return f
}

func TestFirewallCategoryPrint(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	var r = f.run("/firewall/category", "print")
	wantExit(t, r, 0)
	var want = []string{"#|NAME|COLOR|AUTO", "0|from rules|-|yes", "1|web|ff00AA|no", "2|web servers|-|no"}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}

	var searched = f.run("/firewall/category", "print", "search=serv")
	wantExit(t, searched, 0)
	if got := firewallGroupLines(searched.stdout); len(got) != 2 || !strings.Contains(got[1], "web servers") {
		t.Errorf("search: %q", got)
	}

	var asJSON = f.run("/firewall/category", "print", "json")
	wantExit(t, asJSON, 0)
	var lines = strings.Split(strings.TrimSpace(asJSON.stdout), "\n")
	var first map[string]any
	if len(lines) != 3 || json.Unmarshal([]byte(lines[0]), &first) != nil || first["auto"] != "1" {
		t.Errorf("want the raw rows, got %q", asJSON.stdout)
	}

	var detail = f.run("/firewall/category", "print", "detail")
	wantExit(t, detail, 0)
	wantContains(t, "stdout", detail.stdout, "uuid:", "c-web2", "color:", "ff00AA", "auto:")
	wantSearchPhrases(t, f, firewallCategorySearchPath, "", "serv", "", "")
	wantNoMutations(t, f)
}

func TestFirewallCategoryShow(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	for _, selector := range []string{"1", "c-web", "web", "WEB"} {
		var r = f.run("/firewall/category", "show", selector)
		wantExit(t, r, 0)
		var want = []string{"uuid:|c-web", "name:|web", "color:|ff00AA", "auto:|no"}
		if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
			t.Errorf("show %s:\n got  %q\n want %q", selector, got, want)
		}
	}
	wantFailure(t, f.run("/firewall/category", "show", "we"), "not found")
	wantNoMutations(t, f)
}

func TestFirewallCategoryAdd(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	f.on("POST", firewallCategoryAddPath, 200, answerAdded("c-new"))
	var r = f.run("/firewall/category", "add", "name=mail", "color=#00FF88")
	wantExit(t, r, 0)
	if r.stdout != "c-new\n" {
		t.Errorf("want the uuid on stdout, got %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", firewallCategoryAddPath), map[string]any{"category": map[string]any{"name": "mail", "color": "00FF88"}})
	wantSearchPhrases(t, f, firewallCategorySearchPath, "mail")

	t.Run("names are case-sensitive", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t, firewallCategoryRows()...)
		f.on("POST", firewallCategoryAddPath, 200, answerAdded("c-new"))
		wantExit(t, f.run("/firewall/category", "add", "name=Web"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallCategoryAddPath), map[string]any{"category": map[string]any{"name": "Web", "color": ""}})
	})

	t.Run("refused before any call", func(t *testing.T) {
		t.Parallel()
		for _, args := range [][]string{{}, {"name="}, {"name=a,b"}, {"name=x", "color=red"}, {"name=x", "color=#fff"}, {"name=x", "color=ff00001"}} {
			var f = firewallCategoryFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/category", "add"}, args...)...))
			wantNoCalls(t, f)
		}
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t, firewallCategoryRows()...)
		wantFailure(t, f.run("/firewall/category", "add", "name=web"), "exists already", "c-web", "replace")
		wantNoMutations(t, f)
	})

	t.Run("replace", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t, firewallCategoryRows()...)
		f.on("POST", firewallCategorySetPath+"c-web", 200, answerSaved)
		var r = f.run("/firewall/category", "add", "name=web", "replace")
		wantExit(t, r, 0)
		if r.stdout != "c-web\n" {
			t.Errorf("want the uuid on stdout, got %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", firewallCategorySetPath+"c-web"), map[string]any{"category": map[string]any{"name": "web", "color": ""}})
	})

	t.Run("validation error of OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t)
		f.on("POST", firewallCategoryAddPath, 200, answerValidation("category.name", "A category with this name already exists."))
		wantFailure(t, f.run("/firewall/category", "add", "name=x"), "category.name", "already exists")
	})
}

func TestFirewallCategorySet(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	f.on("POST", firewallCategorySetPath+"c-web2", 200, answerSaved)
	var r = f.run("/firewall/category", "set", "web servers", "color=a0b1c2")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("set must be silent: %q", r.stdout)
	}
	// the current name is always sent, a set_item without name would rename the category to "" in the rules
	wantJSON(t, wantOneMutation(t, f, "POST", firewallCategorySetPath+"c-web2"), map[string]any{"category": map[string]any{
		"name": "web servers", "color": "a0b1c2",
	}})

	t.Run("rename and clear the color", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t, firewallCategoryRows()...)
		f.on("POST", firewallCategorySetPath+"c-web", 200, answerSaved)
		wantExit(t, f.run("/firewall/category", "set", "1", "name=www", "color="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallCategorySetPath+"c-web"), map[string]any{"category": map[string]any{
			"name": "www", "color": "",
		}})
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallCategoryFake(t, firewallCategoryRows()...)
		wantFailure(t, f.run("/firewall/category", "set", "web"), "nothing to change")
		wantFailure(t, f.run("/firewall/category", "set", "web", "color=xyz"), "6 hex digits")
		wantFailure(t, f.run("/firewall/category", "set", "web", "name=a,b"), "commas")
		wantFailure(t, f.run("/firewall/category", "set", "nope", "color="), "not found")
		wantNoMutations(t, f)
	})
}

func TestFirewallCategoryRemove(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	f.on("POST", firewallCategoryDelPath+"c-web", 200, answerDeleted)
	var r = f.run("/firewall/category", "remove", "web")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", firewallCategoryDelPath+"c-web")

	var used = firewallCategoryFake(t, firewallCategoryRows()...)
	used.on("POST", firewallCategoryDelPath+"c-web", 500,
		`{"errorMessage":"Filter - allow web {Filter.rules.rule.d83fbe7e-09d5-410f-bc48-75ccb9a6858c}\n","errorTitle":"Item categories.category {web} in use by:"}`)
	wantFailure(t, used.run("/firewall/category", "remove", "web"), "in use by: Filter - allow web {Filter.rules.rule.d83fbe7e-09d5-410f-bc48-75ccb9a6858c}")

	var unknown = firewallCategoryFake(t, firewallCategoryRows()...)
	wantFailure(t, unknown.run("/firewall/category", "remove", "nope"), "not found")
	wantNoMutations(t, unknown)
}

func TestFirewallCategoryComplete(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t, firewallCategoryRows()...)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/firewall/category remove w":  {`"web servers"`, "web"},
		"/firewall/category set item=": {`item="from rules"`, `item="web servers"`, "item=web"},
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}

func TestFirewallCategoryHelp(t *testing.T) {
	t.Parallel()
	var f = firewallCategoryFake(t)
	var r = f.run("/firewall/category", "?")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "print", "show", "add", "set", "remove")
	wantNotContains(t, "stdout", r.stdout, "apply")
	wantNoCalls(t, f)
}
