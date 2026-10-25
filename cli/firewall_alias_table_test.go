package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Answers are shaped like OPNsense 26.7 (AliasUtilController, alias/get_table_size)

const (
	firewallAliasTablesPath    = "/api/firewall/alias_util/aliases"
	firewallAliasTableListPath = "/api/firewall/alias_util/list/"
	firewallAliasTableSizePath = "/api/firewall/alias/get_table_size"
	firewallAliasUtilPath      = "/api/firewall/alias_util/"
)

func firewallAliasTableFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", firewallAliasTablesPath, 200, `["a8fw_hosts","bogons","__lan_network"]`)
	f.on("GET", firewallAliasTableSizePath, 200, `{"status":"ok","size":3007500,"used":13,"details":{`+
		`"a8fw_hosts":{"count":2,"updated":null},"bogons":{"count":10,"updated":"2026-10-25T10:00:00.123456"},"__lan_network":{"count":1,"updated":null}}}`)
	f.on("GET", firewallAliasTableListPath+"bogons", 200, `{"total":2,"rowCount":2,"current":1,"rows":[{"ip":"0.0.0.0\/8"},{"ip":"127.0.0.0\/8"}]}`)
	f.on("GET", firewallAliasTableListPath+"a8fw_hosts", 200, `{"total":0,"rowCount":0,"current":1,"rows":[]}`)
	f.on("GET", firewallAliasTableListPath+"nope", 200, `{"total":0,"rowCount":0,"current":1,"rows":[]}`)
	return f
}

func TestFirewallAliasTablePrint(t *testing.T) {
	t.Parallel()
	var f = firewallAliasTableFake(t)
	var r = f.run("/firewall/alias/table", "print")
	wantExit(t, r, 0)
	var rows = systemBackupWantTable(t, r.stdout, []string{"NAME", "ENTRIES", "UPDATED"}, 0, "a8fw_hosts", "bogons", "__lan_network")
	if len(rows) == 4 && strings.Join(rows[2], "|") != "bogons|10|2026-10-25 10:00:00" {
		t.Errorf("row: %q", rows[2])
	}
	wantContains(t, "stderr", r.stderr, "13 of 3007500 table entries in use")
	wantNoMutations(t, f)

	r = f.run("/firewall/alias/table", "print", "json")
	wantExit(t, r, 0)
	var table map[string]any
	if err := json.Unmarshal([]byte(strings.Split(r.stdout, "\n")[1]), &table); err != nil || table["name"] != "bogons" || table["entries"] != float64(10) {
		t.Errorf("json %v %q", err, r.stdout)
	}

	r = f.run("/firewall/alias/table", "print", "bogons")
	wantExit(t, r, 0)
	systemBackupWantTable(t, r.stdout, []string{"ADDRESS"}, 0, "0.0.0.0/8", "127.0.0.0/8")

	r = f.run("/firewall/alias/table", "print", "alias=bogons", "json")
	wantExit(t, r, 0)
	if r.stdout != "{\"ip\":\"0.0.0.0/8\"}\n{\"ip\":\"127.0.0.0/8\"}\n" {
		t.Errorf("json %q", r.stdout)
	}

	wantExit(t, f.run("/firewall/alias/table", "print", "a8fw_hosts"), 0)
	wantFailure(t, f.run("/firewall/alias/table", "print", "nope"), "not found", "nope")
}

func TestFirewallAliasTableChanges(t *testing.T) {
	t.Parallel()
	t.Run("add", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasTableFake(t)
		f.on("POST", firewallAliasUtilPath+"add/a8fw_hosts", 200, `{"status":"done"}`)
		var r = f.run("/firewall/alias/table", "add", "a8fw_hosts", "address=FD00::1")
		wantExit(t, r, 0)
		if r.stdout != "" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasUtilPath+"add/a8fw_hosts"), map[string]any{"address": "fd00::1"})
	})
	t.Run("add to an unknown alias", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasTableFake(t)
		f.on("POST", firewallAliasUtilPath+"add/nope", 200, `{"status":"failed","status_msg":"nonexistent alias nope"}`)
		wantFailure(t, f.run("/firewall/alias/table", "add", "nope", "address=10.0.0.1"), "not found", "nonexistent alias nope")
	})
	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasTableFake(t)
		f.on("POST", firewallAliasUtilPath+"delete/bogons", 200, `{"status":"done"}`)
		wantExit(t, f.run("/firewall/alias/table", "remove", "bogons", "address=10.0.0.0/8"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasUtilPath+"delete/bogons"), map[string]any{"address": "10.0.0.0/8"})
	})
	t.Run("remove from an unknown table", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasTableFake(t)
		wantFailure(t, f.run("/firewall/alias/table", "remove", "nope", "address=10.0.0.1"), "not found", "nope")
		wantNoMutations(t, f)
	})
	t.Run("flush needs confirm", func(t *testing.T) {
		t.Parallel()
		var f = firewallAliasTableFake(t)
		f.on("POST", firewallAliasUtilPath+"flush/a8fw_hosts", 200, `{"status":"done"}`)
		wantFailure(t, f.run("/firewall/alias/table", "flush", "a8fw_hosts"), "confirm=yes")
		wantNoCalls(t, f)
		wantExit(t, f.run("/firewall/alias/table", "flush", "a8fw_hosts", "confirm=yes"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", firewallAliasUtilPath+"flush/a8fw_hosts"), map[string]any{})
	})
	for _, args := range [][]string{
		{"add", "bogons", "address=nope"},
		{"add", "bogons"},
		{"remove", "bogons", "address=10.0.0.1/33"},
		{"add", "address=10.0.0.1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var f = firewallAliasTableFake(t)
			wantFailure(t, f.run(append([]string{"/firewall/alias/table"}, args...)...))
			wantNoCalls(t, f)
		})
	}
}

func TestFirewallAliasTableFindAndUpdate(t *testing.T) {
	t.Parallel()
	var f = firewallAliasTableFake(t)
	f.onFunc("POST", firewallAliasUtilPath+"find_references", func(w http.ResponseWriter, r *http.Request) {
		var body, _ = io.ReadAll(r.Body)
		if strings.Contains(string(body), "10.99.99.99") {
			_, _ = w.Write([]byte(`{"status":"ok","matches":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","matches":["bogons","__lan_network"]}`))
	})
	f.on("POST", "/api/firewall/alias/update/bogons", 200, `{"status":"ok","message":"Update completed"}`)

	var r = f.run("/firewall/alias/table", "find", "192.168.1.10")
	wantExit(t, r, 0)
	if r.stdout != "__lan_network\nbogons\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	r = f.run("/firewall/alias/table", "find", "address=10.99.99.99")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "no alias table contains 10.99.99.99")
	wantFailure(t, f.run("/firewall/alias/table", "find", "nope"), "address")

	r = f.run("/firewall/alias/table", "update-bogons")
	wantExit(t, r, 0)
	systemBackupWantCalled(t, f, "POST", "/api/firewall/alias/update/bogons")
}
