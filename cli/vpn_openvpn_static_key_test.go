package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	openvpnStaticKeySearchPath = "/api/openvpn/instances/search_static_key"
	openvpnStaticKeyAddPath    = "/api/openvpn/instances/add_static_key"
	openvpnStaticKeySetPath    = "/api/openvpn/instances/set_static_key/"
	openvpnStaticKeyDelPath    = "/api/openvpn/instances/del_static_key/"
	openvpnStaticKeyGenPath    = "/api/openvpn/instances/gen_key/"

	openvpnStaticKeyTestKey = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n" +
		"0123456789abcdef0123456789abcdef\nfedcba9876543210fedcba9876543210\n-----END OpenVPN Static key V1-----"
	openvpnStaticKeyNewKey = "#\n-----BEGIN OpenVPN Static key V1-----\nnewnewnewnew\n-----END OpenVPN Static key V1-----"
)

func openvpnStaticKeyRows() []map[string]any {
	return []map[string]any{
		{"uuid": "k-office", "description": "office key", "mode": "crypt", "%mode": "crypt (Encrypt and authenticate all control channel packets)", "key": openvpnStaticKeyTestKey},
		{"uuid": "k-old", "description": "old key", "mode": "auth", "%mode": "auth (Authenticate control channel packets)", "key": openvpnStaticKeyTestKey},
		{"uuid": "k-d1", "description": "dup", "mode": "auth", "%mode": "auth (...)", "key": openvpnStaticKeyTestKey},
		{"uuid": "k-d2", "description": "dup", "mode": "auth", "%mode": "auth (...)", "key": openvpnStaticKeyTestKey},
	}
}

// openvpnStaticKeyFake serves the keys and two instances, "office" uses "office key"
func openvpnStaticKeyFake(t *testing.T, keys ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(openvpnStaticKeySearchPath, keys...)
	f.search(openvpnInstanceSearchPath,
		openvpnInstanceRow(map[string]any{"uuid": "i-office", "description": "office", "tls_key": "k-office"}),
		openvpnInstanceRow(map[string]any{"uuid": "i-home", "description": "home"}))
	var answer, _ = json.Marshal(map[string]string{"result": "ok", "key": openvpnStaticKeyNewKey})
	for _, keyType := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2-server"} {
		f.on("GET", openvpnStaticKeyGenPath+keyType, 200, string(answer))
	}
	return f
}

func TestOpenvpnStaticKeyPrint(t *testing.T) {
	t.Parallel()
	var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
	var r = f.run("/vpn/openvpn/static-key", "print")
	wantExit(t, r, 0)
	var rows = systemCronWantTable(t, r.stdout, []string{"#", "DESCRIPTION", "MODE", "USED-BY"}, 1, "office key", "old key", "dup", "dup")
	if len(rows) > 1 {
		if got := strings.Join(rows[1], "|"); got != "0|office key|crypt|office" {
			t.Errorf("row 0: %q", got)
		}
	}
	wantNotContains(t, "stdout", r.stdout, "BEGIN", "0123456789abcdef")
	wantNoMutations(t, f)

	t.Run("detail has no key material", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		var r = f.run("/vpn/openvpn/static-key", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "0\n  uuid:         k-office\n  description:  office key\n  mode:         crypt\n  used-by:      office\n")
		wantNotContains(t, "stdout", r.stdout, "BEGIN", "0123456789abcdef")
	})
	t.Run("json has the raw rows with the key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		var r = f.run("/vpn/openvpn/static-key", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 4 {
			t.Fatalf("want 4 lines:\n%s", r.stdout)
		}
		wantContains(t, "json", lines[0], `"uuid":"k-office"`, `"key":"#\n# 2048 bit`, `"%mode":"crypt (`)
	})
	t.Run("search", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantExit(t, f.run("/vpn/openvpn/static-key", "print", "search=old"), 0)
		wantSearchPhrases(t, f, openvpnStaticKeySearchPath, "old")
	})
}

func TestOpenvpnStaticKeyShow(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{"k-office", "Office Key", "0"} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
			var r = f.run("/vpn/openvpn/static-key", "show", selector)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, "uuid:         k-office\n", "description:  office key\n", "mode:         crypt\n", "used-by:      office\n",
				"key:\n  #\n  # 2048 bit OpenVPN static key\n", "  0123456789abcdef0123456789abcdef\n", "  -----END OpenVPN Static key V1-----\n")
		})
	}
	t.Run("ambiguous", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "show", "dup"), "k-d1", "k-d2")
	})
}

func TestOpenvpnStaticKeyAdd(t *testing.T) {
	t.Parallel()
	for mode, keyType := range map[string]string{"": "tls-crypt", "auth": "tls-auth", "CRYPT-V2": "tls-crypt-v2-server"} {
		t.Run("generates a "+keyType+" key", func(t *testing.T) {
			t.Parallel()
			var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
			f.on("POST", openvpnStaticKeyAddPath, 200, answerAdded("k-new"))
			var args = []string{"/vpn/openvpn/static-key", "add", "description=new key"}
			if mode != "" {
				args = append(args, "mode="+mode)
			}
			var r = f.run(args...)
			wantExit(t, r, 0)
			if r.stdout != "k-new\n" {
				t.Errorf("stdout %q, want the uuid", r.stdout)
			}
			var wantMode = map[string]string{"": "crypt", "auth": "auth", "CRYPT-V2": "crypt-v2"}[mode]
			wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeyAddPath), map[string]any{"statickey": map[string]any{
				"description": "new key", "mode": wantMode, "key": openvpnStaticKeyNewKey}})
			var generated bool
			for _, call := range f.calls() {
				generated = generated || call.Method == "GET" && call.Path == openvpnStaticKeyGenPath+keyType
			}
			if !generated {
				t.Errorf("no GET %s%s: %v", openvpnStaticKeyGenPath, keyType, f.calls())
			}
		})
	}
	t.Run("given key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeyAddPath, 200, answerAdded("k-new"))
		wantExit(t, f.run("/vpn/openvpn/static-key", "add", "description=imported", "mode=auth", "key="+openvpnStaticKeyTestKey+"\n"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeyAddPath), map[string]any{"statickey": map[string]any{
			"description": "imported", "mode": "auth", "key": openvpnStaticKeyTestKey}})
		for _, call := range f.calls() {
			if strings.HasPrefix(call.Path, openvpnStaticKeyGenPath) {
				t.Errorf("a given key must not be generated: %v", call)
			}
		}
	})
	t.Run("key file", func(t *testing.T) {
		t.Parallel()
		var path = filepath.Join(t.TempDir(), "ta.key")
		if err := os.WriteFile(path, []byte(openvpnStaticKeyTestKey+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeyAddPath, 200, answerAdded("k-new"))
		wantExit(t, f.run("/vpn/openvpn/static-key", "add", "description=file", "key-file="+path), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeyAddPath), map[string]any{"statickey": map[string]any{
			"description": "file", "mode": "crypt", "key": openvpnStaticKeyTestKey}})
	})
	t.Run("missing key file", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "add", "description=file", "key-file=/nonexistent/ta.key"), "key-file")
		wantNoMutations(t, f)
	})
	t.Run("existing description", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "add", "description=OLD KEY"), "exists already", "k-old")
		wantNoMutations(t, f)
	})
	t.Run("replace generates a new key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeySetPath+"k-old", 200, answerSaved)
		var r = f.run("/vpn/openvpn/static-key", "add", "description=old key", "replace")
		wantExit(t, r, 0)
		if r.stdout != "k-old\n" {
			t.Errorf("stdout %q", r.stdout)
		}
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeySetPath+"k-old"), map[string]any{"statickey": map[string]any{
			"description": "old key", "mode": "crypt", "key": openvpnStaticKeyNewKey}})
	})
	t.Run("generation fails", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t)
		f.on("GET", openvpnStaticKeyGenPath+"tls-crypt", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "add", "description=x"), "generating a tls-crypt key failed")
		wantNoMutations(t, f)
	})
	for name, args := range map[string][]string{
		"no description":     {"mode=auth"},
		"empty description":  {"description= "},
		"mode":               {"description=x", "mode=v3"},
		"key characters":     {"description=x", "key=abc!"},
		"empty key":          {"description=x", "key="},
		"key and key-file":   {"description=x", "key=abc", "key-file=/tmp/x"},
		"control characters": {"description=a\tb"},
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()
			var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
			wantFailure(t, f.run(append([]string{"/vpn/openvpn/static-key", "add"}, args...)...))
			wantNoCalls(t, f)
		})
	}
}

func TestOpenvpnStaticKeySet(t *testing.T) {
	t.Parallel()
	var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
	f.on("POST", openvpnStaticKeySetPath+"k-old", 200, answerSaved)
	var r = f.run("/vpn/openvpn/static-key", "set", "old key", "description=older key")
	wantExit(t, r, 0)
	if r.stdout != "" || r.stderr != "" {
		t.Errorf("set must be silent:\n%s", r)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeySetPath+"k-old"), map[string]any{"statickey": map[string]any{"description": "older key"}})

	t.Run("regenerate with the new mode", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeySetPath+"k-old", 200, answerSaved)
		wantExit(t, f.run("/vpn/openvpn/static-key", "set", "k-old", "mode=crypt-v2", "regenerate"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeySetPath+"k-old"), map[string]any{"statickey": map[string]any{
			"mode": "crypt-v2", "key": openvpnStaticKeyNewKey}})
		wantSearchPhrases(t, f, openvpnStaticKeySearchPath, "", "")
	})
	t.Run("regenerate with the current mode", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeySetPath+"k-old", 200, answerSaved)
		wantExit(t, f.run("/vpn/openvpn/static-key", "set", "k-old", "regenerate"), 0)
		var generated bool
		for _, call := range f.calls() {
			generated = generated || call.Path == openvpnStaticKeyGenPath+"tls-auth"
		}
		if !generated {
			t.Errorf("want a tls-auth key generated: %v", f.calls())
		}
	})
	t.Run("a mode change without a new key warns", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		f.on("POST", openvpnStaticKeySetPath+"k-old", 200, answerSaved)
		var r = f.run("/vpn/openvpn/static-key", "set", "k-old", "mode=crypt")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "regenerate")
		wantJSON(t, wantOneMutation(t, f, "POST", openvpnStaticKeySetPath+"k-old"), map[string]any{"statickey": map[string]any{"mode": "crypt"}})
	})
	t.Run("rename onto another key", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "set", "old key", "description=office KEY"), "k-office")
		wantNoMutations(t, f)
	})
	t.Run("key and regenerate", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "set", "old key", "key=abc", "regenerate"), "only one of")
		wantNoCalls(t, f)
	})
	t.Run("nothing to change", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "set", "old key", "regenerate=no"), "nothing to change")
		wantNoCalls(t, f)
	})
}

func TestOpenvpnStaticKeyRemove(t *testing.T) {
	t.Parallel()
	var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
	f.on("POST", openvpnStaticKeyDelPath+"k-old", 200, answerDeleted)
	var r = f.run("/vpn/openvpn/static-key", "remove", "old key")
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("remove must be silent: %q", r.stdout)
	}
	wantOneMutation(t, f, "POST", openvpnStaticKeyDelPath+"k-old")

	t.Run("refused while in use", func(t *testing.T) {
		t.Parallel()
		var f = openvpnStaticKeyFake(t, openvpnStaticKeyRows()...)
		wantFailure(t, f.run("/vpn/openvpn/static-key", "remove", "office key"), "used by", "office")
		wantNoMutations(t, f)
	})
}
