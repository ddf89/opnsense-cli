package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	systemUserApiKeyAddPath = "/api/auth/user/add_api_key/"
	systemUserApiKeyDelPath = "/api/auth/user/del_api_key/"
	systemUserApiKeyCreated = `{"result":"ok","hostname":"OPNsense.internal","key":"bmV3a2V5","secret":"bmV3c2VjcmV0"}`
)

func TestSystemUserApiKeyPrint(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	var r = f.run("/system/user/api-key", "print")
	wantExit(t, r, 0)
	var want = []string{"#|USER|KEY|IN-USE", "0|root|cm9vdGtleQ==|-", "1|automation|" + testApiKey + "|yes", "2|alice|YWxpY2VrZXk=|-"}
	if got := firewallGroupLines(r.stdout); !reflect.DeepEqual(got, want) {
		t.Errorf("print:\n got  %q\n want %q", got, want)
	}
	var mine = f.run("/system/user/api-key", "print", "user=ALICE", "json")
	wantExit(t, mine, 0)
	if mine.stdout != `{"id":"WVd4cFkyVnJaWGs9","key":"YWxpY2VrZXk=","username":"alice"}`+"\n" {
		t.Errorf("json: %q", mine.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemUserApiKeyAdd(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	f.on("POST", systemUserApiKeyAddPath+"alice", 200, systemUserApiKeyCreated)
	var r = f.run("/system/user/api-key", "add", "alice")
	wantExit(t, r, 0)
	if r.stdout != "key=bmV3a2V5\nsecret=bmV3c2VjcmV0\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "only this once")
	wantOneMutation(t, f, "POST", systemUserApiKeyAddPath+"alice")

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		f.on("POST", systemUserApiKeyAddPath+"alice", 200, systemUserApiKeyCreated)
		var dir = t.TempDir()
		var file = filepath.Join(dir, "apikey.txt")
		var r = f.run("/system/user/api-key", "add", "user=alice", "file="+file)
		wantExit(t, r, 0)
		if r.stdout != "key=bmV3a2V5\n" {
			t.Errorf("only the key goes to stdout, got %q", r.stdout)
		}
		var content, err = os.ReadFile(file)
		if err != nil || string(content) != "key=bmV3a2V5\nsecret=bmV3c2VjcmV0\n" {
			t.Errorf("file: %q / %v", content, err)
		}
		if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", info.Mode())
		}

		// an existing file is refused before the key is created
		wantFailure(t, f.run("/system/user/api-key", "add", "alice", "file="+file), "exists already", "overwrite")
		if len(f.mutations()) != 1 {
			t.Errorf("unexpected mutations %v", f.mutations())
		}
		_ = os.Chmod(file, 0o644)
		wantExit(t, f.run("/system/user/api-key", "add", "alice", "file="+file, "overwrite"), 0)
		if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
			t.Errorf("mode after overwrite %v", info.Mode())
		}
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		wantFailure(t, f.run("/system/user/api-key", "add"), "user=<string> is required")
		wantFailure(t, f.run("/system/user/api-key", "add", "alice", "overwrite"), "file=")
		wantFailure(t, f.run("/system/user/api-key", "add", "ghost"), "not found")
		wantNoMutations(t, f)
	})

	t.Run("failed", func(t *testing.T) {
		t.Parallel()
		var f = systemUserFake(t)
		f.on("POST", systemUserApiKeyAddPath+"alice", 200, `{"result":"failed"}`)
		wantFailure(t, f.run("/system/user/api-key", "add", "alice"), "failed")
	})
}

func TestSystemUserApiKeyRemove(t *testing.T) {
	t.Parallel()
	var f = systemUserFake(t)
	wantFailure(t, f.run("/system/user/api-key", "remove", "2"), "confirm=yes")
	wantNoCalls(t, f)

	f.on("POST", systemUserApiKeyDelPath+"WVd4cFkyVnJaWGs9", 200, answerDeleted)
	wantExit(t, f.run("/system/user/api-key", "remove", "item=YWxpY2VrZXk=", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", systemUserApiKeyDelPath+"WVd4cFkyVnJaWGs9")

	// the key of this connection is never removed
	for _, selector := range []string{"1", testApiKey, "item=dGVzdC1rZXk="} {
		var r = f.run("/system/user/api-key", "remove", selector, "confirm=yes")
		wantFailure(t, r, "refusing", "automation")
	}
	if len(f.mutations()) != 1 {
		t.Errorf("unexpected mutations %v", f.mutations())
	}
	var help = runOpn(t, nil, "/system/user/api-key", "remove", "?")
	wantContains(t, "help", strings.Join(strings.Fields(help.stdout), " "), "refuses to remove the key it uses")
}
