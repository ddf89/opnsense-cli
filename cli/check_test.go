package cli

import (
	"strings"
	"testing"
)

const checkTestInfo = `{"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD 15.1-RELEASE-p1"],"updates":""}`

func TestCheck(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/system/system_information", 200, checkTestInfo)

	var r = f.run("/check")
	wantExit(t, r, 0)
	for _, want := range []string{"status:", "ok", "hostname:", "fw.example.com", "OPNsense 26.7-amd64, FreeBSD 15.1-RELEASE-p1",
		"not verified (OPN_NOSSLVERIFY=1)", "HTTP/", "latency:"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output misses %q\n%s", want, r)
		}
	}
	wantNoMutations(t, f)
}

func TestCheckJSON(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", "/api/diagnostics/system/system_information", 200, checkTestInfo)

	var r = f.run("check", "json")
	wantExit(t, r, 0)
	for _, want := range []string{`"status":"ok"`, `"hostname":"fw.example.com"`, `"tls":"not verified"`, `"latency_ms":`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("json misses %q\n%s", want, r)
		}
	}
}

func TestCheckFailures(t *testing.T) {
	t.Run("wrong secret", func(t *testing.T) {
		var f = newFakeOPN(t)
		var env = []string{"OPN_URL=" + f.srv.URL, "OPN_APIKEY=" + testApiKey, "OPN_APISECRET=wrong", "OPN_NOSSLVERIFY=1"}
		var r = runOpn(t, env, "/check")
		wantFailure(t, r, "auth: authentication failed", "OPN_APISECRET")
	})

	t.Run("not an OPNsense API", func(t *testing.T) {
		var f = newFakeOPN(t) // unknown endpoints answer an empty 200
		wantFailure(t, f.run("/check"), "api: no OPNsense API answer")
	})

	t.Run("no configuration", func(t *testing.T) {
		wantFailure(t, runOpn(t, nil, "/check"), "OPN_URL")
	})

	t.Run("invalid timeout sends nothing", func(t *testing.T) {
		var f = newFakeOPN(t)
		wantFailure(t, f.run("/check", "timeout=0"), "timeout")
		if calls := f.calls(); len(calls) != 0 {
			t.Errorf("sent %d requests, want none", len(calls))
		}
	})
}
