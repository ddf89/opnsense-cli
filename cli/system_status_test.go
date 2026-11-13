package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	systemStatusPath        = "/api/core/system/status"
	systemStatusDismissPath = "/api/core/system/dismiss_status"

	systemStatusFirewallTime = 1762940000
)

// systemStatusAnswer is a trimmed copy of the 26.7.9 answer: the persistent disk notice of the dev boxes, a
// dismissable firewall notice with a two line message, the crash reporter and a notice without a page, in the
// order OPNsense sorted them
const systemStatusAnswer = `{"metadata":{"system":{"status":"ERROR","message":"No pending messages","title":"System"},` +
	`"translations":{"dialogTitle":"System Status","dialogCloseButton":"Close"},"subsystems":[]},"subsystems":{` +
	`"diskspace":{"title":"Disk Space","statusCode":-1,"message":"Disk space on the root filesystem is critically full (2.32G or 90% used, 258M available).","location":null,"timestamp":null,"persistent":true,"isBanner":false,"priority":5,"status":"ERROR"},` +
	`"firewall":{"title":"Firewall","statusCode":-1,"message":"There were error(s) loading the rules:\n/tmp/rules.debug:42: syntax error","location":"/ui/diagnostics/log/core/firewall","timestamp":1762940000,"persistent":false,"isBanner":false,"priority":20,"status":"ERROR","age":"2 hours ago"},` +
	`"crashreporter":{"title":"Crash Reporter","statusCode":0,"message":"An issue was detected and can be reviewed using the firmware crash reporter.","location":"/crash_reporter.php","timestamp":1762900000,"persistent":false,"isBanner":false,"priority":10,"status":"WARNING","age":"13 hours ago"},` +
	`"livemedia":{"title":"Live Media","statusCode":1,"message":"You are running the live media.","location":null,"timestamp":null,"persistent":false,"isBanner":true,"priority":2,"status":"NOTICE"}}}`

const systemStatusEmptyAnswer = `{"metadata":{"system":{"status":"OK","message":"No pending messages","title":"System"},"subsystems":[]},"subsystems":[]}`

func systemStatusFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", systemStatusPath, 200, systemStatusAnswer)
	f.on("POST", systemStatusDismissPath, 200, `{"status":"ok"}`)
	return f
}

func TestSystemStatusPrint(t *testing.T) {
	t.Parallel()
	var header = []string{"#", "SUBJECT", "SEVERITY", "TIME", "MESSAGE"}

	var f = systemStatusFake(t)
	var r = f.run("/system/status", "print")
	wantExit(t, r, 0)
	var rows = systemLoggingWantTable(t, r.stdout, header, 1, "diskspace", "firewall", "crashreporter", "livemedia")
	if len(rows) == 5 {
		var firewallTime = time.Unix(systemStatusFirewallTime, 0).Local().Format(time.DateTime)
		if got := strings.Join(rows[2][2:], "|"); got != "ERROR|"+firewallTime+"|There were error(s) loading the rules: /tmp/rules.debug:42: syntax error" {
			t.Errorf("firewall row (message on one line): %s", got)
		}
		if got := strings.Join(rows[1][2:4], "|"); got != "ERROR|-" {
			t.Errorf("diskspace row (no time): %s", got)
		}
	}
	wantNotContains(t, "stderr", r.stderr, "no pending")
	wantNoMutations(t, f)

	t.Run("detail", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		var r = f.run("/system/status", "print", "detail")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "subject:      firewall", "title:        Crash Reporter", "severity:     WARNING",
			"(2 hours ago)", "page:         /ui/diagnostics/log/core/firewall", "dismissable:  no", "dismissable:  yes",
			"/tmp/rules.debug:42: syntax error")
	})
	t.Run("json is the raw notices plus their subject", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		var r = f.run("/system/status", "print", "json")
		wantExit(t, r, 0)
		var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
		if len(lines) != 4 {
			t.Fatalf("want 4 lines:\n%s", r.stdout)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(lines[1]), &row); err != nil || row["subject"] != "firewall" ||
			row["location"] != "/ui/diagnostics/log/core/firewall" || row["statusCode"] != float64(-1) || row["age"] != "2 hours ago" {
			t.Errorf("line 1: %s (%v)", lines[1], err)
		}
	})
	t.Run("no notices", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemStatusPath, 200, systemStatusEmptyAnswer)
		var r = f.run("/system/status", "print")
		wantExit(t, r, 0)
		systemLoggingWantTable(t, r.stdout, header, 1)
		wantContains(t, "stderr", r.stderr, "no pending notices")
	})
	t.Run("not an OPNsense status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemStatusPath, 200, `{"status":"ok"}`)
		wantFailure(t, f.run("/system/status", "print"), "unexpected answer")
	})
}

func TestSystemStatusShow(t *testing.T) {
	t.Parallel()
	for _, item := range []string{"firewall", "FIREWALL", "Firewall", "1", "item=firewall"} {
		t.Run(item, func(t *testing.T) {
			t.Parallel()
			var f = systemStatusFake(t)
			var r = f.run("/system/status", "show", item)
			wantExit(t, r, 0)
			var fields = systemLoggingFields(r.stdout)
			for key, want := range map[string]string{
				"subject": "firewall", "title": "Firewall", "severity": "ERROR", "dismissable": "yes",
				"page": "/ui/diagnostics/log/core/firewall",
			} {
				if fields[key] != want {
					t.Errorf("%s: got %q, want %q\n%s", key, fields[key], want, r.stdout)
				}
			}
			wantNoMutations(t, f)
		})
	}
	t.Run("by title with a space", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		var r = f.run("/system/status", "show", "disk space")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "subject:      diskspace", "dismissable:  no")
	})
	for _, item := range []string{"pf", "4"} {
		t.Run("unknown "+item, func(t *testing.T) {
			t.Parallel()
			var f = systemStatusFake(t)
			wantFailure(t, f.run("/system/status", "show", item), "not found")
		})
	}
}

func TestSystemStatusDismiss(t *testing.T) {
	t.Parallel()
	for _, item := range []string{"firewall", "Firewall", "1"} {
		t.Run(item, func(t *testing.T) {
			t.Parallel()
			var f = systemStatusFake(t)
			var r = f.run("/system/status", "dismiss", item)
			wantExit(t, r, 0)
			if r.stdout != "" {
				t.Errorf("dismiss must be silent, got %q", r.stdout)
			}
			wantJSON(t, wantOneMutation(t, f, "POST", systemStatusDismissPath), map[string]any{"subject": "firewall"})
		})
	}
	t.Run("the # of the last print", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		var r = f.runScript("/system/status\nprint\ndismiss 2 confirm=yes\n")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemStatusDismissPath), map[string]any{"subject": "crashreporter"})
	})
	t.Run("crash reporter needs confirm, no mutation", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		wantFailure(t, f.run("/system/status", "dismiss", "crashreporter"), "deletes the crash reports", "confirm=yes")
		wantFailure(t, f.runScript("/system/status dismiss crashreporter\n"), "confirm=yes")
		wantNoMutations(t, f)
	})
	t.Run("crash reporter with confirm", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		wantExit(t, f.run("/system/status", "dismiss", "crashreporter", "confirm=yes"), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", systemStatusDismissPath), map[string]any{"subject": "crashreporter"})
	})
	for _, tc := range []struct {
		item  string
		wants []string
	}{
		{"diskspace", []string{"persistent", "cause is fixed"}},
		{"livemedia", []string{"no page"}},
		{"pf", []string{"not found"}},
	} {
		t.Run("refused locally: "+tc.item, func(t *testing.T) {
			t.Parallel()
			var f = systemStatusFake(t)
			var r = f.run("/system/status", "dismiss", tc.item, "confirm=yes")
			wantFailure(t, r, tc.wants...)
			wantNoMutations(t, f)
			// the refusal comes before a confirmation would be asked
			r = f.run("/system/status", "dismiss", tc.item)
			wantFailure(t, r, tc.wants...)
			wantNotContains(t, "stderr", r.stderr, "confirm=yes")
		})
	}
	t.Run("refused by OPNsense", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", systemStatusPath, 200, systemStatusAnswer)
		f.on("POST", systemStatusDismissPath, 200, `{"status":"failed"}`)
		wantFailure(t, f.run("/system/status", "dismiss", "firewall"), "did not dismiss", "firewall")
	})
	t.Run("no item, no API call", func(t *testing.T) {
		t.Parallel()
		var f = systemStatusFake(t)
		wantFailure(t, f.run("/system/status", "dismiss"), "item")
		wantNoCalls(t, f)
	})
}

func TestSystemStatusComplete(t *testing.T) {
	t.Parallel()
	var f = systemStatusFake(t)
	var session = fakeSession(t, f)
	for line, want := range map[string][]string{
		"/system/status show ":      {"crashreporter", "diskspace", "firewall", "item=", "livemedia"},
		"/system/status show d":     {"diskspace"},
		"/system/status dismiss ":   {"confirm", "crashreporter", "firewall", "item="},
		"/system/status dismiss f":  {"firewall"},
		"/system/status dismiss di": nil,
	} {
		if got, _ := session.Complete(line); !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	wantNoMutations(t, f)
}
