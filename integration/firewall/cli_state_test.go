//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"strings"
	"testing"
)

// /firewall/state, /firewall/session and /firewall/statistics through the opn binary, read-only. Of the dropping
// commands only refusals that are decided before anything is sent are run, and with filters or ids matching no
// state (TEST-NET-3), so even a broken guard could not drop a connection. flush with the flag and flush-sources
// are never run live, not even unconfirmed

func TestCliStatePrint(t *testing.T) {
	var printed = mustOpn(t, "/firewall/state", "print")
	requireContains(t, printed, printed.stdout, "#", "INTERFACE", "PROTO", "SOURCE", "DESTINATION", "STATE", "AGE", "EXPIRES",
		"PACKETS", "BYTES", "RULE", "tcp")

	var top = mustOpn(t, "/firewall/state", "print", "protocol=tcp", "sort=bytes", "reverse", "limit=3")
	var lines = strings.Split(strings.TrimSpace(top.stdout), "\n")
	if len(lines) < 2 || len(lines) > 4 {
		t.Errorf("want a header and 1 to 3 states:\n%s", top)
	}
	for _, line := range lines[1:] {
		if !strings.Contains(line, " tcp ") {
			t.Errorf("protocol=tcp shows %q", line)
		}
	}

	var asJSON = mustOpn(t, "/firewall/state", "print", "json", "protocol=tcp")
	for _, line := range strings.Split(strings.TrimSpace(asJSON.stdout), "\n") {
		var state map[string]any
		if err := json.Unmarshal([]byte(line), &state); err != nil || state["proto"] != "tcp" || !stateIdPattern.MatchString(state["id"].(string)) {
			t.Errorf("not a raw TCP state: %q (%v)", line, err)
		}
	}

	var detail = mustOpn(t, "/firewall/state", "print", "detail", "limit=1")
	requireContains(t, detail, detail.stdout, "id:", "source:", "rule-id:")

	var none = mustOpn(t, "/firewall/state", "print", "src=203.0.113.0/24")
	if strings.Count(strings.TrimSpace(none.stdout), "\n") != 0 {
		t.Errorf("want only the header:\n%s", none)
	}

	var ids = mustOpn(t, "/firewall/state", "rule-ids")
	requireContains(t, ids, ids.stdout, "RULE-ID", "DESCRIPTION")
}

func TestCliStateRefusals(t *testing.T) {
	// decided by Check, before the confirmation
	var refused = mustFailOpn(t, "/firewall/state", "kill")
	requireContains(t, refused, refused.stderr, "at least one filter")
	refused = mustFailOpn(t, "/firewall/state", "flush")
	requireContains(t, refused, refused.stderr, "drop-own-connection")

	// not confirmed, and matching nothing anyway
	refused = mustFailOpn(t, "/firewall/state", "kill", "src=203.0.113.99")
	requireContains(t, refused, refused.stderr, "confirm=yes")
	refused = mustFailOpn(t, "/firewall/state", "remove", "ffffffffffffffff/ffffffff")
	requireContains(t, refused, refused.stderr, "confirm=yes")

	// the connections are still there
	mustOpn(t, "/firewall/state", "print", "limit=1")
}

func TestCliSessionPrint(t *testing.T) {
	var printed = mustOpn(t, "/firewall/session", "print", "limit=5")
	requireContains(t, printed, printed.stdout, "PROTO", "SOURCE", "GATEWAY", "RATE", "RULE")
	var lines = strings.Split(strings.TrimSpace(printed.stdout), "\n")
	if len(lines) < 2 || len(lines) > 6 {
		t.Errorf("want a header and 1 to 5 sessions:\n%s", printed)
	}

	var asJSON = mustOpn(t, "/firewall/session", "print", "json", "sort=age", "limit=2")
	for _, line := range strings.Split(strings.TrimSpace(asJSON.stdout), "\n") {
		var session map[string]any
		if err := json.Unmarshal([]byte(line), &session); err != nil || session["proto"] == nil || session["bytes"] == nil {
			t.Errorf("not a raw session: %q (%v)", line, err)
		}
	}
}

func TestCliStatisticsPrint(t *testing.T) {
	var printed = mustOpn(t, "/firewall/statistics", "print")
	requireContains(t, printed, printed.stdout, "info:", "memory:", "timeouts:", "interfaces:", "rules:",
		"state-table", "current-entries", "tcp.established", "REFERENCES", "filter")

	var memory = mustOpn(t, "/firewall/statistics", "print", "section=memory", "json")
	var decoded map[string]map[string]any
	if err := json.Unmarshal([]byte(memory.stdout), &decoded); err != nil || decoded["memory"]["states"] == nil {
		t.Errorf("want the raw memory section: %v\n%s", err, memory)
	}

	var states = mustOpn(t, "/firewall/statistics", "states")
	requireContains(t, states, states.stdout, "current:", "limit:", "used:", "%")
}
