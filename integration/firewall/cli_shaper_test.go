//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCliShaper drives /firewall/shaper/pipe, queue and rule through the binary. Every add carries disabled, rules
// only match documentation networks, and reconfigure / flush-reload are never run
func TestCliShaper(t *testing.T) {
	var core = coreApi(t)
	var pipeDescription, queueDescription, ruleDescription = testDescription("shaper-cli-pipe"), testDescription("shaper-cli-queue"),
		testDescription("shaper-cli-rule")

	// client side validation sends nothing
	mustFailOpn(t, "/firewall/shaper/pipe", "add", "bandwidth=5Gbit", "description="+pipeDescription, "disabled")
	mustFailOpn(t, "/firewall/shaper/pipe", "add", "bandwidth=10Mbit", "codel", "pie", "description="+pipeDescription, "disabled")

	var added = mustOpn(t, "/firewall/shaper/pipe", "add", "bandwidth=10Mbit", "scheduler=fq_codel", "mask=src-ip",
		"description="+pipeDescription, "disabled")
	var pipe = uuidFrom(t, added)
	shaperCleanup(t, core, "pipe", pipe)
	if strings.TrimSpace(added.stdout) != pipe {
		t.Errorf("add must print only the uuid:\n%s", added)
	}
	var rows = shaperRawRows(t, core, "pipe", pipe)
	if len(rows) != 1 || rows[0]["enabled"] != "0" || rows[0]["bandwidth"] != "10" || rows[0]["bandwidthMetric"] != "Mbit" ||
		rows[0]["scheduler"] != "fq_codel" || rows[0]["mask"] != "src-ip" {
		t.Fatalf("unexpected pipe: %v", rows)
	}

	var queue = uuidFrom(t, mustOpn(t, "/firewall/shaper/queue", "add", "pipe="+pipeDescription, "weight=30",
		"description="+queueDescription, "disabled"))
	shaperCleanup(t, core, "queue", queue)
	if rows = shaperRawRows(t, core, "queue", queue); len(rows) != 1 || rows[0]["pipe"] != pipe || rows[0]["enabled"] != "0" || rows[0]["weight"] != "30" {
		t.Fatalf("unexpected queue: %v", rows)
	}

	// unknown interface and target are refused before anything is sent
	mustFailOpn(t, "/firewall/shaper/rule", "add", "target="+queueDescription, "interface=opt99", "disabled")
	mustFailOpn(t, "/firewall/shaper/rule", "add", "target="+runPrefix+" no such queue", "interface=lan", "disabled")

	var rule = uuidFrom(t, mustOpn(t, "/firewall/shaper/rule", "add", "target="+queueDescription, "interface=LAN", "protocol=udp",
		"source=192.0.2.0/24", "destination=198.51.100.0/24", "destination-port=5060", "dscp=ef", "direction=in",
		"description="+ruleDescription, "disabled"))
	shaperCleanup(t, core, "rule", rule)
	if rows = shaperRawRows(t, core, "rule", rule); len(rows) != 1 || rows[0]["target"] != queue || rows[0]["interface"] != "lan" ||
		rows[0]["enabled"] != "0" || rows[0]["source"] != "192.0.2.0/24" || rows[0]["dst_port"] != "5060" || rows[0]["sequence"] == "" {
		t.Fatalf("unexpected rule: %v", rows)
	}

	// duplicates by description
	var duplicate = mustFailOpn(t, "/firewall/shaper/pipe", "add", "bandwidth=1Mbit", "description="+pipeDescription, "disabled")
	requireContains(t, duplicate, duplicate.stderr, "exists", pipe)

	// print, show, json
	var printed = mustOpn(t, "/firewall/shaper/pipe", "print", "search="+pipeDescription)
	requireContains(t, printed, printed.stdout, "DISABLED", "BANDWIDTH", "10 Mbit/s", "fq_codel", pipeDescription)
	printed = mustOpn(t, "/firewall/shaper/queue", "print", "search="+queueDescription)
	requireContains(t, printed, printed.stdout, pipeDescription, "30", queueDescription)
	printed = mustOpn(t, "/firewall/shaper/rule", "print", "search="+ruleDescription)
	// the interface column shows the description of lan, or lan when it has none
	requireContains(t, printed, strings.ToLower(printed.stdout), " lan ")
	requireContains(t, printed, printed.stdout, "udp", "192.0.2.0/24", "198.51.100.0/24 port 5060", "in", queueDescription)
	var shown = mustOpn(t, "/firewall/shaper/rule", "show", ruleDescription)
	requireContains(t, shown, shown.stdout, "uuid:", rule, "dscp:", "ef", "disabled:", "yes")
	var asJSON = mustOpn(t, "/firewall/shaper/queue", "print", "json", "search="+queueDescription)
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(asJSON.stdout)), &row); err != nil || row["uuid"] != queue {
		t.Errorf("want one raw JSON row: %v\n%s", err, asJSON)
	}

	// set changes only the given fields
	requireNoStdout(t, mustOpn(t, "/firewall/shaper/pipe", "set", pipeDescription, "bandwidth=2Mbit", "delay=10"))
	if rows = shaperRawRows(t, core, "pipe", pipe); rows[0]["bandwidth"] != "2" || rows[0]["delay"] != "10" || rows[0]["scheduler"] != "fq_codel" ||
		rows[0]["enabled"] != "0" {
		t.Errorf("unexpected pipe after set: %v", rows[0])
	}
	requireNoStdout(t, mustOpn(t, "/firewall/shaper/rule", "set", ruleDescription, "target="+pipeDescription, "source-invert"))
	if rows = shaperRawRows(t, core, "rule", rule); rows[0]["target"] != pipe || rows[0]["source_not"] != "1" || rows[0]["proto"] != "udp" {
		t.Errorf("unexpected rule after set: %v", rows[0])
	}
	mustFailOpn(t, "/firewall/shaper/rule", "set", "0f0f0f0f-1111-4222-8333-a8f0a8f0a8f0", "description=x")

	// replace keeps the uuid and resets the other fields, still disabled
	var replaced = mustOpn(t, "/firewall/shaper/queue", "add", "pipe="+pipe, "description="+queueDescription, "disabled", "replace")
	if uuidFrom(t, replaced) != queue {
		t.Errorf("replace must reuse %s:\n%s", queue, replaced)
	}
	if rows = shaperRawRows(t, core, "queue", queue); rows[0]["weight"] != "100" || rows[0]["enabled"] != "0" {
		t.Errorf("unexpected queue after replace: %v", rows[0])
	}

	var disabled = mustOpn(t, "/firewall/shaper/rule", "disable", ruleDescription)
	requireContains(t, disabled, disabled.stderr, "already disabled")

	// the pipe is still used by the rule
	var inUse = mustFailOpn(t, "/firewall/shaper/pipe", "remove", pipeDescription)
	requireContains(t, inUse, inUse.stderr, "in use by")

	// statistics are read only
	mustOpn(t, "/firewall/shaper", "status")
	mustOpn(t, "/firewall/shaper", "status", "json")

	for _, step := range []struct{ menu, item, kind, uuid string }{
		{"/firewall/shaper/rule", ruleDescription, "rule", rule},
		{"/firewall/shaper/queue", queueDescription, "queue", queue},
		{"/firewall/shaper/pipe", pipeDescription, "pipe", pipe},
	} {
		requireNoStdout(t, mustOpn(t, step.menu, "remove", step.item))
		if rows = shaperRawRows(t, core, step.kind, step.uuid); len(rows) != 0 {
			t.Errorf("%s still there after remove: %v", step.kind, rows)
		}
	}
}
