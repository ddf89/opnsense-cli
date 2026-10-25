//go:build integration

package integrationfirewall

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// Filter rule tests only create disabled LAN rules blocking to 198.51.100.0/24 (TEST-NET-2), never enable, apply,
// savepoint or revert anything, and only move their own rules before their own rules (which stay behind the
// existing rules). The rollback / apply path is tested with fakes only

func ruleTestApi(t *testing.T) *firewall.FirewallApi {
	t.Helper()
	return &firewall.FirewallApi{OPNsense: coreApi(t)}
}

// ruleTestFields are the fields of a harmless test rule
func ruleTestFields(label string) firewall.FilterRuleFields {
	return firewall.FilterRuleFields{
		"enabled": "0", "action": "block", "interface": "lan", "direction": "in", "ipprotocol": "inet", "protocol": "any",
		"source_net": "any", "destination_net": "198.51.100.0/24", "description": testDescription(label),
	}
}

// ruleCreate creates a harmless test rule and registers its removal
func ruleCreate(t *testing.T, fw *firewall.FirewallApi, label string) (string, firewall.FilterRuleFields) {
	t.Helper()
	var fields = ruleTestFields(label)
	var uuid, err = fw.FilterRuleCreate(fields)
	if err != nil {
		t.Fatalf("FilterRuleCreate(%v): %v", fields, err)
	}
	if !firewall.FilterIsUuid(uuid) {
		t.Fatalf("FilterRuleCreate returned %q, not a uuid", uuid)
	}
	ruleCleanup(t, fw, uuid)
	return uuid, fields
}

// ruleCleanup removes the rule uuid when the test ends and verifies it is gone
func ruleCleanup(t *testing.T, fw *firewall.FirewallApi, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := fw.FilterRuleRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of filter rule %s failed: %v", uuid, err)
		}
		if _, err := fw.FilterRuleGet(uuid); !api.IsNotFound(err) {
			t.Errorf("filter rule %s is still there after the cleanup: %v", uuid, err)
		}
	})
}

// ruleOwnRows returns this run's rules (by description prefix) in evaluation order
func ruleOwnRows(t *testing.T, fw *firewall.FirewallApi) []firewall.FilterRule {
	t.Helper()
	var rules, err = fw.FilterRuleSearch(firewall.FilterRuleQuery{SearchPhrase: runPrefix})
	if err != nil {
		t.Fatal(err)
	}
	var own []firewall.FilterRule
	for _, rule := range rules {
		if strings.HasPrefix(rule.Get("description"), runPrefix) {
			own = append(own, rule)
		}
	}
	return own
}

func TestRuleLibraryLifecycle(t *testing.T) {
	var fw = ruleTestApi(t)
	var uuid, created = ruleCreate(t, fw, "rule-lifecycle")

	t.Run("search finds the rule as a disabled user rule", func(t *testing.T) {
		var rules, err = fw.FilterRuleSearch(firewall.FilterRuleQuery{SearchPhrase: created["description"]})
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].Uuid != uuid {
			t.Fatalf("want exactly the new rule, got %+v", rules)
		}
		var rule = rules[0]
		if rule.IsAutomatic() || rule.Enabled() || !rule.Quick() || rule.Get("action") != "block" || rule.Get("interface") != "lan" ||
			rule.Get("destination_net") != "198.51.100.0/24" || rule.Get("sequence") == "" || rule.Get("prio_group") == "" {
			t.Errorf("unexpected rule %+v", rule.Fields)
		}
		var record, recordErr = fw.FilterRuleRecord(uuid)
		if recordErr != nil || record["action"] != "block" || record["interface"] != "lan" || record["enabled"] != "0" || record["statetype"] != "keep" {
			t.Errorf("unexpected record %v / %v", record, recordErr)
		}
	})

	t.Run("interface filter", func(t *testing.T) {
		for _, tc := range []struct {
			iface string
			found bool
		}{{"lan", true}, {"wan", false}} {
			var rules, err = fw.FilterRuleSearch(firewall.FilterRuleQuery{SearchPhrase: created["description"], Interfaces: []string{tc.iface}})
			if err != nil {
				t.Fatal(err)
			}
			if (len(rules) == 1) != tc.found {
				t.Errorf("interface %s: found %d rules, want found=%v", tc.iface, len(rules), tc.found)
			}
		}
	})

	t.Run("update changes only the given fields", func(t *testing.T) {
		if err := fw.FilterRuleUpdate(uuid, firewall.FilterRuleFields{"protocol": "TCP", "destination_port": "443", "source_net": "10.0.0.0/8", "source_not": "1"}); err != nil {
			t.Fatal(err)
		}
		var rule, err = fw.FilterRuleGet(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if rule.Get("protocol") != "TCP" || rule.Get("destination_port") != "443" || !rule.Flag("source_not") ||
			rule.Get("source_net") != "10.0.0.0/8" || rule.Enabled() || rule.Get("destination_net") != "198.51.100.0/24" ||
			rule.Get("description") != created["description"] {
			t.Errorf("unexpected rule after update %+v", rule.Fields)
		}
	})

	t.Run("OPNsense validations are returned", func(t *testing.T) {
		var err = fw.FilterRuleUpdate(uuid, firewall.FilterRuleFields{"interface": "a8nonexistent"})
		var validationErr *api.ValidationError
		if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "rule.interface") {
			t.Errorf("want a ValidationError for the interface, got %v", err)
		}
		if err := fw.FilterRuleUpdate(uuid, firewall.FilterRuleFields{"destination_net": "any,198.51.100.0/24"}); err == nil {
			t.Errorf("want a client-side error for any combined with a network")
		}
	})

	t.Run("disable and log switch", func(t *testing.T) {
		// the rule is never enabled on the shared box: disabling it again must report no change
		var changed, err = fw.FilterRuleSetEnabled(uuid, false)
		if err != nil || changed {
			t.Errorf("disable of a disabled rule: changed %v / %v", changed, err)
		}
		for _, log := range []bool{true, false} {
			if err := fw.FilterRuleSetLog(uuid, log); err != nil {
				t.Fatal(err)
			}
			var rule, _ = fw.FilterRuleGet(uuid)
			if rule.Flag("log") != log || rule.Enabled() {
				t.Errorf("after SetLog(%v): log %v, enabled %v", log, rule.Flag("log"), rule.Enabled())
			}
		}
	})

	t.Run("move before an own rule", func(t *testing.T) {
		var second, _ = ruleCreate(t, fw, "rule-lifecycle second")
		var own = ruleOwnRows(t, fw)
		if len(own) != 2 || own[0].Uuid != uuid || own[1].Uuid != second {
			t.Fatalf("want the first rule before the second, got %d rows", len(own))
		}
		var before, _ = fw.FilterRuleGet(uuid)
		if err := fw.FilterRuleMoveBefore(second, uuid); err != nil {
			t.Fatal(err)
		}
		own = ruleOwnRows(t, fw)
		if len(own) != 2 || own[0].Uuid != second || own[1].Uuid != uuid {
			t.Errorf("the second rule must come first after the move")
		}
		var after, _ = fw.FilterRuleGet(uuid)
		if after.Get("sequence") != before.Get("sequence") {
			t.Errorf("the target rule must keep its sequence (gap numbering): %s -> %s", before.Get("sequence"), after.Get("sequence"))
		}
		if err := fw.FilterRuleMoveBefore(second, "00000000-0000-4000-8000-000000000000"); !api.IsNotFound(err) {
			t.Errorf("move before an unknown rule: want NotFoundError, got %v", err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		if err := fw.FilterRuleRemove(uuid); err != nil {
			t.Fatal(err)
		}
		if _, err := fw.FilterRuleGet(uuid); !api.IsNotFound(err) {
			t.Errorf("want NotFoundError after remove, got %v", err)
		}
		if err := fw.FilterRuleRemove(uuid); !api.IsNotFound(err) {
			t.Errorf("second remove: want NotFoundError, got %v", err)
		}
		if err := fw.FilterRuleUpdate(uuid, firewall.FilterRuleFields{"log": "1"}); !api.IsNotFound(err) {
			t.Errorf("update: want NotFoundError, got %v", err)
		}
		if err := fw.FilterRuleSetLog(uuid, true); !api.IsNotFound(err) {
			t.Errorf("log switch: want NotFoundError, got %v", err)
		}
	})
}

// read-only: automatic rules, statistics and the option lists of the rule editor
func TestRuleLibraryReadOnly(t *testing.T) {
	var fw = ruleTestApi(t)

	var rules, err = fw.FilterRuleSearch(firewall.FilterRuleQuery{Statistics: true})
	if err != nil {
		t.Fatal(err)
	}
	var automatic *firewall.FilterRule
	for i, rule := range rules {
		if rule.IsAutomatic() {
			if firewall.FilterIsUuid(rule.Uuid) || rule.Get("sort_order") == "" {
				t.Errorf("unexpected automatic rule %+v", rule.Fields)
			}
			if automatic == nil {
				automatic = &rules[i]
			}
		}
		if i > 0 && rules[i-1].Get("sort_order") > rule.Get("sort_order") {
			t.Errorf("rules are not in evaluation order: %s before %s", rules[i-1].Get("sort_order"), rule.Get("sort_order"))
		}
	}
	if automatic == nil {
		t.Fatalf("no automatic rules among %d rules", len(rules))
	}
	if err := fw.FilterRuleRemove(automatic.Uuid); err == nil || !strings.Contains(err.Error(), "automatic") {
		t.Errorf("want refusal for removing an automatic rule, got %v", err)
	}
	if _, err := fw.FilterRuleSetEnabled(automatic.Uuid, false); err == nil {
		t.Errorf("want refusal for disabling an automatic rule")
	}

	var stats, statsErr = fw.FilterRuleStatistics()
	if statsErr != nil || len(stats) == 0 {
		t.Errorf("rule statistics: %d entries / %v", len(stats), statsErr)
	}
	if _, found := stats[automatic.Uuid]; !found {
		t.Errorf("no statistics for the automatic rule %s", automatic.Uuid)
	}

	var interfaces, ifErr = fw.FilterInterfaces()
	var keys = map[string]bool{}
	for _, iface := range interfaces {
		keys[iface.Key] = true
	}
	if ifErr != nil || !keys["lan"] || !keys["wan"] {
		t.Errorf("interfaces: %+v / %v", interfaces, ifErr)
	}
	var networks, netErr = fw.FilterNetworkOptions()
	if netErr != nil || networks["any"] == "" || networks["lan"] == "" || networks["(self)"] == "" {
		t.Errorf("networks: %v / %v", networks, netErr)
	}
	var ports, portErr = fw.FilterPortOptions()
	if portErr != nil || ports["https"] == "" {
		t.Errorf("ports: %v / %v", ports, portErr)
	}
	if _, catErr := fw.FilterCategories(); catErr != nil {
		t.Errorf("categories: %v", catErr)
	}
	var protocols, protoErr = fw.FilterRuleOptions("protocol")
	if protoErr != nil || protocols["TCP"] == "" || protocols["TCP/UDP"] == "" {
		t.Errorf("protocol options: %d / %v", len(protocols), protoErr)
	}
	var record, recordErr = fw.FilterRuleRecord("")
	if recordErr != nil || record["sequence"] == "" || record["action"] != "pass" || record["enabled"] != "1" {
		t.Errorf("defaults of a new rule: %v / %v", record, recordErr)
	}
}
