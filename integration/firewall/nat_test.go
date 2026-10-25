//go:build integration

package integrationfirewall

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// NAT rules (Firewall > NAT). Safety: every rule is created disabled with documentation addresses (198.51.100.0/24,
// 203.0.113.0/24, 2001:db8::/32) and a description owned by this run, d_nat rules keep filter-rule=manual (no
// associated filter rule). Nothing is applied, the outbound NAT mode is only read, nothing is imported. The rules
// OPNsense generates are never changed

func natFirewallApi(t *testing.T) *firewall.FirewallApi {
	t.Helper()
	return &firewall.FirewallApi{OPNsense: coreApi(t)}
}

// natKinds returns the four NAT rule types with fields for a harmless disabled rule (description set by natCreate)
func natKinds(api *firewall.FirewallApi) []struct {
	name   string
	rules  *firewall.NatRules
	fields firewall.NatRuleFields
} {
	return []struct {
		name   string
		rules  *firewall.NatRules
		fields firewall.NatRuleFields
	}{
		{"source", api.SourceNat(), firewall.NatRuleFields{"interface": "wan", "ipprotocol": "inet", "source_net": "198.51.100.0/24",
			"destination_net": "203.0.113.0/24", "target": "203.0.113.10"}},
		{"destination", api.DestinationNat(), firewall.NatRuleFields{"interface": "wan", "ipprotocol": "inet", "protocol": "tcp",
			"destination.network": "203.0.113.5", "destination.port": "8080", "target": "198.51.100.5", "local-port": "80"}},
		{"one-to-one", api.OneToOne(), firewall.NatRuleFields{"interface": "wan", "type": "binat", "source_net": "198.51.100.10",
			"external": "203.0.113.10"}},
		{"npt", api.Npt(), firewall.NatRuleFields{"interface": "wan", "source_net": "2001:db8:1::/48", "destination_net": "2001:db8:2::/48"}},
	}
}

// natCleanup removes the rule when the test ends
func natCleanup(t *testing.T, rules *firewall.NatRules, uuid string) {
	t.Helper()
	t.Cleanup(func() {
		if err := rules.Remove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of %s %s failed: %v", rules.Name(), uuid, err)
		}
	})
}

// natCreate creates a disabled rule with the description and registers its removal
func natCreate(t *testing.T, rules *firewall.NatRules, fields firewall.NatRuleFields, description string) string {
	t.Helper()
	var record = firewall.NatRuleFields{}
	for name, value := range fields {
		record[name] = value
	}
	record[rules.DescriptionField()] = description
	record[rules.DisabledField()] = rules.DisabledValue(true)
	var uuid, err = rules.Create(record)
	if uuid != "" {
		natCleanup(t, rules, uuid)
	}
	if err != nil {
		t.Fatalf("creating a %s: %v", rules.Name(), err)
	}
	return uuid
}

// natOwnRules returns the rules of this run (description prefix)
func natOwnRules(t *testing.T, rules *firewall.NatRules) []firewall.NatRule {
	t.Helper()
	var list, err = rules.List()
	if err != nil {
		t.Fatal(err)
	}
	var own []firewall.NatRule
	for _, rule := range list {
		if ownedByRun(rules.Description(rule)) {
			own = append(own, rule)
		}
	}
	return own
}

// natRequireNothingLeft fails when a rule of this run remains (registered first, so it runs after the cleanups)
func natRequireNothingLeft(t *testing.T, api *firewall.FirewallApi) {
	t.Helper()
	t.Cleanup(func() {
		for _, kind := range natKinds(api) {
			if own := natOwnRules(t, kind.rules); len(own) > 0 {
				t.Errorf("%d %s of this run remain: %v", len(own), kind.rules.Name(), own[0].Uuid)
			}
		}
	})
}

func TestNatLibraryLifecycle(t *testing.T) {
	var fw = natFirewallApi(t)
	natRequireNothingLeft(t, fw)
	var mode, modeErr = fw.SourceNatMode()
	if modeErr != nil || !slices.Contains(firewall.SourceNatModes, mode) {
		t.Fatalf("outbound NAT mode %q, %v", mode, modeErr)
	}

	for _, kind := range natKinds(fw) {
		t.Run(kind.name, func(t *testing.T) {
			var rules = kind.rules
			var description = testDescription("nat-" + kind.name)
			var uuid = natCreate(t, rules, kind.fields, description)

			var rule, err = rules.Get(uuid)
			if err != nil {
				t.Fatal(err)
			}
			if !rules.Disabled(rule) || rules.Description(rule) != description || rule.Automatic {
				t.Errorf("created rule %+v", rule)
			}
			for name, value := range kind.fields {
				if rule.Fields[name] != value {
					t.Errorf("field %s: %q, want %q", name, rule.Fields[name], value)
				}
			}
			// source_nat/search_rule hides the manual rules in the automatic and disabled modes, List adds them
			var wantInactive = kind.name == "source" && (mode == firewall.SourceNatModeAutomatic || mode == firewall.SourceNatModeDisabled)
			if rule.Inactive != wantInactive {
				t.Errorf("inactive %v in mode %s", rule.Inactive, mode)
			}

			if err := rules.Update(uuid, firewall.NatRuleFields{rules.DescriptionField(): description + " changed", "log": "1"}); err != nil {
				t.Fatal(err)
			}
			if rule, err = rules.Get(uuid); err != nil || rules.Description(rule) != description+" changed" || rule.Fields["log"] != "1" ||
				!rules.Disabled(rule) || rule.Fields["interface"] != "wan" {
				t.Errorf("after update: %+v, %v", rule, err)
			}

			if changed, err := rules.SetEnabled(uuid, false); err != nil || changed {
				t.Errorf("disabling a disabled rule: changed %v, %v", changed, err)
			}

			var options, optionsErr = rules.Options()
			if optionsErr != nil || !slices.Contains(options["interface"], "wan") {
				t.Errorf("interface options %v, %v", options["interface"], optionsErr)
			}

			// set_rule would create a rule for an unknown uuid
			var unknown = "00000000-0000-4000-8000-" + strings.Repeat("a8", 6)
			if err := rules.Update(unknown, firewall.NatRuleFields{rules.DescriptionField(): description + " ghost",
				rules.DisabledField(): rules.DisabledValue(true)}); !api.IsNotFound(err) {
				t.Errorf("update of an unknown uuid: %v", err)
			}
			if _, err := rules.Get(unknown); !api.IsNotFound(err) {
				natCleanup(t, rules, unknown)
				t.Errorf("the update created %s", unknown)
			}
			if _, err := rules.SetEnabled(unknown, false); !api.IsNotFound(err) {
				t.Errorf("toggle of an unknown uuid: %v", err)
			}

			var exported, exportErr = rules.Export()
			if exportErr != nil || !strings.Contains(string(exported), uuid) {
				t.Errorf("export lacks the rule: %v\n%s", exportErr, exported)
			}

			if err := rules.Remove(uuid); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.Get(uuid); !api.IsNotFound(err) {
				t.Errorf("the rule exists after remove: %v", err)
			}
			if err := rules.Remove(uuid); !api.IsNotFound(err) {
				t.Errorf("second remove: %v", err)
			}
		})
	}
}

func TestNatDestinationNoFilterRuleAndExport(t *testing.T) {
	var fw = natFirewallApi(t)
	natRequireNothingLeft(t, fw)
	var rules = fw.DestinationNat()
	var description = testDescription("nat-dnat-export")
	var uuid = natCreate(t, rules, natKinds(fw)[1].fields, description)

	// filter-rule=manual: no filter rule is associated
	var filterRows, err = rawSearch(coreApi(t), "firewall/filter/search_rule", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range filterRows {
		if ownedByRun(row.Description) && strings.Contains(row.Description, "nat-dnat") {
			t.Errorf("a filter rule was created for the port forward: %+v", row)
		}
	}
	if rule, err := rules.Get(uuid); err != nil || rule.Fields["pass"] != "" || rule.Fields["associated-rule-id"] != "" {
		t.Errorf("the rule is associated with a filter rule: %+v, %v", rule.Fields, err)
	}

	// OPNsense exports source / destination as empty columns, Export restores their fields
	var exported, exportErr = rules.Export()
	if exportErr != nil {
		t.Fatal(exportErr)
	}
	var parsed, parseErr = firewall.FilterRulesParseCsv(exported)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if slices.Contains(parsed.Header, "destination") || !slices.Contains(parsed.Header, "destination.network") {
		t.Errorf("export header %q", parsed.Header)
	}
	var columns, columnsErr = rules.Columns()
	if columnsErr != nil {
		t.Fatal(columnsErr)
	}
	for _, name := range parsed.Header {
		if !slices.Contains(columns, name) {
			t.Errorf("the exported column %q is not an import column", name)
		}
	}
	var line string
	for _, row := range strings.Split(string(exported), "\n") {
		if strings.HasPrefix(row, uuid) {
			line = row
		}
	}
	if !strings.Contains(line, ";203.0.113.5;8080;") {
		t.Errorf("the destination is not exported: %q", line)
	}
}

func TestNatMoveAndValidation(t *testing.T) {
	var fw = natFirewallApi(t)
	natRequireNothingLeft(t, fw)
	var rules = fw.OneToOne()
	var first = natCreate(t, rules, firewall.NatRuleFields{"interface": "wan", "source_net": "198.51.100.20", "external": "203.0.113.20"},
		testDescription("nat-move-first"))
	var second = natCreate(t, rules, firewall.NatRuleFields{"interface": "wan", "source_net": "198.51.100.21", "external": "203.0.113.21"},
		testDescription("nat-move-second"))

	var position = func() (int, int) {
		var list, err = rules.List()
		if err != nil {
			t.Fatal(err)
		}
		var a, b = -1, -1
		for i, rule := range list {
			switch rule.Uuid {
			case first:
				a = i
			case second:
				b = i
			}
		}
		return a, b
	}
	if a, b := position(); a > b {
		t.Fatalf("the new rule is not after the first: %d, %d", a, b)
	}
	if err := rules.MoveBefore(second, first); err != nil {
		t.Fatal(err)
	}
	if a, b := position(); b > a {
		t.Errorf("move before: %d, %d", a, b)
	}
	if err := rules.MoveToEnd(second); err != nil {
		t.Fatal(err)
	}
	if a, b := position(); a > b {
		t.Errorf("move to the end: %d, %d", a, b)
	}
	var rule, _ = rules.Get(second)
	if sequence, _ := strconv.Atoi(rule.Fields["sequence"]); sequence < 1 || sequence > 999999 {
		t.Errorf("sequence %q", rule.Fields["sequence"])
	}

	// OPNsense validates the address family of source NAT rules
	var snat = fw.SourceNat()
	var created, err = snat.Create(firewall.NatRuleFields{"enabled": "0", "interface": "wan", "ipprotocol": "inet",
		"source_net": "2001:db8::/32", "description": testDescription("nat-invalid")})
	if created != "" {
		natCleanup(t, snat, created)
	}
	var validationErr *api.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Validations["rule.source_net"] == "" {
		t.Errorf("want a validation error for rule.source_net, got %v", err)
	}
}
