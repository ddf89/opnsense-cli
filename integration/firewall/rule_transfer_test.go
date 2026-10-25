//go:build integration

package integrationfirewall

import (
	"slices"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/firewall"
)

// Live tests of the rule CSV export. Read only: the import (upload_rules) changes the ruleset of the shared box
// and is only tested against fakes

func ruleTransferTestApi(t *testing.T) *firewall.FirewallApi {
	t.Helper()
	return &firewall.FirewallApi{OPNsense: coreApi(t)}
}

func TestFilterRulesTransferExport(t *testing.T) {
	var api = ruleTransferTestApi(t)
	var content, err = api.FilterRulesExport()
	if err != nil {
		t.Fatalf("FilterRulesExport: %v", err)
	}
	if len(content) == 0 {
		t.Skip("the instance has no filter rules, the export is empty")
	}
	parsed, err := firewall.FilterRulesParseCsv(content)
	if err != nil {
		t.Fatalf("the export does not pass the import check: %v\n%s", err, content)
	}
	if parsed.Separator != ';' || parsed.Header[0] != firewall.FilterRulesUuidColumn {
		t.Errorf("separator %q, header %q", parsed.Separator, parsed.Header)
	}

	// the export has exactly the columns the import understands
	columns, err := api.FilterRulesColumns()
	if err != nil {
		t.Fatalf("FilterRulesColumns: %v", err)
	}
	var header = slices.Clone(parsed.Header)
	slices.Sort(header)
	if !slices.Equal(header, columns) {
		t.Errorf("export columns %q\n import columns %q", header, columns)
	}

	// every row is an existing rule; rows of other test runs (a8-...) may be removed meanwhile, so skip them
	var core = coreApi(t)
	var descriptionColumn = slices.Index(parsed.Header, "description")
	for i, uuid := range parsed.Uuids() {
		if descriptionColumn >= 0 && strings.HasPrefix(parsed.Rows[i][descriptionColumn], "a8-") {
			continue
		}
		var answer struct {
			Rule map[string]any `json:"rule"`
		}
		if err := core.DoJSON("GET", core.EndpointForModule("firewall/filter/get_rule/"+uuid), nil, &answer); err != nil || len(answer.Rule) == 0 {
			t.Errorf("row %d: rule %s not found: %v", i, uuid, err)
		}
	}
}
