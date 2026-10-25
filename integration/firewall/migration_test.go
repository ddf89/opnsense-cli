//go:build integration

package integrationfirewall

import (
	"testing"

	"opnsense-cli/opnsense/api/firewall"
)

// Live tests of the legacy rule migration API. Read only: flush and flush_outbound are only tested against fakes

func TestMigrationCountAndExport(t *testing.T) {
	var api = ruleTransferTestApi(t)
	for _, kind := range firewall.MigrationKinds {
		t.Run(string(kind), func(t *testing.T) {
			var count, err = api.MigrationCount(kind)
			if err != nil || count < 0 {
				t.Fatalf("MigrationCount: %d %v", count, err)
			}
			content, err := api.MigrationExport(kind)
			if err != nil {
				t.Fatalf("MigrationExport: %v", err)
			}
			if count == 0 {
				// without legacy rules the export is completely empty, not even a header
				if len(content) != 0 {
					t.Errorf("no legacy rules, but an export of %d bytes:\n%s", len(content), content)
				}
				return
			}
			parsed, err := firewall.FilterRulesParseCsv(content)
			if err != nil {
				t.Fatalf("the export does not pass the import check: %v\n%s", err, content)
			}
			if len(parsed.Rows) != count || parsed.Header[0] != firewall.FilterRulesUuidColumn {
				t.Errorf("%d rows for %d legacy rules, header %q", len(parsed.Rows), count, parsed.Header)
			}
		})
	}
	if _, err := api.MigrationCount("nat"); err == nil {
		t.Errorf("an unknown kind must fail")
	}
}
