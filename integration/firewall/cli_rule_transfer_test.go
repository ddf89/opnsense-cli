//go:build integration

package integrationfirewall

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"opnsense-cli/opnsense/api/firewall"
)

// Live tests of /firewall/rule export and /firewall/migration print / export. import and flush are never run
// against the shared box (they change the ruleset), their guards are tested with fakes in package cli

func TestCliRuleTransferExport(t *testing.T) {
	var api = ruleTransferTestApi(t)
	var expected, err = api.FilterRulesExport()
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Skip("the instance has no filter rules")
	}
	var parsed, _ = firewall.FilterRulesParseCsv(expected)

	// other tests may change rules meanwhile, so compare the format, not the content
	var result = mustOpn(t, "/firewall/rule", "export", "file=-")
	if stdout, err := firewall.FilterRulesParseCsv([]byte(result.stdout)); err != nil || !slices.Equal(stdout.Header, parsed.Header) {
		t.Errorf("stdout is not the API export format (%v):\n%s", err, result)
	}

	var dir = t.TempDir()
	var path = filepath.Join(dir, "rules.csv")
	result = mustOpn(t, "/firewall/rule", "export", path)
	requireNoStdout(t, result)
	requireContains(t, result, result.stderr, "saved")
	content, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(content), "@uuid;") {
		t.Fatalf("the exported file: %q %v", content, err)
	}
	if again, err := firewall.FilterRulesParseCsv(content); err != nil || !slices.Equal(again.Header, parsed.Header) {
		t.Errorf("the exported file is not the API export format: %v", err)
	}

	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	result = mustFailOpn(t, "/firewall/rule", "export", path)
	requireContains(t, result, result.stderr, "already exists")
	if kept, _ := os.ReadFile(path); string(kept) != "keep" {
		t.Errorf("the existing file was changed without overwrite")
	}
	mustOpn(t, "/firewall/rule", "export", path, "overwrite")
	if replaced, _ := os.ReadFile(path); !strings.HasPrefix(string(replaced), "@uuid;") {
		t.Errorf("overwrite did not replace the file: %q", replaced)
	}
}

func TestCliMigration(t *testing.T) {
	var api = ruleTransferTestApi(t)
	var result = mustOpn(t, "/firewall/migration", "print")
	requireContains(t, result, result.stdout, "TYPE", "COUNT", "filter", "outbound")

	result = mustOpn(t, "/firewall/migration", "print", "json")
	for _, kind := range firewall.MigrationKinds {
		var count, err = api.MigrationCount(kind)
		if err != nil {
			t.Fatal(err)
		}
		requireContains(t, result, result.stdout, `"type":"`+string(kind)+`"`)
		requireContains(t, result, result.stdout, `{"count":`+strconv.Itoa(count)+`,"type":"`+string(kind)+`"}`)

		var path = filepath.Join(t.TempDir(), string(kind)+".csv")
		var export = mustOpn(t, "/firewall/migration", "export", string(kind), "file="+path)
		requireNoStdout(t, export)
		_, statErr := os.Stat(path)
		if count == 0 {
			requireContains(t, export, export.stderr, "nothing exported")
			if !os.IsNotExist(statErr) {
				t.Errorf("%s: a file was written without legacy rules", kind)
			}
		} else if statErr != nil {
			t.Errorf("%s: no file written for %d legacy rules: %v", kind, count, statErr)
		}
	}
}
