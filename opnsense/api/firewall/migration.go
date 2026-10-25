package firewall

import (
	"fmt"
	"strings"
)

// Migration of the legacy firewall rules and outbound NAT rules (stored in config.xml under filter/rule and
// nat/outbound/rule by the pre MVC pages) to the MVC models (api/firewall/migration, Firewall > Rules > Migration
// assistant). The export is a CSV in the import format of the MVC pages (filter rules: FilterRulesImport,
// outbound NAT: the source NAT import), flush deletes all legacy rules of a kind from config.xml (the running
// ruleset only changes on the next filter reload). Without legacy rules the export is empty

// MigrationKind selects the legacy rules: MigrationFilter or MigrationOutbound
type MigrationKind string

const (
	MigrationFilter   MigrationKind = "filter"   // legacy firewall rules
	MigrationOutbound MigrationKind = "outbound" // legacy outbound NAT rules
)

// MigrationKinds are all kinds of legacy rules
var MigrationKinds = []MigrationKind{MigrationFilter, MigrationOutbound}

// migrationMethods are the download, count and flush methods of a kind
var migrationMethods = map[MigrationKind][3]string{
	MigrationFilter:   {"download_rules", "count_rules", "flush"},
	MigrationOutbound: {"download_outbound", "count_outbound", "flush_outbound"},
}

func (opn *FirewallApi) migrationEndpoint(kind MigrationKind, method int) (string, error) {
	var methods, known = migrationMethods[kind]
	if !known {
		return "", fmt.Errorf("unknown kind of legacy rules %q, valid are: filter, outbound", kind)
	}
	return opn.endpoint("firewall", "migration", methods[method]), nil
}

// MigrationCount returns the number of legacy rules of kind
func (opn *FirewallApi) MigrationCount(kind MigrationKind) (int, error) {
	var endpoint, err = opn.migrationEndpoint(kind, 1)
	if err != nil {
		return 0, err
	}
	var answer struct {
		Status string `json:"status"`
		Count  *int   `json:"count"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return 0, err
	}
	if answer.Status != "ok" || answer.Count == nil {
		return 0, fmt.Errorf("counting the legacy %s rules failed: status %q", kind, answer.Status)
	}
	return *answer.Count, nil
}

// MigrationExport returns the legacy rules of kind as CSV (';' separated, header row), empty when there are none
func (opn *FirewallApi) MigrationExport(kind MigrationKind) ([]byte, error) {
	var endpoint, err = opn.migrationEndpoint(kind, 0)
	if err != nil {
		return nil, err
	}
	return opn.filterRulesDownloadCsv(endpoint)
}

// MigrationFlush deletes all legacy rules of kind from the configuration. This can not be undone (except by
// reverting to a configuration backup), export them first
func (opn *FirewallApi) MigrationFlush(kind MigrationKind) error {
	var endpoint, err = opn.migrationEndpoint(kind, 2)
	if err != nil {
		return err
	}
	var answer struct {
		Status string `json:"status"`
	}
	// a GET is answered with {"status":"failed"} without flushing
	if err := opn.DoJSON("POST", endpoint, nil, &answer); err != nil {
		return err
	}
	if !strings.EqualFold(answer.Status, "ok") {
		return fmt.Errorf("flushing the legacy %s rules failed: status %q", kind, answer.Status)
	}
	return nil
}
