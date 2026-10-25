package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
)

// Firewall > Diagnostics > Aliases (api/firewall/alias_util): the live pf tables behind the aliases.
// Behaviour of OPNsense 26.7 this wrapper relies on:
//   - list/<alias> of an unknown table answers an empty list, existence is checked via aliases
//   - add/delete of a host or network alias also changes the alias content in the configuration (saved), for the
//     other types only the live table changes until it is reloaded
//   - addresses are checked against [0-9a-f:./_] only (lower case), add answers {"status":"not_an_address"}
//   - add to an unknown alias answers {"status":"failed","status_msg":"nonexistent alias x"}, delete and flush
//     always answer {"status":"done"}

func (opn *FirewallApi) aliasUtilEndpoint(method string, args ...string) string {
	var endpoint = opn.endpoint("firewall", "alias_util", method)
	for _, arg := range args {
		endpoint += "/" + url.PathEscape(arg)
	}
	return endpoint
}

// AliasTables lists the names of the pf tables (one per loaded alias), sorted case-insensitively
func (opn *FirewallApi) AliasTables() ([]string, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.aliasUtilEndpoint("aliases"), nil, &raw); err != nil {
		return nil, err
	}
	var tables = []string{}
	if trimmed := bytes.TrimSpace(raw); bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("OPNsense could not list the pf tables")
	}
	if err := json.Unmarshal(raw, &tables); err != nil {
		return nil, fmt.Errorf("could not decode the pf tables: %w", err)
	}
	return tables, nil
}

// aliasTableExists checks that alias is a pf table
func (opn *FirewallApi) aliasTableExists(alias string) error {
	var tables, err = opn.AliasTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table == alias {
			return nil
		}
	}
	return &coreapi.NotFoundError{Name: fmt.Sprintf("pf table %s (the alias does not exist or is not loaded, see apply)", alias)}
}

// AliasTableEntries lists the addresses in the pf table of alias, *NotFoundError when there is no such table
func (opn *FirewallApi) AliasTableEntries(alias string) ([]string, error) {
	if alias == "" {
		return nil, errors.New("an alias name is required")
	}
	var rows, err = coreapi.Search[struct {
		Ip string `json:"ip"`
	}](opn.OPNsense, opn.aliasUtilEndpoint("list", alias), "")
	if err != nil {
		return nil, err
	}
	var entries = make([]string, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, row.Ip)
	}
	if len(entries) == 0 {
		if err := opn.aliasTableExists(alias); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// AliasTableStat is the pf table of an alias as reported by get_table_size
type AliasTableStat struct {
	Count int `json:"count"`
	// Updated is the time of the last update of URL tables, "" for the others
	Updated string `json:"updated"`
}

// AliasTableSizes are the pf table entries in use and the limit (Firewall > Settings > Advanced)
type AliasTableSizes struct {
	// Size is the table entries limit, Used the entries in all tables
	Size    int                       `json:"size"`
	Used    int                       `json:"used"`
	Details map[string]AliasTableStat `json:"-"`
}

// AliasTableSize returns the table entries in use, the limit and the entries per table
func (opn *FirewallApi) AliasTableSize() (AliasTableSizes, error) {
	var container struct {
		Status  string `json:"status"`
		Size    int    `json:"size"`
		Used    int    `json:"used"`
		Details map[string]struct {
			Count   int     `json:"count"`
			Updated *string `json:"updated"`
		} `json:"details"`
	}
	if err := opn.DoJSON("GET", opn.aliasEndpoint("get_table_size"), nil, &container); err != nil {
		return AliasTableSizes{}, err
	}
	if container.Status != "ok" {
		return AliasTableSizes{}, fmt.Errorf("OPNsense could not read the table sizes: status %q", container.Status)
	}
	var sizes = AliasTableSizes{Size: container.Size, Used: container.Used, Details: map[string]AliasTableStat{}}
	for name, detail := range container.Details {
		var stat = AliasTableStat{Count: detail.Count}
		if detail.Updated != nil {
			stat.Updated = *detail.Updated
		}
		sizes.Details[name] = stat
	}
	return sizes, nil
}

type aliasUtilStatus struct {
	Status    string `json:"status"`
	StatusMsg string `json:"status_msg"`
}

// AliasTableAdd adds address (an IP address or network) to the live pf table of alias. For host and network
// aliases OPNsense also adds it to the alias content (saved), for the others the live table only changes until the
// alias is reloaded
func (opn *FirewallApi) AliasTableAdd(alias string, address string) error {
	var result aliasUtilStatus
	if err := opn.DoJSON("POST", opn.aliasUtilEndpoint("add", alias), map[string]string{"address": address}, &result); err != nil {
		return err
	}
	switch result.Status {
	case "done":
		return nil
	case "not_an_address":
		return fmt.Errorf("%q is not an address OPNsense accepts (IP address or network, lower case)", address)
	case "failed":
		if result.StatusMsg != "" {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("alias %s (%s)", alias, result.StatusMsg)}
		}
		return errors.New("adding the address failed")
	default:
		return fmt.Errorf("unexpected answer from alias_util/add: status %q", result.Status)
	}
}

// AliasTableDelete removes address from the live pf table of alias (and from the content of host and network
// aliases, saved). *NotFoundError when there is no such table (checked first, OPNsense answers "done" anyway)
func (opn *FirewallApi) AliasTableDelete(alias string, address string) error {
	if err := opn.aliasTableExists(alias); err != nil {
		return err
	}
	return opn.aliasUtilDone("delete", alias, map[string]string{"address": address})
}

// AliasTableFlush removes all addresses from the live pf table of alias, until it is reloaded. *NotFoundError when
// there is no such table (checked first, OPNsense answers "done" anyway)
func (opn *FirewallApi) AliasTableFlush(alias string) error {
	if err := opn.aliasTableExists(alias); err != nil {
		return err
	}
	return opn.aliasUtilDone("flush", alias, struct{}{})
}

func (opn *FirewallApi) aliasUtilDone(method string, alias string, body any) error {
	var result aliasUtilStatus
	if err := opn.DoJSON("POST", opn.aliasUtilEndpoint(method, alias), body, &result); err != nil {
		return err
	}
	if result.Status != "done" {
		return fmt.Errorf("alias_util/%s failed: status %q", method, result.Status)
	}
	return nil
}

// AliasFindReferences returns the aliases whose pf table contains ip (an address, or a network contained in an
// entry), sorted
func (opn *FirewallApi) AliasFindReferences(ip string) ([]string, error) {
	var result struct {
		Status  string   `json:"status"`
		Matches []string `json:"matches"`
	}
	if err := opn.DoJSON("POST", opn.aliasUtilEndpoint("find_references"), map[string]string{"ip": ip}, &result); err != nil {
		return nil, err
	}
	if result.Status != "ok" {
		// e.g. "Not an IP address!"
		return nil, fmt.Errorf("finding %s failed: %s", ip, result.Status)
	}
	if result.Matches == nil {
		result.Matches = []string{}
	}
	sort.Strings(result.Matches)
	return result.Matches, nil
}
