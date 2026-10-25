package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
)

// FilterRule is a row of Firewall > Rules (api/firewall/filter/search_rule).
//
// search_rule returns two kinds of rows, sorted by their evaluation order (sort_order):
//   - rules of the MVC model (user rules), their uuid is a regular uuid
//   - automatic rules OPNsense generates (default deny, anti-lockout, DHCP, bogons, ...) and legacy rules, their id is
//     a 32 character md5 key, they carry "legacy":true and "is_automatic":true and can not be changed with this API
//
// The values have mixed types (automatic rows send flags as booleans or numbers), Fields holds every value as text
// with flags as "1"/"0", keyed by the API field name (also the "%field" descriptions OPNsense adds)
type FilterRule struct {
	Uuid   string
	Fields map[string]string
	// Raw is the row as returned by the API
	Raw json.RawMessage
}

// UnmarshalJSON reads a search_rule row
func (r *FilterRule) UnmarshalJSON(data []byte) error {
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	*r = FilterRule{Fields: make(map[string]string, len(row)), Raw: append(json.RawMessage(nil), data...)}
	for key, value := range row {
		switch value.(type) {
		case []any, map[string]any: // category_colors, alias_meta_*: formatting hints of the GUI
			continue
		}
		r.Fields[key] = filterText(value)
	}
	r.Uuid = r.Fields["uuid"]
	return nil
}

// filterText renders a JSON value as text: booleans as "1"/"0", numbers without exponent
func filterText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		var encoded, _ = json.Marshal(v)
		return string(encoded)
	}
}

// Get returns the value of an API field ("" when not set)
func (r FilterRule) Get(field string) string {
	return r.Fields[field]
}

// Flag returns a boolean field
func (r FilterRule) Flag(field string) bool {
	return r.Fields[field] == "1"
}

// IsAutomatic is true for rules OPNsense generates (and legacy rules), which can not be changed with this API
func (r FilterRule) IsAutomatic() bool {
	return r.Flag("is_automatic") || r.Flag("legacy") || !FilterIsUuid(r.Uuid)
}

// Enabled tells whether the rule is active
func (r FilterRule) Enabled() bool {
	return r.Fields["enabled"] != "0"
}

// Quick tells whether the first matching rule wins (pf quick), automatic rules without the field are quick
func (r FilterRule) Quick() bool {
	var quick, given = r.Fields["quick"]
	return !given || quick != "0"
}

// FilterRuleStats are the pf counters of a rule (filter_util/rule_stats, search_rule with show_all)
type FilterRuleStats struct {
	PfRules     int64 `json:"pf_rules"` // number of pf rules the rule expands to
	Evaluations int64 `json:"evaluations"`
	Packets     int64 `json:"packets"`
	Bytes       int64 `json:"bytes"`
	States      int64 `json:"states"`
}

var filterUuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// FilterIsUuid tells whether id is the uuid of an MVC rule (automatic rules have md5 keys)
func FilterIsUuid(id string) bool {
	return filterUuidPattern.MatchString(id)
}

// FilterRuleFields holds rule fields for create / update keyed by the API field name, see FilterRuleFieldNames.
// Lists (interface, source_net, categories, icmptype, ...) are comma separated, flags "0"/"1"
type FilterRuleFields map[string]string

// FilterRuleFieldNames are the writable fields of a rule in OPNsense 26.7, in the order of the GUI
var FilterRuleFieldNames = []string{
	"enabled", "sequence", "action", "quick", "interfacenot", "interface", "direction", "ipprotocol", "protocol",
	"icmptype", "icmp6type", "source_net", "source_not", "source_port", "destination_net", "destination_not",
	"destination_port", "log", "categories", "sched", "description", "statetype", "state-policy", "divert-to",
	"gateway", "replyto", "disablereplyto", "allowopts", "nosync", "nopfsync", "statetimeout", "udp-first",
	"udp-multiple", "udp-single", "max-src-nodes", "max-src-states", "max-src-conn", "max", "max-src-conn-rate",
	"max-src-conn-rates", "overload", "adaptivestart", "adaptiveend", "prio", "set-prio", "set-prio-low", "tag",
	"tagged", "tcpflags1", "tcpflags2", "tcpflags_any", "tos", "shaper1", "shaper2",
}

// FilterRuleDefaults are the values OPNsense uses for a new rule (without sequence, which OPNsense numbers)
var FilterRuleDefaults = FilterRuleFields{
	"enabled": "1", "action": "pass", "quick": "1", "interfacenot": "0", "interface": "", "direction": "in",
	"ipprotocol": "inet", "protocol": "any", "icmptype": "", "icmp6type": "", "source_net": "any", "source_not": "0",
	"source_port": "", "destination_net": "any", "destination_not": "0", "destination_port": "", "log": "0",
	"categories": "", "sched": "", "description": "", "statetype": "keep", "state-policy": "", "divert-to": "",
	"gateway": "", "replyto": "", "disablereplyto": "0", "allowopts": "0", "nosync": "0", "nopfsync": "0",
	"statetimeout": "", "udp-first": "", "udp-multiple": "", "udp-single": "", "max-src-nodes": "",
	"max-src-states": "", "max-src-conn": "", "max": "", "max-src-conn-rate": "", "max-src-conn-rates": "",
	"overload": "", "adaptivestart": "", "adaptiveend": "", "prio": "", "set-prio": "", "set-prio-low": "", "tag": "",
	"tagged": "", "tcpflags1": "", "tcpflags2": "", "tcpflags_any": "0", "tos": "", "shaper1": "", "shaper2": "",
}

var filterFlagFields = map[string]bool{
	"enabled": true, "quick": true, "interfacenot": true, "source_not": true, "destination_not": true, "log": true,
	"disablereplyto": true, "allowopts": true, "nosync": true, "nopfsync": true, "tcpflags_any": true,
}

var filterOptionFields = map[string][]string{
	"action":       {"pass", "block", "reject"},
	"direction":    {"in", "out", "any"},
	"ipprotocol":   {"inet", "inet6", "inet46"},
	"statetype":    {"keep", "sloppy", "modulate", "synproxy", "none"},
	"state-policy": {"", "if-bound", "floating"},
	"prio":         {"", "0", "1", "2", "3", "4", "5", "6", "7"},
	"set-prio":     {"", "0", "1", "2", "3", "4", "5", "6", "7"},
	"set-prio-low": {"", "0", "1", "2", "3", "4", "5", "6", "7"},
}

var filterTcpFlags = []string{"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"}

// filterRanges are the integer fields with their limits, empty is allowed for all but sequence
var filterRanges = map[string][2]int64{
	"sequence": {1, 999999}, "statetimeout": {1, 2147483647}, "udp-first": {1, 2147483647},
	"udp-multiple": {1, 2147483647}, "udp-single": {1, 2147483647}, "max-src-nodes": {1, 2147483647},
	"max-src-states": {1, 2147483647}, "max-src-conn": {1, 2147483647}, "max": {1, 2147483647},
	"max-src-conn-rate": {1, 4294967}, "max-src-conn-rates": {1, 2147483647}, "adaptivestart": {0, 2147483647},
	"adaptiveend": {0, 2147483647},
}

var (
	filterNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.()-]+$`)
	filterPortPattern = regexp.MustCompile(`^([0-9]{1,5}([-:][0-9]{1,5})?|[A-Za-z][A-Za-z0-9_.-]*)$`)
	filterTagPattern  = regexp.MustCompile(`^[0-9a-zA-Z.,_-]{0,512}$`)
)

// filterPortProtocols are the protocols ports can be used with
var filterPortProtocols = []string{"TCP", "UDP", "TCP/UDP"}

// FilterNetFamily returns inet / inet6 for an address or network, "" for anything else (aliases, any, lan, ...)
func FilterNetFamily(value string) string {
	if net.ParseIP(value) == nil {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return ""
		}
	}
	if strings.Contains(value, ":") {
		return "inet6"
	}
	return "inet"
}

// FilterValidateNetwork checks a source / destination list: addresses, networks, any, (self), interface networks
// (lan, lanip) and alias names. any can not be combined with others
func FilterValidateNetwork(value string) error {
	if value == "" {
		return errors.New("must not be empty, use any")
	}
	var elements = strings.Split(value, ",")
	for _, element := range elements {
		element = strings.TrimSpace(element)
		if element == "any" && len(elements) > 1 {
			return errors.New("any can not be combined with other networks")
		}
		if FilterNetFamily(element) == "" && !filterNamePattern.MatchString(element) {
			return fmt.Errorf("invalid network %q: expected an address, a network, any, (self), an interface network like lan or an alias", element)
		}
	}
	return nil
}

// FilterValidatePort checks a port: a number, a range like 1024-65535, a well-known name like https or a port alias
func FilterValidatePort(value string) error {
	if value == "" {
		return nil
	}
	if !filterPortPattern.MatchString(value) {
		return fmt.Errorf("invalid port %q: expected a port, a range like 1024-65535, a name like https or a port alias", value)
	}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == ':' }) {
		if number, err := strconv.Atoi(part); err == nil && (number < 0 || number > 65535) {
			return fmt.Errorf("invalid port %q: ports are 0-65535", value)
		}
	}
	return nil
}

// FilterValidateFields checks the fields client-side. current are the fields of the rule being changed (nil for a
// new rule), they are used for the checks involving several fields (ports need TCP/UDP, address families, ...)
func FilterValidateFields(fields FilterRuleFields, current FilterRuleFields) error {
	var names = make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var known = map[string]bool{}
	for _, name := range FilterRuleFieldNames {
		known[name] = true
	}

	for _, name := range names {
		var value = fields[name]
		var fail = func(format string, args ...any) error {
			return fmt.Errorf("invalid %s %q: %s", name, value, fmt.Sprintf(format, args...))
		}
		switch {
		case !known[name]:
			return fmt.Errorf("unknown filter rule field %q", name)
		case filterFlagFields[name]:
			if value != "0" && value != "1" {
				return fail("expected 0 or 1")
			}
		case filterOptionFields[name] != nil:
			if !filterContains(filterOptionFields[name], value) {
				return fail("expected one of %s", strings.Join(filterOptionFields[name], ", "))
			}
		case name == "sequence" || filterRanges[name] != [2]int64{}:
			if value == "" && name != "sequence" {
				continue
			}
			var limits = filterRanges[name]
			var number, err = strconv.ParseInt(value, 10, 64)
			if err != nil || number < limits[0] || number > limits[1] {
				return fail("expected a number from %d to %d", limits[0], limits[1])
			}
		case name == "source_net" || name == "destination_net":
			if err := FilterValidateNetwork(value); err != nil {
				return fmt.Errorf("invalid %s: %w", name, err)
			}
		case name == "source_port" || name == "destination_port":
			if err := FilterValidatePort(value); err != nil {
				return fmt.Errorf("invalid %s: %w", name, err)
			}
		case name == "protocol":
			if value == "" || strings.ContainsFunc(value, unicode.IsSpace) {
				return fail("expected a protocol like any, TCP, UDP, TCP/UDP or ICMP")
			}
		case name == "tcpflags1" || name == "tcpflags2":
			for _, flag := range filterSplit(value) {
				if !filterContains(filterTcpFlags, flag) {
					return fail("expected flags of %s", strings.Join(filterTcpFlags, ", "))
				}
			}
		case name == "tag" || name == "tagged":
			if !filterTagPattern.MatchString(value) {
				return fail("only a-z, A-Z, 0-9 and .,_- are allowed")
			}
		default: // interface, categories, gateway, descriptions, ...: no control characters
			if strings.ContainsFunc(value, unicode.IsControl) {
				return fail("control characters are not allowed")
			}
		}
	}
	return filterValidateCombination(fields, current)
}

// filterValidateCombination checks the rules of the model which involve several fields, on the merged record
func filterValidateCombination(fields FilterRuleFields, current FilterRuleFields) error {
	var merged = FilterRuleFields{}
	for name, value := range FilterRuleDefaults {
		merged[name] = value
	}
	for name, value := range current {
		merged[name] = value
	}
	for name, value := range fields {
		merged[name] = value
	}

	var protocol = strings.ToUpper(merged["protocol"])
	for _, port := range []string{"source_port", "destination_port"} {
		if merged[port] != "" && !filterContains(filterPortProtocols, protocol) {
			return fmt.Errorf("%s needs protocol TCP, UDP or TCP/UDP, not %s", port, merged["protocol"])
		}
	}
	for _, side := range []string{"source", "destination"} {
		var networks = filterSplit(merged[side+"_net"])
		if merged[side+"_not"] == "1" && len(networks) > 1 {
			return fmt.Errorf("%s: only a single network can be inverted", side)
		}
		for _, network := range networks {
			var family = FilterNetFamily(network)
			if family != "" && merged["ipprotocol"] != "inet46" && family != merged["ipprotocol"] {
				return fmt.Errorf("%s %s does not match the IP protocol %s", side, network, merged["ipprotocol"])
			}
		}
	}
	if merged["interfacenot"] == "1" && len(filterSplit(merged["interface"])) != 1 {
		return errors.New("only a single interface can be inverted")
	}
	if merged["icmptype"] != "" && protocol != "ICMP" {
		return errors.New("icmp types need protocol ICMP")
	}
	if merged["icmp6type"] != "" && protocol != "IPV6-ICMP" {
		return errors.New("icmp6 types need protocol IPV6-ICMP")
	}
	return nil
}

func filterSplit(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

func filterContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (opn *FirewallApi) filterEndpoint(method string) string {
	return opn.endpoint("firewall", "filter", method)
}

// FilterRuleQuery selects rules for FilterRuleSearch, the zero value lists every rule
type FilterRuleQuery struct {
	// SearchPhrase: rules where any field contains every word (case-insensitive)
	SearchPhrase string
	// Interfaces: the rules OPNsense evaluates on these interfaces: their own rules, floating rules (no or several
	// interfaces), rules of interface groups containing them and the automatic rules
	Interfaces []string
	// Floating: only floating rules (no interface or several), ignored with Interfaces
	Floating bool
	// Categories: only rules with one of these category uuids
	Categories []string
	// Statistics adds the pf counters (pf_rules, evaluations, packets, bytes, states) to the rows
	Statistics bool
}

// FilterRuleSearch returns the rules matching query in evaluation order.
// search_rule reads searchPhrase only from a POST body (a GET searchPhrase is ignored), so it is always POSTed
func (opn *FirewallApi) FilterRuleSearch(query FilterRuleQuery) ([]FilterRule, error) {
	var body = map[string]any{"current": 1, "rowCount": -1, "searchPhrase": query.SearchPhrase}
	switch {
	case len(query.Interfaces) > 0:
		body["interface"] = strings.Join(query.Interfaces, ",")
	case query.Floating:
		body["interface"] = ""
	}
	if len(query.Categories) > 0 {
		body["category"] = query.Categories
	}
	if query.Statistics {
		body["show_all"] = "1"
	}
	var container struct {
		Rows []FilterRule `json:"rows"`
	}
	if err := opn.DoJSON("POST", opn.filterEndpoint("search_rule"), body, &container); err != nil {
		return nil, err
	}
	return container.Rows, nil
}

// FilterRuleList returns all rules (MVC and automatic) in evaluation order
func (opn *FirewallApi) FilterRuleList() ([]FilterRule, error) {
	return opn.FilterRuleSearch(FilterRuleQuery{})
}

// FilterRuleGet returns the rule with this uuid (or md5 key of an automatic rule), or a *NotFoundError.
// get_rule is no help: it answers unknown uuids with the defaults of a new rule
func (opn *FirewallApi) FilterRuleGet(uuid string) (FilterRule, error) {
	if uuid == "" {
		return FilterRule{}, errors.New("rule uuid must not be empty")
	}
	var rules, err = opn.FilterRuleList()
	if err != nil {
		return FilterRule{}, err
	}
	for _, rule := range rules {
		if strings.EqualFold(rule.Uuid, uuid) {
			return rule, nil
		}
	}
	return FilterRule{}, &coreapi.NotFoundError{Name: fmt.Sprintf("filter rule %s", uuid)}
}

// FilterRuleRecord returns the stored fields of an MVC rule as get_rule returns them, with the option fields reduced
// to their selected keys (comma separated). Without uuid it returns the defaults of a new rule (with the next sequence)
func (opn *FirewallApi) FilterRuleRecord(uuid string) (FilterRuleFields, error) {
	var record, err = opn.filterGetRule(uuid)
	if err != nil {
		return nil, err
	}
	var fields = FilterRuleFields{}
	for name, raw := range record {
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			fields[name] = text
			continue
		}
		var options map[string]filterOption
		if err := json.Unmarshal(raw, &options); err == nil {
			fields[name] = filterSelected(options)
			continue
		}
		var other any
		if err := json.Unmarshal(raw, &other); err != nil {
			return nil, fmt.Errorf("unexpected value of %s in get_rule: %s", name, raw)
		}
		if list, isList := other.([]any); isList && len(list) == 0 { // categories without options: []
			fields[name] = ""
			continue
		}
		fields[name] = filterText(other)
	}
	return fields, nil
}

type filterOption struct {
	Value    string `json:"value"`
	Selected any    `json:"selected"`
}

func filterSelected(options map[string]filterOption) string {
	var selected []string
	for key, option := range options {
		if filterText(option.Selected) == "1" {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return strings.Join(selected, ",")
}

func (opn *FirewallApi) filterGetRule(uuid string) (map[string]json.RawMessage, error) {
	var endpoint = opn.filterEndpoint("get_rule")
	if uuid != "" {
		endpoint += "/" + uuid
	}
	var container struct {
		Rule map[string]json.RawMessage `json:"rule"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	if container.Rule == nil {
		return nil, fmt.Errorf("unexpected answer from %s: no rule", endpoint)
	}
	return container.Rule, nil
}

// FilterRuleOptions returns the options of an option field of a new rule (get_rule): key -> description, e.g.
// protocol, gateway, replyto, sched, shaper1, overload, tos, icmptype. The "none" option ("") is left out
func (opn *FirewallApi) FilterRuleOptions(field string) (map[string]string, error) {
	var record, err = opn.filterGetRule("")
	if err != nil {
		return nil, err
	}
	var options map[string]filterOption
	if err := json.Unmarshal(record[field], &options); err != nil {
		return nil, fmt.Errorf("%s of get_rule has no options", field)
	}
	var result = make(map[string]string, len(options))
	for key, option := range options {
		if key != "" {
			result[key] = option.Value
		}
	}
	return result, nil
}

// filterRequireMvc refuses ids of automatic rules, they are not stored in the model
func filterRequireMvc(uuid string) error {
	if uuid == "" {
		return errors.New("rule uuid must not be empty")
	}
	if !FilterIsUuid(uuid) {
		return fmt.Errorf("%s is an automatic rule generated by OPNsense, it can not be changed here", uuid)
	}
	return nil
}

// FilterRuleCreate adds a rule and returns its uuid. Fields not given get the OPNsense defaults
// (FilterRuleDefaults: an enabled pass rule from any to any!), the sequence defaults to the end of the list
func (opn *FirewallApi) FilterRuleCreate(fields FilterRuleFields) (string, error) {
	if err := FilterValidateFields(fields, nil); err != nil {
		return "", err
	}
	return opn.Mutate(opn.filterEndpoint("add_rule"), map[string]FilterRuleFields{"rule": fields})
}

// FilterRuleUpdate sends only the given fields to the MVC rule uuid (set_rule merges), automatic rules are refused.
// Returns *NotFoundError for unknown uuids (checked first, set_rule would create a new rule)
func (opn *FirewallApi) FilterRuleUpdate(uuid string, fields FilterRuleFields) error {
	if err := filterRequireMvc(uuid); err != nil {
		return err
	}
	if len(fields) == 0 {
		return errors.New("no rule fields to change")
	}
	var rule, err = opn.FilterRuleGet(uuid)
	if err != nil {
		return err
	}
	if err := FilterValidateFields(fields, FilterRuleFields(rule.Fields)); err != nil {
		return err
	}
	var _, setErr = opn.Mutate(fmt.Sprintf("%s/%s", opn.filterEndpoint("set_rule"), rule.Uuid), map[string]FilterRuleFields{"rule": fields})
	return filterMutationError(rule.Uuid, setErr)
}

// filterMutationError turns the "not found" / bare "failed" answers into *NotFoundError and the HTTP 500 of a
// refused change ({"errorMessage":"Rule not found"}) into its message
func filterMutationError(uuid string, err error) error {
	var validationErr *coreapi.ValidationError
	if coreapi.IsNotFound(err) || errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("filter rule %s", uuid), Err: err}
	}
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 && httpErr.Message != "" && !strings.HasPrefix(httpErr.Message, "{") {
		switch httpErr.Message {
		case "Rule not found", "Either source or destination is not a rule managed with this component":
			return &coreapi.NotFoundError{Name: fmt.Sprintf("filter rule %s", uuid), Err: errors.New(httpErr.Message)}
		}
		return errors.New(httpErr.Message)
	}
	return err
}

// FilterRuleRemove deletes the MVC rule uuid, automatic rules are refused. Returns *NotFoundError for unknown uuids
func (opn *FirewallApi) FilterRuleRemove(uuid string) error {
	if err := filterRequireMvc(uuid); err != nil {
		return err
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.filterEndpoint("del_rule"), uuid), nil)
	return filterMutationError(uuid, err)
}

// FilterRuleSetEnabled enables or disables the MVC rule uuid and returns whether its state changed
func (opn *FirewallApi) FilterRuleSetEnabled(uuid string, enabled bool) (bool, error) {
	if err := filterRequireMvc(uuid); err != nil {
		return false, err
	}
	// toggle_rule/<uuid>/<0|1> sets the given state, without the state it would flip it
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.filterEndpoint("toggle_rule"), uuid, filterBit(enabled))
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed":
		return false, &coreapi.NotFoundError{Name: fmt.Sprintf("filter rule %s", uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// FilterRuleSetLog switches logging of the MVC rule uuid on or off (toggle_rule_log)
func (opn *FirewallApi) FilterRuleSetLog(uuid string, log bool) error {
	if err := filterRequireMvc(uuid); err != nil {
		return err
	}
	return opn.filterStatusOk(fmt.Sprintf("%s/%s/%s", opn.filterEndpoint("toggle_rule_log"), uuid, filterBit(log)), uuid)
}

// FilterRuleMoveBefore moves the MVC rule uuid right before the rule target by changing its sequence (other rules
// are renumbered only when there is no gap). Both must be of the same kind: floating, group or interface rules
func (opn *FirewallApi) FilterRuleMoveBefore(uuid string, target string) error {
	if err := filterRequireMvc(uuid); err != nil {
		return err
	}
	if err := filterRequireMvc(target); err != nil {
		return err
	}
	if strings.EqualFold(uuid, target) {
		return errors.New("a rule can not be moved before itself")
	}
	return opn.filterStatusOk(fmt.Sprintf("%s/%s/%s", opn.filterEndpoint("move_rule_before"), uuid, target), uuid)
}

// filterStatusOk POSTs to endpoint and expects {"status":"ok"}
func (opn *FirewallApi) filterStatusOk(endpoint string, uuid string) error {
	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return filterMutationError(uuid, err)
	}
	if result.Status != "ok" {
		return fmt.Errorf("unexpected answer from %s: %s %s", endpoint, result.Status, result.Message)
	}
	return nil
}

func filterBit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// FilterRuleStatistics returns the current pf counters of all rules keyed by uuid (filter_util/rule_stats)
func (opn *FirewallApi) FilterRuleStatistics() (map[string]FilterRuleStats, error) {
	var endpoint = opn.endpoint("firewall", "filter_util", "rule_stats")
	var result struct {
		Status string                     `json:"status"`
		Stats  map[string]FilterRuleStats `json:"stats"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &result); err != nil {
		return nil, err
	}
	if result.Status != "ok" {
		return nil, fmt.Errorf("rule statistics are not available: status %q", result.Status)
	}
	return result.Stats, nil
}

// FilterInterface is an interface (or interface group) rules can be attached to
type FilterInterface struct {
	Key   string // like lan or opt1
	Name  string // like LAN
	Group bool   // an interface group
}

// FilterInterfaces returns the interfaces and interface groups of the rule editor (get_interface_list)
func (opn *FirewallApi) FilterInterfaces() ([]FilterInterface, error) {
	var sections map[string]struct {
		Items []struct {
			Value string `json:"value"`
			Label string `json:"label"`
			Type  string `json:"type"`
		} `json:"items"`
	}
	if err := opn.DoJSON("GET", opn.filterEndpoint("get_interface_list"), nil, &sections); err != nil {
		return nil, err
	}
	var interfaces []FilterInterface
	for _, section := range []string{"interfaces", "groups"} {
		for _, item := range sections[section].Items {
			interfaces = append(interfaces, FilterInterface{Key: item.Value, Name: item.Label, Group: item.Type == "group"})
		}
	}
	return interfaces, nil
}

// FilterCategory is a firewall category with the number of rules using it
type FilterCategory struct {
	Uuid  string `json:"uuid"`
	Name  string `json:"name"`
	Color string `json:"color"`
	Used  int    `json:"used"`
}

// FilterCategories returns the firewall categories sorted by name (list_categories)
func (opn *FirewallApi) FilterCategories() ([]FilterCategory, error) {
	var result struct {
		Rows []FilterCategory `json:"rows"`
	}
	if err := opn.DoJSON("GET", opn.filterEndpoint("list_categories"), nil, &result); err != nil {
		return nil, err
	}
	return result.Rows, nil
}

// FilterNetworkOptions returns the named networks rules can use (any, (self), lan, lanip, ... and the network aliases)
// as key -> description (list_network_select_options)
func (opn *FirewallApi) FilterNetworkOptions() (map[string]string, error) {
	return opn.filterSelectOptions("list_network_select_options", "networks", "aliases")
}

// FilterPortOptions returns the well-known port names and port aliases as key -> description
// (list_port_select_options), without the "any" option ("")
func (opn *FirewallApi) FilterPortOptions() (map[string]string, error) {
	return opn.filterSelectOptions("list_port_select_options", "ports", "aliases")
}

func (opn *FirewallApi) filterSelectOptions(method string, sections ...string) (map[string]string, error) {
	var answer map[string]struct {
		Items json.RawMessage `json:"items"`
	}
	if err := opn.DoJSON("GET", opn.filterEndpoint(method), nil, &answer); err != nil {
		return nil, err
	}
	var result = map[string]string{}
	for _, section := range sections {
		var items map[string]string
		// PHP sends an empty list as [] instead of {}
		if raw := answer[section].Items; len(raw) > 0 && raw[0] == '{' {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("unexpected %s of %s: %w", section, method, err)
			}
		}
		for key, value := range items {
			if key != "" {
				result[key] = value
			}
		}
	}
	return result, nil
}

// ErrFilterRollbackUnsupported is returned by the savepoint / rollback calls on OPNsense versions without them:
// OPNsense 26.7 removed savepoint, cancel_rollback and revert (and the rollback of apply)
var ErrFilterRollbackUnsupported = errors.New("this OPNsense version has no filter savepoints / rollback (removed in 26.7)")

// filterUnsupported maps the answers of a missing endpoint (404 or an empty 200) to ErrFilterRollbackUnsupported
func filterUnsupported(err error) error {
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 404 || err != nil && strings.HasPrefix(err.Error(), "empty response") {
		return ErrFilterRollbackUnsupported
	}
	return err
}

// FilterApply loads the saved rules into pf (filter reload)
func (opn *FirewallApi) FilterApply() error {
	return opn.filterApply(opn.filterEndpoint("apply"))
}

// FilterApplyWithRollback loads the saved rules into pf and starts the rollback timer of OPNsense (up to 26.1):
// unless FilterCancelRollback(revision) follows within 60 seconds the rules of savepoint revision are restored
func (opn *FirewallApi) FilterApplyWithRollback(revision string) error {
	if err := filterValidateRevision(revision); err != nil {
		return err
	}
	return opn.filterApply(opn.filterEndpoint("apply") + "/" + revision)
}

func (opn *FirewallApi) filterApply(endpoint string) error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("applying the filter rules failed: status %q", strings.TrimSpace(result.Status))
	}
	return nil
}

var filterRevisionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func filterValidateRevision(revision string) error {
	if !filterRevisionPattern.MatchString(revision) {
		return fmt.Errorf("invalid savepoint revision %q: expected a number like 1729876543.1234", revision)
	}
	return nil
}

// FilterSavepoint stores the current configuration as savepoint and returns its revision (OPNsense up to 26.1).
// Returns ErrFilterRollbackUnsupported on versions without savepoints
func (opn *FirewallApi) FilterSavepoint() (string, error) {
	var result struct {
		Status   string `json:"status"`
		Revision string `json:"revision"`
	}
	if err := opn.DoJSON("POST", opn.filterEndpoint("savepoint"), nil, &result); err != nil {
		return "", filterUnsupported(err)
	}
	if result.Status != "ok" || filterValidateRevision(result.Revision) != nil {
		return "", fmt.Errorf("creating a savepoint failed: status %q, revision %q", result.Status, result.Revision)
	}
	return result.Revision, nil
}

// FilterCancelRollback stops the rollback timer started by FilterApplyWithRollback(revision), the applied rules
// stay. Fails when the timer is not running (any more): the rollback has happened already
func (opn *FirewallApi) FilterCancelRollback(revision string) error {
	if err := filterValidateRevision(revision); err != nil {
		return err
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.filterEndpoint("cancel_rollback")+"/"+revision, nil, &result); err != nil {
		return filterUnsupported(err)
	}
	var status = strings.ToLower(strings.TrimSpace(result.Status))
	if strings.Contains(status, "error") || strings.Contains(status, "fail") {
		return fmt.Errorf("no rollback of savepoint %s is pending (the rules may have been reverted already): %s", revision, strings.TrimSpace(result.Status))
	}
	return nil
}

// FilterRevert restores the rules of savepoint revision and applies them
func (opn *FirewallApi) FilterRevert(revision string) error {
	if err := filterValidateRevision(revision); err != nil {
		return err
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.filterEndpoint("revert")+"/"+revision, nil, &result); err != nil {
		return filterUnsupported(err)
	}
	if strings.TrimSpace(result.Status) != "ok" {
		return fmt.Errorf("reverting to savepoint %s failed: %s", revision, strings.TrimSpace(result.Status))
	}
	return nil
}
