package diagnostics

import (
	"encoding/json"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"regexp"
	"strconv"
	"strings"
)

// The pf state table of Firewall > Diagnostics > States (api/diagnostics/firewall): list, drop one state, drop
// states by filter, flush everything, the rule ids of the running ruleset and the state counter

// FirewallState is one pf state (pfctl -vvs state, parsed by OPNsense)
type FirewallState struct {
	// Id identifies the state as "<state id>/<creator id>" (hex), e.g. "6f14de6a00000000/0449ade0"
	Id string `json:"id"`
	// Iface is the device the state is bound to, "all" for floating states (the default state policy);
	// Interface is its name (WAN, loopback) when known
	Iface     string `json:"iface"`
	Interface string `json:"interface"`
	// Proto is the protocol (tcp, udp, icmp, ...), IpProto ipv4 or ipv6
	Proto   string `json:"proto"`
	IpProto string `json:"ipproto"`
	// Direction is in or out as seen by the interface
	Direction string `json:"direction"`
	SrcAddr   string `json:"src_addr"`
	SrcPort   string `json:"src_port"`
	DstAddr   string `json:"dst_addr"`
	DstPort   string `json:"dst_port"`
	// NatAddr and NatPort are the address and port before translation, empty without NAT
	NatAddr string `json:"nat_addr"`
	NatPort string `json:"nat_port"`
	// Gateway is set for route-to / reply-to states
	Gateway string `json:"gateway"`
	// State is the connection state of both sides, e.g. ESTABLISHED:ESTABLISHED or MULTIPLE:SINGLE
	State string `json:"state"`
	// Age and Expires are durations like 00:01:26 (hours can exceed 24)
	Age     string `json:"age"`
	Expires string `json:"expires"`
	// Pkts and Bytes are the counters of both directions: [from the initiator, to the initiator]
	Pkts  []int64 `json:"pkts"`
	Bytes []int64 `json:"bytes"`
	// Rule is the number of the rule in the running ruleset, Label its rule id, Descr its description
	Rule  string   `json:"rule"`
	Label string   `json:"label"`
	Descr string   `json:"descr"`
	Flags []string `json:"flags"`

	// Raw is the state as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

func (state *FirewallState) UnmarshalJSON(data []byte) error {
	type plainState FirewallState
	var plain plainState
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	*state = FirewallState(plain)
	state.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// TotalPackets returns the packets of both directions
func (state FirewallState) TotalPackets() int64 {
	return firewallSum(state.Pkts)
}

// TotalBytes returns the bytes of both directions
func (state FirewallState) TotalBytes() int64 {
	return firewallSum(state.Bytes)
}

func firewallSum(values []int64) int64 {
	var sum int64
	for _, value := range values {
		sum += value
	}
	return sum
}

// FirewallStateQuery selects states on the firewall
type FirewallStateQuery struct {
	// Search is OPNsense's filter: words that are addresses or networks (optionally with :port, IPv6 as
	// [addr]:port) must match the source, destination, NAT address or gateway; all other words must occur
	// (case-sensitive) in any field
	Search string
	// RuleId only returns states created by this rule id (label), a case-sensitive substring match
	RuleId string
}

// firewallStatesMaxRows is sent as rowCount, OPNsense returns at most 9999 states without it
const firewallStatesMaxRows = 10000000

// FirewallStateList returns the states matching query in the order of pfctl
func (opn *DiagnosticsApi) FirewallStateList(query FirewallStateQuery) ([]FirewallState, error) {
	var body = map[string]any{"current": 1, "rowCount": firewallStatesMaxRows}
	if query.Search != "" {
		body["searchPhrase"] = query.Search
	}
	if query.RuleId != "" {
		body["ruleid"] = query.RuleId
	}
	var container struct {
		Rows  []FirewallState `json:"rows"`
		Total *int            `json:"total"`
	}
	var endpoint = opn.endpoint("firewall", "query_states")
	if err := opn.DoJSON("POST", endpoint, body, &container); err != nil {
		return nil, err
	}
	if container.Total == nil {
		return nil, fmt.Errorf("unexpected answer from %s: no total", endpoint)
	}
	if container.Rows == nil {
		container.Rows = []FirewallState{}
	}
	return container.Rows, nil
}

// firewallStateIdPattern is "<state id>/<creator id>" in hex
var firewallStateIdPattern = regexp.MustCompile(`^[0-9a-fA-F]+/[0-9a-fA-F]+$`)

var firewallKilledPattern = regexp.MustCompile(`killed (\d+) states`)

// FirewallStateRemove drops the state id ("<state id>/<creator id>" as listed). Returns *NotFoundError when pf
// has no such state (any more)
func (opn *DiagnosticsApi) FirewallStateRemove(id string) error {
	if !firewallStateIdPattern.MatchString(id) {
		return fmt.Errorf("invalid state id %q, must be <state id>/<creator id> in hex as listed", id)
	}
	var container struct {
		Result string `json:"result"`
	}
	var endpoint = opn.endpoint("firewall", "del_state/"+id)
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &container); err != nil {
		return err
	}
	// the result is the output of pfctl -k id -k <id>, e.g. "killed 1 states from 1 specified"
	var match = firewallKilledPattern.FindStringSubmatch(container.Result)
	if match == nil {
		return fmt.Errorf("unexpected answer from %s: %q", endpoint, strings.TrimSpace(container.Result))
	}
	if match[1] == "0" {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("state %s", id)}
	}
	return nil
}

// FirewallStateKill drops the states matching filter and/or ruleId on the firewall and returns how many were
// dropped. At least one must be given.
//
// Beware of OPNsense's sanitizing: filter keeps only letters, digits, space, comma, "*-_.#" (so CIDR networks,
// ports and IPv6 addresses are mangled into text that is matched as a substring), ruleId only letters and digits
// (the dashes of uuid rule ids are removed, so they match nothing). Select the states with FirewallStateList and
// drop them with FirewallStateRemove for exact results
func (opn *DiagnosticsApi) FirewallStateKill(filter string, ruleId string) (int, error) {
	if strings.TrimSpace(filter) == "" && strings.TrimSpace(ruleId) == "" {
		return 0, fmt.Errorf("refusing to kill states without filter or rule id")
	}
	var body = map[string]any{}
	if filter != "" {
		body["filter"] = filter
	}
	if ruleId != "" {
		body["ruleid"] = ruleId
	}
	var container struct {
		Result        string `json:"result"`
		DroppedStates *int   `json:"dropped_states"`
	}
	var endpoint = opn.endpoint("firewall", "kill_states")
	if err := opn.DoJSON("POST", endpoint, body, &container); err != nil {
		return 0, err
	}
	if container.Result != "ok" || container.DroppedStates == nil {
		return 0, fmt.Errorf("killing states failed: result %q", container.Result)
	}
	return *container.DroppedStates, nil
}

// FirewallStateFlush drops every state (pfctl -F state): every connection through and to the firewall is cut,
// including the one making this call
func (opn *DiagnosticsApi) FirewallStateFlush() error {
	return opn.firewallResultOk("flush_states")
}

// FirewallSourceFlush clears the source tracking table (pfctl -F Sources): sticky addresses and per source limits
func (opn *DiagnosticsApi) FirewallSourceFlush() error {
	return opn.firewallResultOk("flush_sources")
}

func (opn *DiagnosticsApi) firewallResultOk(method string) error {
	var container struct {
		Result string `json:"result"`
	}
	// actions must be POSTed, a GET answers {"result":"failed"} without doing anything
	var endpoint = opn.endpoint("firewall", method)
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &container); err != nil {
		return err
	}
	if container.Result != "ok" {
		return fmt.Errorf("%s failed: result %q", method, container.Result)
	}
	return nil
}

// FirewallRuleId is a rule id (pf label) of the running ruleset with its description
type FirewallRuleId struct {
	Id string `json:"id"`
	// Descr is the rule description, "-- <id>" for rules without description
	Descr string `json:"descr"`
}

// FirewallRuleIds returns the rule ids of the running ruleset, sorted by description
func (opn *DiagnosticsApi) FirewallRuleIds() ([]FirewallRuleId, error) {
	var container struct {
		Items []FirewallRuleId `json:"items"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("firewall", "list_rule_ids"), nil, &container); err != nil {
		return nil, err
	}
	if container.Items == nil {
		container.Items = []FirewallRuleId{}
	}
	return container.Items, nil
}

// FirewallStateCount is the number of states and the hard limit of the state table
type FirewallStateCount struct {
	Current int64
	Limit   int64
}

// FirewallStateCountGet returns the number of states and the state limit
func (opn *DiagnosticsApi) FirewallStateCountGet() (FirewallStateCount, error) {
	var container struct {
		Current string `json:"current"`
		Limit   string `json:"limit"`
		Result  string `json:"result"`
	}
	var endpoint = opn.endpoint("firewall", "pf_states")
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return FirewallStateCount{}, err
	}
	var current, currentErr = strconv.ParseInt(container.Current, 10, 64)
	var limit, limitErr = strconv.ParseInt(container.Limit, 10, 64)
	if currentErr != nil || limitErr != nil {
		return FirewallStateCount{}, fmt.Errorf("unexpected answer from %s: current %q, limit %q, result %q",
			endpoint, container.Current, container.Limit, container.Result)
	}
	return FirewallStateCount{Current: current, Limit: limit}, nil
}
