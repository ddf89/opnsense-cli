package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The pf statistics of Firewall > Diagnostics > Statistics (api/diagnostics/firewall/pf_statistics/<section>)

// FirewallStatisticsSections are the sections pf_statistics knows, in GUI order
var FirewallStatisticsSections = []string{"info", "memory", "timeouts", "interfaces", "rules"}

// FirewallStatisticsCounter is a counter of pfctl -si: Table is state-table, source-tracking-table, counters or
// limit-counters, Rate the per second average since the statistics were cleared (HasRate false for gauges like
// current-entries)
type FirewallStatisticsCounter struct {
	Table   string
	Name    string
	Total   int64
	Rate    float64
	HasRate bool
}

// FirewallStatisticsValue is a named value: a memory limit (pfctl -sm) or a timeout (pfctl -st, e.g. "120s")
type FirewallStatisticsValue struct {
	Name  string
	Value string
}

// FirewallStatisticsInterface are the pf counters of an interface (pfctl -vvsI). Counters are named like
// in4_pass_packets, out6_block_bytes
type FirewallStatisticsInterface struct {
	Name       string
	Cleared    string
	References int64
	Counters   map[string]int64
}

// Packets and Bytes sum the counters of direction (in, out) and action (pass, block) over IPv4 and IPv6
func (i FirewallStatisticsInterface) Packets(direction string, action string) int64 {
	return i.Counters[direction+"4_"+action+"_packets"] + i.Counters[direction+"6_"+action+"_packets"]
}

func (i FirewallStatisticsInterface) Bytes(direction string, action string) int64 {
	return i.Counters[direction+"4_"+action+"_bytes"] + i.Counters[direction+"6_"+action+"_bytes"]
}

// FirewallStatisticsRule are the counters of a filter or NAT rule of the running ruleset (pfctl -vvsr / -vvsn)
type FirewallStatisticsRule struct {
	// Ruleset is "filter rules" or "nat rules"
	Ruleset string
	// Rule is the rule as pfctl shows it, starting with its number, e.g. "@3 pass in quick on vtnet0 ..."
	Rule           string
	Evaluations    int64
	Packets        int64
	Bytes          int64
	States         int64
	StateCreations int64
}

// FirewallStatistics holds the sections that were requested, Raw the answer of each as sent by OPNsense
// ({"info":{...}})
type FirewallStatistics struct {
	Info       []FirewallStatisticsCounter
	Memory     []FirewallStatisticsValue
	Timeouts   []FirewallStatisticsValue
	Interfaces []FirewallStatisticsInterface
	Rules      []FirewallStatisticsRule
	Raw        map[string]json.RawMessage
}

// FirewallStatisticsGet returns the given sections (all when none are given). Every section is a request of its
// own: pf_statistics without a section answers [] instead of all sections
func (opn *DiagnosticsApi) FirewallStatisticsGet(sections ...string) (FirewallStatistics, error) {
	if len(sections) == 0 {
		sections = FirewallStatisticsSections
	}
	var result = FirewallStatistics{Raw: map[string]json.RawMessage{}}
	for _, section := range sections {
		var known = false
		for _, name := range FirewallStatisticsSections {
			known = known || name == section
		}
		if !known {
			return FirewallStatistics{}, fmt.Errorf("unknown statistics section %q, must be one of %s", section,
				strings.Join(FirewallStatisticsSections, ", "))
		}

		var raw json.RawMessage
		var endpoint = opn.endpoint("firewall", "pf_statistics/"+section)
		if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
			return FirewallStatistics{}, err
		}
		var container map[string]json.RawMessage
		if err := json.Unmarshal(raw, &container); err != nil || container[section] == nil {
			return FirewallStatistics{}, fmt.Errorf("unexpected answer from %s: %.100s", endpoint, raw)
		}
		result.Raw[section] = raw
		if err := result.decode(section, container[section]); err != nil {
			return FirewallStatistics{}, fmt.Errorf("could not decode the %s statistics: %w", section, err)
		}
	}
	return result, nil
}

func (s *FirewallStatistics) decode(section string, data json.RawMessage) error {
	var members, err = firewallObjectMembers(data)
	if err != nil {
		return err
	}
	switch section {
	case "info":
		for _, table := range members {
			var counters, err = firewallObjectMembers(table.value)
			if err != nil {
				return err
			}
			for _, counter := range counters {
				var value struct {
					Total int64    `json:"total"`
					Rate  *float64 `json:"rate"`
				}
				if err := json.Unmarshal(counter.value, &value); err != nil {
					return err
				}
				var entry = FirewallStatisticsCounter{Table: table.key, Name: counter.key, Total: value.Total}
				if value.Rate != nil {
					entry.Rate, entry.HasRate = *value.Rate, true
				}
				s.Info = append(s.Info, entry)
			}
		}
	case "memory", "timeouts":
		var values = make([]FirewallStatisticsValue, 0, len(members))
		for _, member := range members {
			var text string
			if json.Unmarshal(member.value, &text) != nil {
				text = string(member.value) // a number
			}
			values = append(values, FirewallStatisticsValue{Name: member.key, Value: text})
		}
		if section == "memory" {
			s.Memory = values
		} else {
			s.Timeouts = values
		}
	case "interfaces":
		for _, member := range members {
			var fields map[string]any
			if err := json.Unmarshal(member.value, &fields); err != nil {
				return err
			}
			var entry = FirewallStatisticsInterface{Name: member.key, Counters: map[string]int64{}}
			for name, value := range fields {
				switch typed := value.(type) {
				case string:
					if name == "cleared" {
						entry.Cleared = typed
					}
				case float64:
					if name == "references" {
						entry.References = int64(typed)
					} else {
						entry.Counters[name] = int64(typed)
					}
				}
			}
			s.Interfaces = append(s.Interfaces, entry)
		}
	case "rules":
		for _, ruleset := range members {
			var rules, err = firewallObjectMembers(ruleset.value)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				// the values are numbers, except a few broken up texts ("inserted", "time")
				var fields map[string]any
				if err := json.Unmarshal(rule.value, &fields); err != nil {
					return err
				}
				var number = func(name string) int64 {
					var value, _ = fields[name].(float64)
					return int64(value)
				}
				s.Rules = append(s.Rules, FirewallStatisticsRule{
					Ruleset: ruleset.key, Rule: rule.key, Evaluations: number("evaluations"), Packets: number("packets"),
					Bytes: number("bytes"), States: number("states"), StateCreations: number("state_creations"),
				})
			}
		}
	}
	return nil
}

type firewallMember struct {
	key   string
	value json.RawMessage
}

// firewallObjectMembers returns the members of a JSON object in their order (pfctl's order), an empty
// array (PHP's empty object) gives none
func firewallObjectMembers(data json.RawMessage) ([]firewallMember, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("[]")) {
		return nil, nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(data))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, fmt.Errorf("not an object: %.50s", data)
	}
	var members []firewallMember
	for decoder.More() {
		var keyToken, keyErr = decoder.Token()
		if keyErr != nil {
			return nil, keyErr
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		members = append(members, firewallMember{key: key, value: value})
	}
	return members, nil
}
