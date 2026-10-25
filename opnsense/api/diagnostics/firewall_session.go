package diagnostics

import (
	"encoding/json"
	"fmt"
)

// FirewallSession is one connection of the pftop view (Firewall > Diagnostics > Sessions, api/diagnostics/firewall/query_pf_top)
type FirewallSession struct {
	Proto string `json:"proto"`
	// Dir is in or out
	Dir     string `json:"dir"`
	SrcAddr string `json:"src_addr"`
	SrcPort string `json:"src_port"`
	DstAddr string `json:"dst_addr"`
	DstPort string `json:"dst_port"`
	// GwAddr and GwPort are the translated (NAT) or gateway endpoint, empty when there is none
	GwAddr string `json:"gw_addr"`
	GwPort string `json:"gw_port"`
	State  string `json:"state"`
	// Age and Expire are seconds
	Age    int64 `json:"age"`
	Expire int64 `json:"expire"`
	Pkts   int64 `json:"pkts"`
	Bytes  int64 `json:"bytes"`
	// Avg is the average rate in bytes per second
	Avg int64 `json:"avg"`
	// Rule is the number of the rule in the running ruleset, Label its rule id and Descr its description (when known)
	Rule  string `json:"rule"`
	Label string `json:"label"`
	Descr string `json:"descr"`

	// Raw is the session as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

func (session *FirewallSession) UnmarshalJSON(data []byte) error {
	type plainSession FirewallSession
	var plain plainSession
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	*session = FirewallSession(plain)
	session.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// FirewallSessionQuery selects sessions
type FirewallSessionQuery struct {
	// Search are words: addresses and networks must match the source, destination or gateway address, all other
	// words must occur in any field (case-insensitive)
	Search string
	// RuleId only returns sessions of this rule id (label), exact match
	RuleId string
}

// FirewallSessionList returns the sessions matching query. OPNsense caches the pftop output for 30 seconds, so
// the values change at most every 30 seconds
func (opn *DiagnosticsApi) FirewallSessionList(query FirewallSessionQuery) ([]FirewallSession, error) {
	var body = map[string]any{}
	if query.Search != "" {
		body["searchPhrase"] = query.Search
	}
	if query.RuleId != "" {
		body["ruleid"] = query.RuleId
	}
	var container struct {
		Rows  []FirewallSession `json:"rows"`
		Total *int              `json:"total"`
	}
	var endpoint = opn.endpoint("firewall", "query_pf_top")
	// without rowCount every row is returned
	if err := opn.DoJSON("POST", endpoint, body, &container); err != nil {
		return nil, err
	}
	if container.Total == nil {
		return nil, fmt.Errorf("unexpected answer from %s: no total", endpoint)
	}
	if container.Rows == nil {
		container.Rows = []FirewallSession{}
	}
	return container.Rows, nil
}
