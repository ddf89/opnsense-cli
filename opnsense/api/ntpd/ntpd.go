// Package ntpd wraps the NTP status of Services > Network Time > Status (api/ntpd/service). The NTP settings are
// legacy pages (services_ntpd.php) without API
package ntpd

import (
	"encoding/json"
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
)

// NtpdApi wraps api/ntpd/service
//
//goland:noinspection GoNameStartsWithPackageName
type NtpdApi struct {
	*coreapi.OPNsense
}

// Peer is one line of ntpq -p: a configured server, pool or peer of ntpd
type Peer struct {
	// Status is the tally code: * system peer, + candidate, o PPS peer, # selected (backup), . excess, x false
	// ticker, - outlier, " " not considered, and __pool for a DNS pool entry
	Status string `json:"status"`
	Server string `json:"server"`
	RefId  string `json:"refid"`
	// Stratum is the distance from the reference clock, 16 = unsynchronized
	Stratum string `json:"stratum"`
	// Type is u(nicast), b(roadcast), l(ocal), m(ulticast), s(ymmetric) or p(ool)
	Type string `json:"type"`
	// When is how many seconds ago the last packet was received, "-" for never
	When string `json:"when"`
	// Poll is the poll interval in seconds
	Poll string `json:"poll"`
	// Reach is the octal reachability register of the last 8 polls (377 = all answered)
	Reach string `json:"reach"`
	// Delay, Offset and Jitter are in milliseconds
	Delay  string `json:"delay"`
	Offset string `json:"offset"`
	Jitter string `json:"jitter"`
	// Raw is the row as OPNsense returned it
	Raw json.RawMessage `json:"-"`
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	type plain Peer
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = Peer(decoded)
	p.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// PeerStatusNames are the meanings of the tally codes of Peer.Status as the GUI shows them
var PeerStatusNames = map[string]string{
	"*":      "active peer",
	"+":      "candidate",
	"o":      "PPS peer",
	"#":      "selected",
	".":      "excess peer",
	"x":      "false ticker",
	"-":      "outlier",
	"__pool": "DNS pool",
	" ":      "not considered",
	"":       "not considered",
}

// PeerTypeNames are the meanings of Peer.Type
var PeerTypeNames = map[string]string{
	"u": "unicast", "b": "broadcast", "l": "local", "m": "multicast", "s": "symmetric", "p": "pool",
}

// Status returns the peers of ntpd (ntpq -p). It is empty when ntpd does not run. The endpoint ignores
// ?searchPhrase=, filter the result
func (opn *NtpdApi) Status() ([]Peer, error) {
	return coreapi.Search[Peer](opn.OPNsense, opn.EndpointForPluginControllerMethod("ntpd", "service", "status"), "")
}

// Gps returns the GPS status of ntpd (ntpd/service/gps "gps" section), nil without a GPS clock
func (opn *NtpdApi) Gps() (map[string]any, error) {
	var answer struct {
		Gps json.RawMessage `json:"gps"`
	}
	if err := opn.DoJSON("GET", opn.EndpointForPluginControllerMethod("ntpd", "service", "gps"), nil, &answer); err != nil {
		return nil, err
	}
	var gps map[string]any
	if len(answer.Gps) == 0 || answer.Gps[0] == '[' { // PHP sends an empty map as []
		return nil, nil
	}
	if err := json.Unmarshal(answer.Gps, &gps); err != nil {
		return nil, fmt.Errorf("unexpected GPS status from ntpd: %w", err)
	}
	if len(gps) == 0 {
		return nil, nil
	}
	return gps, nil
}
