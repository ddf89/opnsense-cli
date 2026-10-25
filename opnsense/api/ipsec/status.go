package ipsec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// The status pages of VPN > IPsec: Status Overview (api/ipsec/sessions), Security Association Database
// (api/ipsec/sad), Security Policy Database (api/ipsec/spd) and Lease Status (api/ipsec/leases). The rows are
// built by configd scripts from strongSwan (vici, swanctl) and the kernel (setkey), Record renders their values
// as text.
//
// Session (phase 1) rows: name (the strongSwan connection name: the connection uuid, or con<ikeid> for legacy
// tunnels), phase1desc, version, local-addrs, remote-addrs, local-id, remote-id, local-class, remote-class,
// connected and routed ("1"/"0"), install-time, bytes-in/-out, packets-in/-out. Phase 2 rows (child SAs): name,
// uniqueid, reqid, state, mode, protocol, spi-in, spi-out, encr-alg, encr-keysize, integ-alg, dh-group, local-ts,
// remote-ts, remote-host, bytes-in/-out, packets-in/-out, install-time, rekey-time, life-time, phase2desc.
// SAD rows: id (md5 used by delete), src, dst, satype, spi, mode, reqid, alg_enc, alg_auth, bytes_current, ...,
// phase1desc / phase2desc when the reqid belongs to a configured child. SPD rows: id, src, dst, src_port,
// dst_port, upperspec, dir, type, proto, mode, src-dst, level, reqid, phase1desc / phase2desc. Lease rows: pool,
// address, online ("1"/"0"), user

// statusIdPattern matches the md5 ids of SAD and SPD rows
var statusIdPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// statusRows GETs (or POSTs body to) a searchRecordsetBase endpoint
func (opn *IPsecApi) statusRows(method string, endpoint string, body any) ([]Record, error) {
	var container struct {
		Rows []Record `json:"rows"`
	}
	if err := opn.DoJSON(method, endpoint, body, &container); err != nil {
		return nil, err
	}
	if container.Rows == nil {
		container.Rows = []Record{}
	}
	return container.Rows, nil
}

// SessionList returns the phase 1 sessions: every connection strongSwan has loaded (routed) and every IKE SA
// (connected). Empty while strongSwan is not running
func (opn *IPsecApi) SessionList() ([]Record, error) {
	return opn.statusRows("GET", opn.endpoint("sessions", "search_phase1"), nil)
}

// SessionChildren returns the phase 2 (child) SAs of the session with this name (the name field of SessionList)
func (opn *IPsecApi) SessionChildren(name string) ([]Record, error) {
	if name == "" {
		return nil, fmt.Errorf("no session name given")
	}
	// the connection is read from the POST body, a GET lists nothing
	return opn.statusRows("POST", opn.endpoint("sessions", "search_phase2"), map[string]string{"id": name})
}

// SessionConnect initiates all children of the strongSwan connection with this name (swanctl --initiate).
// OPNsense answers ok for any name, unknown names are ignored
func (opn *IPsecApi) SessionConnect(name string) error {
	return opn.sessionAction("connect", name)
}

// SessionDisconnect terminates the IKE SA of the strongSwan connection with this name (swanctl --terminate).
// OPNsense answers ok for any name, unknown or not connected names are ignored
func (opn *IPsecApi) SessionDisconnect(name string) error {
	return opn.sessionAction("disconnect", name)
}

func (opn *IPsecApi) sessionAction(action string, name string) error {
	if name == "" || strings.ContainsAny(name, "/?#") {
		return fmt.Errorf("invalid session name %q", name)
	}
	var answer struct {
		Result string `json:"result"`
	}
	var endpoint = opn.endpoint("sessions", action) + "/" + url.PathEscape(name)
	// a GET is answered with {"result":"failed"}
	if err := opn.DoJSON("POST", endpoint, nil, &answer); err != nil {
		return err
	}
	if answer.Result != "ok" {
		return fmt.Errorf("ipsec session %s %s failed: result %q", action, name, answer.Result)
	}
	return nil
}

// SadList returns the security associations of the kernel. The row OPNsense makes of setkey's "No SAD entries."
// (src "No", dst "SAD", no satype and spi) is dropped
func (opn *IPsecApi) SadList() ([]Record, error) {
	var rows, err = opn.statusRows("GET", opn.endpoint("sad", "search"), nil)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(rows, func(row Record) bool {
		return row.Value("satype") != "" || row.Value("spi") != ""
	}), nil
}

// SadRemove deletes the security association with this id (the id field of SadList) from the kernel
func (opn *IPsecApi) SadRemove(id string) error {
	return opn.statusRemove("sad", "security association", id)
}

// SpdList returns the security policies of the kernel
func (opn *IPsecApi) SpdList() ([]Record, error) {
	return opn.statusRows("GET", opn.endpoint("spd", "search"), nil)
}

// SpdRemove deletes the security policy with this id (the id field of SpdList) from the kernel
func (opn *IPsecApi) SpdRemove(id string) error {
	return opn.statusRemove("spd", "security policy", id)
}

// statusRemove POSTs sad/delete or spd/delete, which answer {"status":"found"|"not_found","items":[...],"result":"ok"}
func (opn *IPsecApi) statusRemove(controller string, noun string, id string) error {
	if !statusIdPattern.MatchString(id) {
		return fmt.Errorf("invalid %s id %q, expected the 32 hex digits of the id field", noun, id)
	}
	var answer struct {
		Result string          `json:"result"`
		Status string          `json:"status"`
		Items  json.RawMessage `json:"items"`
	}
	if err := opn.DoJSON("POST", opn.endpoint(controller, "delete")+"/"+id, nil, &answer); err != nil {
		return err
	}
	switch {
	case answer.Result != "ok":
		return fmt.Errorf("removing the %s %s failed: result %q", noun, id, answer.Result)
	case answer.Status == "not_found":
		return &coreapi.NotFoundError{Name: fmt.Sprintf("%s %s", noun, id)}
	}
	return nil
}

// LeaseList returns the addresses strongSwan leased from its pools (swanctl --list-pools --leases)
func (opn *IPsecApi) LeaseList() ([]Record, error) {
	return opn.statusRows("GET", opn.endpoint("leases", "search"), nil)
}

// LeasePools returns the pools strongSwan has loaded with their usage, sorted by name: name, net (the first
// address), online, offline and size
func (opn *IPsecApi) LeasePools() ([]Record, error) {
	var answer struct {
		Pools json.RawMessage `json:"pools"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("leases", "pools"), nil, &answer); err != nil {
		return nil, err
	}
	// an empty PHP array arrives as [], pools as an object keyed by name
	var pools = map[string]Record{}
	if trimmed := strings.TrimSpace(string(answer.Pools)); trimmed != "" && trimmed[0] == '{' {
		if err := json.Unmarshal(answer.Pools, &pools); err != nil {
			return nil, fmt.Errorf("could not decode the ipsec pools: %w", err)
		}
	}
	var names = make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	var result = make([]Record, 0, len(names))
	for _, name := range names {
		result = append(result, pools[name])
	}
	return result, nil
}
