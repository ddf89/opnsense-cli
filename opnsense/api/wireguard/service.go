package wireguard

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// GeneralEnabled tells whether WireGuard is enabled globally (VPN > WireGuard, "Enable WireGuard")
func (opn *WireguardApi) GeneralEnabled() (bool, error) {
	var answer struct {
		General *struct {
			Enabled string `json:"enabled"`
		} `json:"general"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("general", "get"), nil, &answer); err != nil {
		return false, err
	}
	if answer.General == nil {
		return false, fmt.Errorf("unexpected answer from %s", opn.endpoint("general", "get"))
	}
	return answer.General.Enabled == "1", nil
}

// GeneralSetEnabled enables or disables WireGuard globally. Like every change it takes effect with
// ServiceReconfigure
func (opn *WireguardApi) GeneralSetEnabled(enabled bool) error {
	var _, err = opn.Mutate(opn.endpoint("general", "set"), map[string]map[string]string{"general": {"enabled": flag(enabled)}})
	return err
}

// ServiceStatus returns the state of the WireGuard service: running, stopped, disabled or unknown
func (opn *WireguardApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status == "" {
		return "", fmt.Errorf("unexpected answer from wireguard service status: no status given")
	}
	return answer.Status, nil
}

// ServiceReconfigure applies the saved configuration: registers the wg interfaces, writes the configuration and
// (re)starts the enabled instances (configd "wireguard configure"); it answers {"result":"ok"}
func (opn *WireguardApi) ServiceReconfigure() error {
	var answer struct {
		Result string `json:"result"`
		Status string `json:"status"`
	}
	// actions must be POSTed, a GET answers {"result":"failed"}
	if err := opn.DoJSON("POST", opn.endpoint("service", "reconfigure"), nil, &answer); err != nil {
		return err
	}
	if answer.Result != "ok" && answer.Status != "ok" {
		return fmt.Errorf("wireguard reconfigure failed: %q", answer.Result+answer.Status)
	}
	return nil
}

// ServiceStart starts WireGuard (all enabled instances)
func (opn *WireguardApi) ServiceStart() error {
	return opn.serviceAction("start")
}

// ServiceStop stops WireGuard (all instances)
func (opn *WireguardApi) ServiceStop() error {
	return opn.serviceAction("stop")
}

// ServiceRestart restarts WireGuard (all enabled instances)
func (opn *WireguardApi) ServiceRestart() error {
	return opn.serviceAction("restart")
}

// serviceAction POSTs start / stop / restart, OPNsense passes the configd answer through as {"response":"OK"}
func (opn *WireguardApi) serviceAction(action string) error {
	var answer struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), nil, &answer); err != nil {
		return err
	}
	if response, isString := answer.Response.(string); !isString || !strings.EqualFold(strings.TrimSpace(response), "OK") {
		return fmt.Errorf("wireguard service %s failed: unexpected response %v", action, answer.Response)
	}
	return nil
}

// Status is one line of wg show all dump (service/show, VPN > WireGuard > Status): an interface (instance) or a
// peer of it. Numbers are decoded from JSON numbers
type Status struct {
	// Interface is the device (wg0), InstanceName the name of its instance
	Interface    string `json:"if"`
	InstanceName string `json:"ifname"`
	// Type is "interface" or "peer"
	Type      string `json:"type"`
	PublicKey string `json:"public-key"`
	// Name is the name of the instance or peer with this public key ("" when unknown)
	Name string `json:"name"`
	// Endpoint is the listen port of an interface, the ip:port of a peer
	Endpoint string `json:"endpoint"`
	// InterfaceStatus is up / down for interfaces
	InterfaceStatus string `json:"status"`
	// PeerStatus is online (handshake within 300s), stale or offline for peers
	PeerStatus          string `json:"peer-status"`
	ListenPort          string `json:"listen-port"`
	AllowedIps          string `json:"allowed-ips"`
	PersistentKeepalive string `json:"persistent-keepalive"`
	// LatestHandshake is the unix time of the latest handshake (0: none), HandshakeAge its age in seconds (nil: none)
	LatestHandshake int64  `json:"latest-handshake"`
	HandshakeAge    *int64 `json:"latest-handshake-age"`
	TransferRx      int64  `json:"transfer-rx"`
	TransferTx      int64  `json:"transfer-tx"`
	// Raw is the row as the API returned it
	Raw json.RawMessage `json:"-"`
}

// Online tells whether an interface is up or a peer had a handshake within the last 300 seconds
func (s Status) Online() bool {
	if s.Type == "interface" {
		return s.InterfaceStatus == "up"
	}
	return s.PeerStatus == "online"
}

// StatusList returns the live WireGuard status (wg show all dump) of the running instances and their peers.
// types filters by "interface" and/or "peer", none for both; searchPhrase is a substring match over all columns
func (opn *WireguardApi) StatusList(searchPhrase string, types ...string) ([]Status, error) {
	var query = url.Values{}
	for _, statusType := range types {
		query.Add("type[]", statusType)
	}
	if searchPhrase != "" {
		query.Set("searchPhrase", searchPhrase)
	}
	var endpoint = opn.endpoint("service", "show")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var answer struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	var result = make([]Status, len(answer.Rows))
	for i, row := range answer.Rows {
		var status, err = decodeStatus(row)
		if err != nil {
			return nil, fmt.Errorf("unexpected wireguard status from OPNsense: %w", err)
		}
		result[i] = status
	}
	return result, nil
}

// decodeStatus decodes a status row; ports, the keepalive and the counters may come as strings or numbers
func decodeStatus(row json.RawMessage) (Status, error) {
	var fields map[string]any
	if err := json.Unmarshal(row, &fields); err != nil {
		return Status{}, err
	}
	var text = func(name string) string {
		switch value := fields[name].(type) {
		case string:
			return value
		case float64:
			return fmt.Sprint(int64(value))
		case bool:
			return fmt.Sprint(value)
		}
		return ""
	}
	var number = func(name string) (int64, bool) {
		switch value := fields[name].(type) {
		case float64:
			return int64(value), true
		case string:
			var parsed int64
			if _, err := fmt.Sscan(value, &parsed); err == nil {
				return parsed, true
			}
		}
		return 0, false
	}
	var status = Status{
		Interface: text("if"), InstanceName: text("ifname"), Type: text("type"), PublicKey: text("public-key"),
		Name: text("name"), Endpoint: text("endpoint"), InterfaceStatus: text("status"), PeerStatus: text("peer-status"),
		ListenPort: text("listen-port"), AllowedIps: text("allowed-ips"), PersistentKeepalive: text("persistent-keepalive"),
		Raw: row,
	}
	status.LatestHandshake, _ = number("latest-handshake")
	status.TransferRx, _ = number("transfer-rx")
	status.TransferTx, _ = number("transfer-tx")
	if age, ok := number("latest-handshake-age"); ok {
		status.HandshakeAge = &age
	}
	return status, nil
}
