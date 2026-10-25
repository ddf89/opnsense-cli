package openvpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// Session is a row of VPN > OpenVPN > Connection Status, Sessions (api/openvpn/service/search_sessions). The rows are
// built by ovpn_status.py from the management sockets ("status 3" / "state") and merged by OPNsense:
//   - a connected client of a server: the server's fields merged with the client list entry, IsClient is true and
//     Id is "<instance>_<real address>"
//   - a running server without clients, a client instance (Status e.g. "connected"): Id is the instance
//   - an enabled instance that is not running: only Id, ServiceId, Type and Description, Status is empty
//
// All rows carry the same keys (missing ones are null), numbers come as strings. Raw is the row as received
type Session struct {
	Id          string
	Type        string // "server" or "client" (the role of the instance)
	Description string // of the instance
	ServiceId   string // "openvpn/<instance>", only for instances that are not running
	IsClient    bool   // a client connected to a server
	// Status is "ok" for a running server, the OpenVPN state (e.g. "connected") for a client instance, empty when
	// the instance is not running
	Status string
	// CommonName, Username, VirtualAddress and VirtualIpv6Address are set for connected clients
	CommonName         string
	Username           string
	RealAddress        string // address:port of the peer
	VirtualAddress     string
	VirtualIpv6Address string
	// BytesReceived / BytesSent are counted by the instance: received from / sent to the peer
	BytesReceived string
	BytesSent     string
	// ConnectedSince is OpenVPN's text (e.g. "2026-10-25 14:03:12"), ConnectedSinceEpoch the unix time when known
	ConnectedSince      string
	ConnectedSinceEpoch int64
	ClientId            string
	PeerId              string
	DataChannelCipher   string
	Raw                 json.RawMessage
}

// UnmarshalJSON decodes a row leniently: every value may be a string, a number, a bool or null
func (s *Session) UnmarshalJSON(data []byte) error {
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	var text = func(key string) string { return statusText(row[key]) }
	*s = Session{
		Id:                 text("id"),
		Type:               text("type"),
		Description:        text("description"),
		ServiceId:          text("service_id"),
		IsClient:           statusBool(row["is_client"]),
		Status:             text("status"),
		CommonName:         text("common_name"),
		Username:           text("username"),
		RealAddress:        text("real_address"),
		VirtualAddress:     text("virtual_address"),
		VirtualIpv6Address: text("virtual_ipv6_address"),
		BytesReceived:      text("bytes_received"),
		BytesSent:          text("bytes_sent"),
		ConnectedSince:     text("connected_since"),
		ClientId:           text("client_id"),
		PeerId:             text("peer_id"),
		DataChannelCipher:  text("data_channel_cipher"),
		Raw:                append(json.RawMessage(nil), data...),
	}
	// clients of a server: "Connected Since (time_t)", client instances and p2p servers: the state timestamp
	for _, key := range []string{"connected_since__time_t_", "timestamp"} {
		if epoch, err := strconv.ParseInt(text(key), 10, 64); err == nil && epoch > 0 {
			s.ConnectedSinceEpoch = epoch
			break
		}
	}
	return nil
}

// InstanceId returns the instance (uuid, or vpnid of a legacy server) the session belongs to
func (s Session) InstanceId() string {
	if s.IsClient {
		var instance, _, _ = strings.Cut(s.Id, "_")
		return instance
	}
	return s.Id
}

// Running tells whether the instance of the row is running (instances that are not running have no status)
func (s Session) Running() bool {
	return s.Status != "" || s.IsClient
}

// ConnectedSinceTime returns when the session was established, ok is false when unknown
func (s Session) ConnectedSinceTime() (since time.Time, ok bool) {
	if s.ConnectedSinceEpoch <= 0 {
		return time.Time{}, false
	}
	return time.Unix(s.ConnectedSinceEpoch, 0), true
}

// Route is a row of VPN > OpenVPN > Connection Status, Routes (api/openvpn/service/search_routes): an entry of a
// server's routing table ("status 3" ROUTING_TABLE). Raw is the row as received
type Route struct {
	Id          string // the instance
	Type        string // "server" or "client"
	Description string // of the instance
	// VirtualAddress is the target: a client's virtual address or a network behind it (iroute)
	VirtualAddress string
	CommonName     string
	RealAddress    string
	// LastRef is OpenVPN's text of the last use, LastRefEpoch the unix time when known
	LastRef      string
	LastRefEpoch int64
	Raw          json.RawMessage
}

// UnmarshalJSON decodes a row leniently: every value may be a string, a number, a bool or null
func (r *Route) UnmarshalJSON(data []byte) error {
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	var text = func(key string) string { return statusText(row[key]) }
	*r = Route{
		Id:             text("id"),
		Type:           text("type"),
		Description:    text("description"),
		VirtualAddress: text("virtual_address"),
		CommonName:     text("common_name"),
		RealAddress:    text("real_address"),
		LastRef:        text("last_ref"),
		Raw:            append(json.RawMessage(nil), data...),
	}
	if epoch, err := strconv.ParseInt(text("last_ref__time_t_"), 10, 64); err == nil && epoch > 0 {
		r.LastRefEpoch = epoch
	}
	return nil
}

func statusText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "1"
		}
		return "0"
	default:
		var encoded, _ = json.Marshal(v)
		return string(encoded)
	}
}

func statusBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "1" || v == "true"
	case float64:
		return v != 0
	}
	return false
}

func (opn *OpenVPNApi) statusServiceEndpoint(method string) string {
	return opn.endpoint("service", method)
}

// statusSearch queries a service/search_* endpoint, types limits the rows to instances of these roles
// ("server", "client"; none for all)
func statusSearch[T any](opn *OpenVPNApi, method string, searchPhrase string, types []string) ([]T, error) {
	var query = url.Values{}
	if searchPhrase != "" {
		query.Set("searchPhrase", searchPhrase)
	}
	for _, role := range types {
		query.Add("type[]", role)
	}
	var endpoint = opn.statusServiceEndpoint(method)
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var container struct {
		Rows []T `json:"rows"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	return container.Rows, nil
}

// SessionList returns the sessions (connected clients, running instances without clients, enabled instances that
// are not running), searchPhrase is a substring match over all columns ("" for all), types limits them to instances
// of these roles ("server", "client")
func (opn *OpenVPNApi) SessionList(searchPhrase string, types ...string) ([]Session, error) {
	return statusSearch[Session](opn, "search_sessions", searchPhrase, types)
}

// RouteList returns the routing tables of the running instances, searchPhrase and types like SessionList
func (opn *OpenVPNApi) RouteList(searchPhrase string, types ...string) ([]Route, error) {
	return statusSearch[Route](opn, "search_routes", searchPhrase, types)
}

// SessionKill disconnects client sessions of instance (uuid, or vpnid of a legacy server). Each of sessions is a
// real address "ip:port" or a common name (which matches all sessions with this common name); they are tried in
// order until one matched, like the GUI tries the address and then the common name (a reconnected client has a new
// address). Returns the number of clients OpenVPN reported as killed; *NotFoundError when none matched or the
// instance has no management socket (it is not running)
func (opn *OpenVPNApi) SessionKill(instance string, sessions ...string) (int, error) {
	sessions = slices.DeleteFunc(slices.Clone(sessions), func(s string) bool { return s == "" })
	if instance == "" || len(sessions) == 0 {
		return 0, errors.New("instance and session must not be empty")
	}
	// kill_session reads server_id / session_id from the (JSON) POST body and answers
	// {"status":"killed","clients":1}, {"status":"not_found"} (no such session), {"status":"server_not_found"}
	// (no socket), {"result":"failed"} (configd error) or {"status":"invalid"} (parameters missing)
	var endpoint = opn.statusServiceEndpoint("kill_session")
	for _, session := range sessions {
		var result struct {
			Status  string `json:"status"`
			Result  string `json:"result"`
			Clients int    `json:"clients"`
		}
		var body = map[string]string{"server_id": instance, "session_id": session}
		if err := opn.DoJSON("POST", endpoint, body, &result); err != nil {
			return 0, err
		}
		switch {
		case result.Status == "killed":
			return result.Clients, nil
		case result.Status == "not_found":
			continue
		case result.Status == "server_not_found":
			return 0, &coreapi.NotFoundError{Name: fmt.Sprintf("openvpn instance %s (no management socket, is it running?)", instance)}
		case result.Result != "":
			return 0, fmt.Errorf("killing openvpn session %s of instance %s: %s", session, instance, result.Result)
		default:
			return 0, fmt.Errorf("unexpected answer from %s: status %q", endpoint, result.Status)
		}
	}
	return 0, &coreapi.NotFoundError{Name: fmt.Sprintf("openvpn session %s of instance %s", strings.Join(sessions, " / "), instance)}
}
