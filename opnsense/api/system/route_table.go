package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
)

// RouteTableEntry is one route of the kernel routing table (System > Routes > Status, netstat -rW)
type RouteTableEntry struct {
	// Proto is the address family: ipv4 or ipv6
	Proto string `json:"proto"`
	// Destination is a network (10.0.2.0/24), a host (10.0.2.3) or "default"; with resolve a host name
	Destination string `json:"destination"`
	// Gateway is an address (10.0.2.2, fe80::2%vtnet1) or a link (link#2) for directly connected routes
	Gateway string `json:"gateway"`
	// Flags are the netstat route flags, e.g. UGS (up, gateway, static)
	Flags           string `json:"flags"`
	Nhop            string `json:"nhop#"`
	Mtu             string `json:"mtu"`
	Netif           string `json:"netif"`
	Expire          string `json:"expire"`
	IntfDescription string `json:"intf_description"`
	// Id is the row key OPNsense stitches together. 26.7 sends "destination,gateway", the current source
	// "proto,destination,gateway", so it is only informative
	Id string `json:"id"`

	// Raw is the route as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

func (entry *RouteTableEntry) UnmarshalJSON(data []byte) error {
	type plainEntry RouteTableEntry
	var plain plainEntry
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	*entry = RouteTableEntry(plain)
	entry.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// Key identifies the route: "proto,destination,gateway" (destination and gateway together are unique per family)
func (entry RouteTableEntry) Key() string {
	return strings.Join([]string{entry.Proto, entry.Destination, entry.Gateway}, ",")
}

// IsDefault tells whether this is a default route (of either family)
func (entry RouteTableEntry) IsDefault() bool {
	switch entry.Destination {
	case "default", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

func (opn *SystemApi) routeTableEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("diagnostics", "interface", method)
}

// RouteTableList returns the kernel routing table in netstat order (IPv4 first). resolve shows host and network
// names instead of addresses where they resolve (slow when DNS is unreachable)
func (opn *SystemApi) RouteTableList(resolve bool) ([]RouteTableEntry, error) {
	var endpoint = opn.routeTableEndpoint("get_routes")
	if resolve {
		endpoint += "?resolve=yes"
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return nil, err
	}
	// a failing configd action is answered with null
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return nil, fmt.Errorf("unexpected answer from %s: %.100s", endpoint, raw)
	}
	var routes []RouteTableEntry
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("could not decode the routing table: %w", err)
	}
	return routes, nil
}

// RouteTableRemove deletes a route from the kernel routing table (route delete), not from the configuration: a
// static route or a gateway's route is installed again on the next routing reconfigure. family is ipv4 or ipv6,
// destination and gateway as listed by RouteTableList (gateway may be a link#n, then only the destination is
// matched). Returns *NotFoundError when the kernel has no such route or refused to delete it
func (opn *SystemApi) RouteTableRemove(family string, destination string, gateway string) error {
	if family != "ipv4" && family != "ipv6" {
		return fmt.Errorf("invalid address family %q, must be ipv4 or ipv6", family)
	}
	if destination == "" {
		return fmt.Errorf("cannot remove a route without destination")
	}
	var body = map[string]string{"family": family, "destination": destination, "gateway": gateway}
	var container struct {
		Message string `json:"message"`
	}
	var endpoint = opn.routeTableEndpoint("del_route")
	if err := opn.DoJSON("POST", endpoint, body, &container); err != nil {
		return err
	}
	switch container.Message {
	case "found":
		return nil
	case "not_found":
		return &coreapi.NotFoundError{Name: fmt.Sprintf("%s route %s via %s (or the kernel refused to delete it)", family, destination, gateway)}
	default:
		return fmt.Errorf("unexpected answer from %s: %q", endpoint, container.Message)
	}
}
