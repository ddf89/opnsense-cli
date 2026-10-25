package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strings"
)

// Static routes of System > Routes > Configuration (api/routes/routes).
//
// OPNsense 26.7 behaviour (verified live):
//   - addroute accepts duplicate networks and networks with host bits (198.51.100.5/24), the mask is required
//   - enabled defaults to "1" when it is not sent
//   - setroute on an unknown but well-formed uuid creates the route (malformed uuids answer a bare "failed"),
//     so StaticRouteUpdate checks the existence first
//   - setroute remembers the old network for deletion on the next reconfigure when the posted network differs
//     from the stored one, and a network that is not posted counts as different: StaticRouteUpdate always sends it
//   - getroute/<unknown uuid> answers [] instead of a not found result, delroute answers "not found", toggleroute "failed"
//   - the gateway options come from the configd action "interface gateways list", which is cached for 20 seconds:
//     a new gateway can not be used for a route right away
//   - an IPv6 network needs an IPv6 gateway, an IPv4 network may use an IPv6 gateway (RFC 5549)

// StaticRoute is a route as returned by searchroute
type StaticRoute struct {
	Uuid string `json:"uuid"`
	// Network is the destination in CIDR notation, e.g. 198.51.100.0/24 or 2001:db8::/32
	Network string `json:"network"`
	// Gateway is the name of the gateway, e.g. WAN_DHCP
	Gateway string `json:"gateway"`
	// GatewayDescription is "<name> - <address>", e.g. "WAN_DHCP - 10.0.2.2"
	GatewayDescription string `json:"%gateway"`
	Description        string `json:"descr"`
	// Enabled is "1" or "0"
	Enabled string `json:"enabled"`
}

// GatewayAddress returns the address part of GatewayDescription, "" when there is none
func (route StaticRoute) GatewayAddress() string {
	return staticRouteGatewayAddress(route.GatewayDescription)
}

// StaticRoutePatch holds the fields to send on create / update, nil fields are not sent
type StaticRoutePatch struct {
	Network     *string `json:"network,omitempty"`
	Gateway     *string `json:"gateway,omitempty"`
	Description *string `json:"descr,omitempty"`
	Enabled     *string `json:"enabled,omitempty"`
}

// StaticRouteGateway is a gateway a route can use, from the option list of getroute
type StaticRouteGateway struct {
	Name string
	// Address is the gateway address, "" when unknown; dynamic gateways may only name the protocol (inet / inet6)
	Address string
	// Description is the option text, "<name> - <address>"
	Description string
}

// Protocol returns "inet" or "inet6" like OPNsense determines it for the route validation, "" when the
// gateway has no address
func (gateway StaticRouteGateway) Protocol() string {
	switch {
	case gateway.Address == "":
		return ""
	case gateway.Address == "inet" || gateway.Address == "inet6":
		return gateway.Address
	case strings.Contains(gateway.Address, ":"):
		return "inet6"
	default:
		return "inet"
	}
}

type staticRouteContainer struct {
	Route StaticRoutePatch `json:"route"`
}

// staticRouteGatewayAddress returns what follows the last "-" of a gateway option text, like OPNsense does
func staticRouteGatewayAddress(description string) string {
	var index = strings.LastIndex(description, "-")
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(description[index+1:])
}

func (opn *SystemApi) staticRouteEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("routes", "routes", method)
}

func staticRouteNotFound(uuid string, err error) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("static route %s", uuid), Err: err}
}

// StaticRouteSearch returns all routes where any column contains searchPhrase, use "" for all routes
func (opn *SystemApi) StaticRouteSearch(searchPhrase string) ([]StaticRoute, error) {
	return coreapi.Search[StaticRoute](opn.OPNsense, opn.staticRouteEndpoint("searchroute"), searchPhrase)
}

func (opn *SystemApi) StaticRouteList() ([]StaticRoute, error) {
	return opn.StaticRouteSearch("")
}

// StaticRouteGet returns the route with the given uuid, *coreapi.NotFoundError if there is none
func (opn *SystemApi) StaticRouteGet(uuid string) (StaticRoute, error) {
	// getroute/<uuid> answers with the gateway option list instead of the plain name, so we filter the search result
	var routes, err = opn.StaticRouteList()
	if err != nil {
		return StaticRoute{}, err
	}
	for _, route := range routes {
		if strings.EqualFold(route.Uuid, uuid) {
			return route, nil
		}
	}
	return StaticRoute{}, staticRouteNotFound(uuid, nil)
}

// StaticRouteCreate creates a route from the non empty fields of route (Uuid and GatewayDescription are ignored)
// and returns its uuid. OPNsense requires Network and Gateway, Enabled defaults to "1"
func (opn *SystemApi) StaticRouteCreate(route StaticRoute) (string, error) {
	var optional = func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	var patch = StaticRoutePatch{
		Network:     optional(route.Network),
		Gateway:     optional(route.Gateway),
		Description: optional(route.Description),
		Enabled:     optional(route.Enabled),
	}
	return opn.Mutate(opn.staticRouteEndpoint("addroute"), staticRouteContainer{Route: patch})
}

// StaticRouteUpdate changes the non nil fields of patch on the route with the given uuid, returns
// *coreapi.NotFoundError if it does not exist (OPNsense would create it). The current network is sent when the
// patch has none, OPNsense would otherwise delete and re-add the route on the next reconfigure
func (opn *SystemApi) StaticRouteUpdate(uuid string, patch StaticRoutePatch) error {
	if uuid == "" {
		return errors.New("cannot update a static route without uuid")
	}
	var current, err = opn.StaticRouteGet(uuid)
	if err != nil {
		return err
	}
	if patch.Network == nil {
		patch.Network = &current.Network
	}

	var endpoint = fmt.Sprintf("%s/%s", opn.staticRouteEndpoint("setroute"), current.Uuid)
	if _, err := opn.Mutate(endpoint, staticRouteContainer{Route: patch}); err != nil {
		// removed meanwhile: a malformed uuid answers {"result":"failed"} without validation messages
		var validationErr *coreapi.ValidationError
		if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
			return staticRouteNotFound(uuid, err)
		}
		return err
	}
	return nil
}

// StaticRouteRemove deletes the route with the given uuid, returns *coreapi.NotFoundError if it does not exist.
// The route stays in the routing table until StaticRouteReconfigure
func (opn *SystemApi) StaticRouteRemove(uuid string) error {
	if uuid == "" {
		return errors.New("cannot remove a static route without uuid")
	}
	var endpoint = fmt.Sprintf("%s/%s", opn.staticRouteEndpoint("delroute"), uuid)
	if _, err := opn.Mutate(endpoint, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return staticRouteNotFound(uuid, err)
		}
		return err
	}
	return nil
}

// StaticRouteSetEnabled enables or disables the route with the given uuid and returns whether its state changed
func (opn *SystemApi) StaticRouteSetEnabled(uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("cannot toggle a static route without uuid")
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	// toggleroute/<uuid>/<0|1> sets the given state, without the state it would flip it
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.staticRouteEndpoint("toggleroute"), uuid, state)
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
	case "failed": // unknown uuid
		return false, staticRouteNotFound(uuid, nil)
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// StaticRouteGateways returns the gateways a route can use, sorted by name. The list is cached by OPNsense for
// 20 seconds, a gateway created just now may be missing
func (opn *SystemApi) StaticRouteGateways() ([]StaticRouteGateway, error) {
	var container struct {
		Route struct {
			Gateway json.RawMessage `json:"gateway"`
		} `json:"route"`
	}
	if err := opn.DoJSON("GET", opn.staticRouteEndpoint("getroute"), nil, &container); err != nil {
		return nil, err
	}

	var options map[string]struct {
		Value string `json:"value"`
	}
	// PHP encodes an empty option list as []
	if raw := bytes.TrimSpace(container.Route.Gateway); len(raw) > 0 && !bytes.Equal(raw, []byte("[]")) {
		if err := json.Unmarshal(raw, &options); err != nil {
			return nil, fmt.Errorf("unexpected gateway options from %s: %w", opn.staticRouteEndpoint("getroute"), err)
		}
	}

	var gateways = make([]StaticRouteGateway, 0, len(options))
	for name, option := range options {
		if name == "" { // the "none selected" option, if any
			continue
		}
		gateways = append(gateways, StaticRouteGateway{
			Name: name, Address: staticRouteGatewayAddress(option.Value), Description: option.Value,
		})
	}
	sort.Slice(gateways, func(i, j int) bool {
		return gateways[i].Name < gateways[j].Name
	})
	return gateways, nil
}

// StaticRouteReconfigure applies the static routes: removes deleted and changed routes and installs the
// enabled ones (configd "interface routes configure")
func (opn *SystemApi) StaticRouteReconfigure() error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.staticRouteEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(container.Status), "ok") {
		return fmt.Errorf("applying the static routes failed: %q", container.Status)
	}
	return nil
}
