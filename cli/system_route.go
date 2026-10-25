package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"strings"
	"unicode"
)

// /system/route: the static routes of System > Routes > Configuration. Items are selected by the # of print, the
// uuid or the network. The network is the natural key of add: the routing table holds one route per destination

const systemRouteItemHelp = "the #, uuid or network of the route"

const systemRouteApplyHint = `Changes are only saved, run "/system/route apply" to apply them.`

// systemRouteFieldArgs are the field arguments of add (with the defaults) and set
func systemRouteFieldArgs(add bool) []Arg {
	var disabled = Arg{Name: "disabled", Help: "keep the route, but don't install it", Type: Bool}
	if add {
		disabled.Default = "no"
	}
	return []Arg{
		{Name: "network", Required: add, Validate: systemRouteValidateNetwork,
			Help: "destination network in CIDR notation, e.g. 198.51.100.0/24 or 2001:db8::/32 (host bits are cleared)"},
		{Name: "gateway", Required: add, Validate: systemRouteValidateGatewayName, Complete: systemRouteGatewayNames,
			Help: "name of the gateway; an IPv6 network needs an IPv6 gateway, an IPv4 network may use either"},
		{Name: "description", Help: "description, empty for none", Validate: systemRouteValidateDescription},
		disabled,
	}
}

func init() {
	var menu = Root.Menu("system/route")
	menu.Help = "static routes (System > Routes > Configuration)"
	var item = Arg{Name: "item", Help: systemRouteItemHelp, Positional: true, Required: true, Complete: systemRouteItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the static routes", Args: []Arg{
			{Name: "detail", Help: "show all fields of every route", Type: Bool},
			{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
			{Name: "search", Help: "only routes where any field contains this text"},
		}, Run: systemRoutePrint},
		&Command{Name: "show", Help: "show all fields of one static route", Args: []Arg{item}, Run: systemRouteShow},
		&Command{Name: "add", Help: "add a static route, prints its uuid",
			Long: `The network names the route: if a route for this network exists already, add fails unless replace is
given, then that route is replaced completely (a missing description is cleared, a missing disabled enables it).
OPNsense lists a new gateway for routes only after up to 20 seconds.
` + systemRouteApplyHint,
			Args: append(systemRouteFieldArgs(true), Arg{Name: "replace", Help: "replace the route for the same network", Type: Bool}),
			Run:  systemRouteAdd},
		&Command{Name: "set", Help: "change fields of a static route, the others are kept",
			Long: `network= moves the route to another destination, the old one is removed on apply. An empty description=
clears the description.
` + systemRouteApplyHint,
			Args:  append([]Arg{item}, systemRouteFieldArgs(false)...),
			Check: systemRouteCheckSet, Run: systemRouteSet},
		&Command{Name: "remove", Help: "remove a static route",
			Long: "The route stays in the routing table until apply. " + systemRouteApplyHint,
			Args: []Arg{item}, Run: systemRouteRemove},
		&Command{Name: "enable", Help: "enable a static route", Long: systemRouteApplyHint, Args: []Arg{item}, Run: systemRouteEnabler(true)},
		&Command{Name: "disable", Help: "disable a static route", Long: systemRouteApplyHint, Args: []Arg{item}, Run: systemRouteEnabler(false)},
		&Command{Name: "apply", Help: "apply the static route changes: re-applies the routes to the routing table",
			Long: `Removes deleted, disabled and moved routes from the routing table and installs the enabled routes.`,
			Run:  systemRouteApply},
	)
}

// --- validation

// systemRouteValidateNetwork accepts a network in CIDR notation, the prefix length is required
func systemRouteValidateNetwork(value string) error {
	if _, err := netip.ParsePrefix(value); err != nil {
		return fmt.Errorf("must be a network in CIDR notation like 198.51.100.0/24 or 2001:db8::/32, got %q", value)
	}
	return nil
}

func systemRouteValidateGatewayName(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty, give the name of a gateway")
	}
	return nil
}

// systemRouteValidateDescription rejects what OPNsense rejects: control characters (newlines) and more than 255 characters
func systemRouteValidateDescription(value string) error {
	if len([]rune(value)) > 255 {
		return errors.New("must be at most 255 characters")
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func systemRouteCheckSet(args *Args) error {
	for _, field := range []string{"network", "gateway", "description", "disabled"} {
		if args.Has(field) {
			return nil
		}
	}
	return errors.New("nothing to change, give at least one field like gateway= or description= (type \"set ?\" for help)")
}

// systemRouteNetwork returns the canonical network (host bits cleared, IPv6 compressed), or value itself when
// it is no network
func systemRouteNetwork(value string) string {
	var prefix, err = netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return value
	}
	return prefix.Masked().String()
}

// systemRouteIsIPv6 reports whether network is an IPv6 network, the way OPNsense decides it
func systemRouteIsIPv6(network string) bool {
	return strings.Contains(network, ":")
}

// --- lookups

func systemRouteApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemRouteSearch returns the matching routes in API order, with the raw API objects for json output
func systemRouteSearch(api *system.SystemApi, searchPhrase string) ([]system.StaticRoute, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("routes", "routes", "searchroute")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var routes = make([]system.StaticRoute, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &routes[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected static route from OPNsense: %w", err)
		}
	}
	return routes, rows, nil
}

func systemRouteUuid(route system.StaticRoute) string {
	return route.Uuid
}

// systemRouteNames are the names a route is selected by: its network as stored and in canonical form
func systemRouteNames(route system.StaticRoute) []string {
	return []string{route.Network, systemRouteNetwork(route.Network)}
}

// systemRouteSelect loads all routes and finds the one selector refers to, it also returns all routes
func systemRouteSelect(c *Context, api *system.SystemApi, selector string) (system.StaticRoute, []system.StaticRoute, error) {
	var routes, _, err = systemRouteSearch(api, "")
	if err != nil {
		return system.StaticRoute{}, nil, err
	}
	if _, parseErr := netip.ParsePrefix(strings.TrimSpace(selector)); parseErr == nil {
		selector = systemRouteNetwork(selector)
	}
	var route, selectErr = Select(c, selector, routes, systemRouteUuid, systemRouteNames)
	return route, routes, selectErr
}

// systemRouteSameNetwork returns the routes (other than except) to the same destination as network
func systemRouteSameNetwork(routes []system.StaticRoute, network string, except string) []system.StaticRoute {
	var matching []system.StaticRoute
	for _, route := range routes {
		if route.Uuid != except && systemRouteNetwork(route.Network) == systemRouteNetwork(network) {
			matching = append(matching, route)
		}
	}
	return matching
}

func systemRouteUuids(routes []system.StaticRoute) string {
	var uuids = make([]string, len(routes))
	for i, route := range routes {
		uuids[i] = route.Uuid
	}
	return strings.Join(uuids, ", ")
}

// systemRouteItemNames completes item names (networks) from the API
func systemRouteItemNames(c *Context) []string {
	var api, err = systemRouteApi(c)
	if err != nil {
		return nil
	}
	var routes, _, searchErr = systemRouteSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(routes))
	for _, route := range routes {
		names = append(names, route.Network)
	}
	return names
}

// systemRouteGatewayNames completes gateway= with the gateways routes can use
func systemRouteGatewayNames(c *Context) []string {
	var api, err = systemRouteApi(c)
	if err != nil {
		return nil
	}
	var gateways, listErr = api.StaticRouteGateways()
	if listErr != nil {
		return nil
	}
	var names = make([]string, len(gateways))
	for i, gateway := range gateways {
		names[i] = gateway.Name
	}
	return names
}

// systemRouteGateway finds the gateway called name (exact, else case-insensitive) among the gateways routes can use
func systemRouteGateway(gateways []system.StaticRouteGateway, name string) (system.StaticRouteGateway, bool) {
	for _, gateway := range gateways {
		if gateway.Name == name {
			return gateway, true
		}
	}
	for _, gateway := range gateways {
		if strings.EqualFold(gateway.Name, name) {
			return gateway, true
		}
	}
	return system.StaticRouteGateway{}, false
}

// systemRouteResolveGateway returns the gateway called name, an error when there is none or when it can not
// carry network (an IPv6 network needs an IPv6 gateway; an IPv4 network may use an IPv6 next hop, RFC 5549)
func systemRouteResolveGateway(gateways []system.StaticRouteGateway, name string, network string) (system.StaticRouteGateway, error) {
	var gateway, found = systemRouteGateway(gateways, name)
	if !found {
		var names = make([]string, len(gateways))
		for i, available := range gateways {
			names[i] = available.Name
		}
		return gateway, fmt.Errorf("unknown gateway %q, the gateways are: %s (OPNsense lists a new gateway after up to 20 seconds)",
			name, strings.Join(names, ", "))
	}
	if err := systemRouteCheckProtocol(gateway, network); err != nil {
		return gateway, err
	}
	return gateway, nil
}

func systemRouteCheckProtocol(gateway system.StaticRouteGateway, network string) error {
	if systemRouteIsIPv6(network) && gateway.Protocol() == "inet" {
		return fmt.Errorf("the IPv6 network %s needs an IPv6 gateway, %s is IPv4 (%s)", network, gateway.Name, gateway.Address)
	}
	return nil
}

// --- output

// systemRouteDisabled renders the enabled flag of the API as the disabled argument
func systemRouteDisabled(route system.StaticRoute) string {
	if route.Enabled == "0" {
		return "yes"
	}
	return "no"
}

// systemRouteFields are the fields of show and print detail, named like the arguments of add and set
func systemRouteFields(route system.StaticRoute) [][2]string {
	return [][2]string{
		{"uuid", route.Uuid},
		{"disabled", systemRouteDisabled(route)},
		{"network", route.Network},
		{"gateway", route.Gateway},
		{"gateway-ip", route.GatewayAddress()},
		{"description", route.Description},
	}
}

func systemRoutePrint(c *Context, args *Args) error {
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	var routes, raw, searchErr = systemRouteSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(routes))
	for i, route := range routes {
		uuids[i] = route.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(routes))
		for i, route := range routes {
			items[i] = systemRouteFields(route)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(routes))
		for i, route := range routes {
			rows[i] = []string{systemRouteDisabled(route), route.Network, route.Gateway, route.GatewayAddress(), route.Description}
		}
		c.Items([]string{"DISABLED", "NETWORK", "GATEWAY", "GATEWAY-IP", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func systemRouteShow(c *Context, args *Args) error {
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	var route, _, selectErr = systemRouteSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemRouteFields(route))
	return nil
}

// --- changes

func systemRouteAdd(c *Context, args *Args) error {
	var network = systemRouteNetwork(args.String("network"))
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	var gateways, gatewaysErr = api.StaticRouteGateways()
	if gatewaysErr != nil {
		return gatewaysErr
	}
	var gateway, gatewayErr = systemRouteResolveGateway(gateways, args.String("gateway"), network)
	if gatewayErr != nil {
		return gatewayErr
	}
	var routes, _, searchErr = systemRouteSearch(api, "")
	if searchErr != nil {
		return searchErr
	}

	var route = system.StaticRoute{
		Network: network, Gateway: gateway.Name, Description: strings.TrimSpace(args.String("description")),
		Enabled: Flag(!args.Bool("disabled")),
	}
	var existing = systemRouteSameNetwork(routes, network, "")
	switch {
	case len(existing) == 0:
		var uuid, createErr = api.StaticRouteCreate(route)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d routes for %s (%s), change or remove them with set or remove",
			len(existing), network, systemRouteUuids(existing))}
	case !args.Bool("replace"):
		return fmt.Errorf("a route for %s exists already (%s), change it with set or replace it with add ... replace",
			network, existing[0].Uuid)
	}

	var patch = system.StaticRoutePatch{
		Network: &route.Network, Gateway: &route.Gateway, Description: &route.Description, Enabled: &route.Enabled,
	}
	if err := api.StaticRouteUpdate(existing[0].Uuid, patch); err != nil {
		return err
	}
	c.Infof("replaced the existing route for %s", network)
	c.Println(existing[0].Uuid)
	return nil
}

func systemRouteSet(c *Context, args *Args) error {
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	var route, routes, selectErr = systemRouteSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}

	var patch system.StaticRoutePatch
	var network = route.Network
	if args.Has("network") {
		network = systemRouteNetwork(args.String("network"))
		if others := systemRouteSameNetwork(routes, network, route.Uuid); len(others) > 0 {
			return fmt.Errorf("another route for %s exists already (%s)", network, systemRouteUuids(others))
		}
		patch.Network = &network
	}
	if args.Has("gateway") || args.Has("network") {
		var gateways, gatewaysErr = api.StaticRouteGateways()
		if gatewaysErr != nil {
			return gatewaysErr
		}
		if args.Has("gateway") {
			var gateway, gatewayErr = systemRouteResolveGateway(gateways, args.String("gateway"), network)
			if gatewayErr != nil {
				return gatewayErr
			}
			patch.Gateway = &gateway.Name
		} else if gateway, found := systemRouteGateway(gateways, route.Gateway); found {
			if err := systemRouteCheckProtocol(gateway, network); err != nil {
				return fmt.Errorf("%w, give a gateway= as well", err)
			}
		}
	}
	if args.Has("description") {
		var description = strings.TrimSpace(args.String("description"))
		patch.Description = &description
	}
	if args.Has("disabled") {
		var enabled = Flag(!args.Bool("disabled"))
		patch.Enabled = &enabled
	}
	return api.StaticRouteUpdate(route.Uuid, patch)
}

func systemRouteRemove(c *Context, args *Args) error {
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	var route, _, selectErr = systemRouteSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.StaticRouteRemove(route.Uuid)
}

func systemRouteEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = systemRouteApi(c)
		if err != nil {
			return err
		}
		var route, _, selectErr = systemRouteSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.StaticRouteSetEnabled(route.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("the route for %s is already %s", route.Network, EnabledWord(enabled))
		}
		return nil
	}
}

func systemRouteApply(c *Context, _ *Args) error {
	var api, err = systemRouteApi(c)
	if err != nil {
		return err
	}
	return api.StaticRouteReconfigure()
}
