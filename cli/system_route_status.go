package cli

import (
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"sort"
	"strings"
)

// /system/route/status: the kernel routing table of System > Routes > Status (api/diagnostics/interface/get_routes)
// and removing a route from it (del_route)

const systemRouteStatusRemoveConfirm = "This deletes the route from the kernel routing table, connectivity can be lost."

func init() {
	var menu = Root.Menu("system/route/status")
	menu.Help = "the kernel routing table (System > Routes > Status)"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the kernel routing table",
			Long: `Shows the routes the kernel uses right now (netstat -rW), IPv4 first. INTERFACE is the interface
description with the device in parentheses, e.g. "WAN (vtnet1)". protocol=, interface= and search= filter
the table, the # of the rows stays the one of the unfiltered list only without filters. resolve shows host
and network names instead of addresses (slow when DNS does not answer). detail shows every field, json the
routes as OPNsense returns them, one object per line. follow refreshes the view every interval until Ctrl-C.

  print protocol=ipv4 interface=wan
  print follow interval=5s`,
			Args: []Arg{
				{Name: "protocol", Help: "only routes of this address family", Values: []string{"ipv4", "ipv6"}},
				{Name: "interface", Type: List, Help: "only routes over these interfaces, by device (vtnet1) or description (WAN)",
					Complete: systemRouteStatusCompleteInterface},
				{Name: "search", Help: "only routes where any field contains this text (case-insensitive)"},
				{Name: "resolve", Type: Bool, Help: "show names instead of addresses"},
				{Name: "detail", Type: Bool, Help: "show every field of every route"},
				{Name: "json", Type: Bool, Help: "print the routes as JSON, one object per line"},
				{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			},
			Run: systemRouteStatusPrint,
		},
		&Command{
			Name: "remove",
			Help: "delete a route from the kernel routing table",
			Long: `Deletes a route from the kernel routing table right away, like the trash button of System > Routes >
Status. The configuration is not changed: a static route or gateway route is installed again on the next
routing reconfigure, a route of a connected network when its interface is reconfigured.

The item is the # of the last print, the destination as printed (10.0.2.0/24, 10.0.2.3, a name with
resolve) or the route as protocol,destination,gateway (ipv4,10.0.2.3,10.0.2.2). A destination that exists
for both IPv4 and IPv6 or over several gateways must be given as protocol,destination,gateway or by #.
Default routes are refused unless allow-default is given, deleting one cuts off everything that is not
directly connected (likely including this CLI).

  remove 3
  remove 10.99.0.0/24 confirm=yes`,
			Args: []Arg{
				{Name: "item", Positional: true, Required: true, Help: "the #, the destination or protocol,destination,gateway",
					Complete: systemRouteStatusCompleteItem},
				{Name: "allow-default", Type: Bool, Help: "allow deleting a default route"},
			},
			Confirm: systemRouteStatusRemoveConfirm,
			Check:   systemRouteStatusCheckRemove,
			Run:     systemRouteStatusRemove,
		},
	)
}

// systemRouteStatusApi returns the system API on the session's connection
func systemRouteStatusApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemRouteStatusInterface renders the interface column: "WAN (vtnet1)", or the device without description
func systemRouteStatusInterface(route system.RouteTableEntry) string {
	if route.IntfDescription == "" || route.IntfDescription == route.Netif {
		return route.Netif
	}
	return fmt.Sprintf("%s (%s)", route.IntfDescription, route.Netif)
}

// --- print

var systemRouteStatusHeaders = []string{"PROTOCOL", "DESTINATION", "GATEWAY", "FLAGS", "INTERFACE", "MTU", "EXPIRE"}

func systemRouteStatusPrint(c *Context, args *Args) error {
	var api, err = systemRouteStatusApi(c)
	if err != nil {
		return err
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)

	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var routes, listErr = systemActivityAwait(c, func() ([]system.RouteTableEntry, error) {
			return api.RouteTableList(args.Bool("resolve"))
		})
		if listErr != nil {
			return listErr
		}
		routes = systemRouteStatusFilter(routes, args.String("protocol"), args.List("interface"), args.String("search"))

		if asJSON {
			for _, route := range routes {
				if err := c.JSON(route.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		var keys = make([]string, 0, len(routes))
		for _, route := range routes {
			keys = append(keys, route.Key())
		}
		if args.Bool("detail") {
			var items = make([][][2]string, 0, len(routes))
			for _, route := range routes {
				items = append(items, [][2]string{
					{"protocol", route.Proto}, {"destination", route.Destination}, {"gateway", route.Gateway},
					{"flags", route.Flags}, {"interface", route.IntfDescription}, {"device", route.Netif},
					{"mtu", route.Mtu}, {"expire", route.Expire}, {"nhop", route.Nhop},
				})
			}
			c.Details(items, keys)
			return nil
		}
		var rows = make([][]string, 0, len(routes))
		for _, route := range routes {
			rows = append(rows, []string{route.Proto, route.Destination, route.Gateway, route.Flags,
				systemRouteStatusInterface(route), route.Mtu, route.Expire})
		}
		c.Items(systemRouteStatusHeaders, rows, keys)
		return nil
	})
}

// systemRouteStatusFilter keeps the routes of protocol ("" for both), over one of interfaces (device or
// description, case-insensitive, none for all) that contain search in any field (case-insensitive, "" for all)
func systemRouteStatusFilter(routes []system.RouteTableEntry, protocol string, interfaces []string, search string) []system.RouteTableEntry {
	var phrase = strings.ToLower(search)
	return coreapi.Filter(routes, func(route system.RouteTableEntry) bool {
		if protocol != "" && !strings.EqualFold(route.Proto, protocol) {
			return false
		}
		if len(interfaces) > 0 {
			var matches = false
			for _, name := range interfaces {
				if strings.EqualFold(route.Netif, name) || strings.EqualFold(route.IntfDescription, name) {
					matches = true
				}
			}
			if !matches {
				return false
			}
		}
		if phrase == "" {
			return true
		}
		var fields = strings.Join([]string{route.Proto, route.Destination, route.Gateway, route.Flags, route.Nhop,
			route.Mtu, route.Netif, route.Expire, route.IntfDescription}, "\n")
		return strings.Contains(strings.ToLower(fields), phrase)
	})
}

func systemRouteStatusCompleteInterface(c *Context) []string {
	var api, err = systemRouteStatusApi(c)
	if err != nil {
		return nil
	}
	var routes, listErr = api.RouteTableList(false)
	if listErr != nil {
		return nil
	}
	var seen = map[string]bool{}
	for _, route := range routes {
		for _, name := range []string{route.Netif, strings.ToLower(route.IntfDescription)} {
			if name != "" {
				seen[name] = true
			}
		}
	}
	var names = make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// --- remove

func systemRouteStatusCompleteItem(c *Context) []string {
	var api, err = systemRouteStatusApi(c)
	if err != nil {
		return nil
	}
	var routes, listErr = api.RouteTableList(false)
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(routes))
	for _, route := range routes {
		if !route.IsDefault() {
			names = append(names, route.Destination)
		}
	}
	return names
}

// systemRouteStatusDefaultSelectors are item names that always mean a default route
var systemRouteStatusDefaultSelectors = []string{"default", "0.0.0.0/0", "::/0"}

// systemRouteStatusCheckRemove refuses a default route given by name before the confirmation is asked
// (by # it is refused once the item is resolved)
func systemRouteStatusCheckRemove(args *Args) error {
	if args.Bool("allow-default") {
		return nil
	}
	var selector = strings.ToLower(strings.TrimSpace(args.String("item")))
	for _, name := range systemRouteStatusDefaultSelectors {
		if selector == name || strings.HasSuffix(selector, ","+name) || strings.Contains(selector, ","+name+",") {
			return systemRouteStatusDefaultError()
		}
	}
	return nil
}

func systemRouteStatusDefaultError() error {
	return fmt.Errorf("refusing to delete a default route, add allow-default to really do it")
}

func systemRouteStatusRemove(c *Context, args *Args) error {
	var api, err = systemRouteStatusApi(c)
	if err != nil {
		return err
	}
	var routes, listErr = api.RouteTableList(false)
	if listErr != nil {
		return listErr
	}
	var route, selectErr = Select(c, args.String("item"), routes, system.RouteTableEntry.Key, systemRouteStatusNames)
	if coreapi.IsNotFound(selectErr) {
		// the item may refer to a print with resolve, which shows names instead of addresses
		if resolvedRoute, found := systemRouteStatusSelectResolved(c, api, args.String("item"), routes); found {
			route, selectErr = resolvedRoute, nil
		}
	}
	if selectErr != nil {
		return selectErr
	}
	if route.IsDefault() && !args.Bool("allow-default") {
		return systemRouteStatusDefaultError()
	}
	return api.RouteTableRemove(route.Proto, route.Destination, route.Gateway)
}

func systemRouteStatusNames(route system.RouteTableEntry) []string {
	return []string{route.Destination}
}

// systemRouteStatusSelectResolved selects the item in the resolved routing table (print resolve) and returns the
// route at the same position of routes (unresolved, both are netstat -rW in the same order) when it is the same
// route apart from the names
func systemRouteStatusSelectResolved(c *Context, api *system.SystemApi, selector string, routes []system.RouteTableEntry) (system.RouteTableEntry, bool) {
	var resolved, err = api.RouteTableList(true)
	if err != nil || len(resolved) != len(routes) {
		return system.RouteTableEntry{}, false
	}
	var route, selectErr = Select(c, selector, resolved, system.RouteTableEntry.Key, systemRouteStatusNames)
	if selectErr != nil {
		return system.RouteTableEntry{}, false
	}
	for i := range resolved {
		if resolved[i].Key() != route.Key() {
			continue
		}
		var candidate = routes[i]
		if candidate.Proto == route.Proto && candidate.Flags == route.Flags && candidate.Netif == route.Netif && candidate.Nhop == route.Nhop {
			return candidate, true
		}
	}
	return system.RouteTableEntry{}, false
}
