package cli

import (
	"fmt"
	"strings"
	"time"

	"opnsense-cli/opnsense/api/openvpn"
)

// /vpn/openvpn/session and /vpn/openvpn/route: VPN > OpenVPN > Connection Status (api/openvpn/service/search_sessions,
// search_routes, kill_session). The start / stop / restart of instances is in /vpn/openvpn/instance

func init() {
	var sessions = Root.Menu("vpn/openvpn/session")
	sessions.Help = "OpenVPN connection status: connected clients and the state of the instances (VPN > OpenVPN > Connection Status)"
	sessions.Add(
		&Command{
			Name: "print",
			Help: "list the connected clients and the instances, follow refreshes until Ctrl-C",
			Long: `Lists the clients connected to the servers, the client instances and their state, running servers
without clients and enabled instances that are not running (status stopped). BYTES-IN / BYTES-OUT are counted by the
firewall: received from / sent to the peer.

follow repeats the query every interval until Ctrl-C, on a terminal the screen is redrawn, otherwise a "--- time" line
separates the refreshes.

  print follow interval=5s`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every session"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only sessions where any field contains this text"},
				{Name: "type", Values: []string{"server", "client"}, Help: "only sessions of server or of client instances"},
				{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			},
			Run: openvpnSessionPrint,
		},
		&Command{
			Name:    "remove",
			Aliases: []string{"kill"},
			Help:    "disconnect a client from its server",
			Long: `Disconnects the client session by its address; when OpenVPN does not know the address (any more, e.g.
after a reconnect) all sessions of its common name on that server are disconnected, like the GUI does. The client
may reconnect at once, set block on its client specific override to keep it out.`,
			Args: []Arg{{
				Name: "item", Positional: true, Required: true,
				Help:     "the # of print, the common name or the real address (ip:port) of the client session",
				Complete: openvpnSessionNames,
			}},
			Confirm: "This disconnects the client.",
			Run:     openvpnSessionRemove,
		},
	)

	var routes = Root.Menu("vpn/openvpn/route")
	routes.Help = "OpenVPN routing tables of the running instances (VPN > OpenVPN > Connection Status)"
	routes.Add(&Command{
		Name: "print",
		Help: "list the routes of the running instances: which client a virtual address or network is routed to",
		Args: []Arg{
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "search", Help: "only routes where any field contains this text"},
			{Name: "type", Values: []string{"server", "client"}, Help: "only routes of server or of client instances"},
		},
		Run: openvpnRoutePrint,
	})
}

func openvpnStatusTypes(args *Args) []string {
	if role := strings.ToLower(args.String("type")); role != "" {
		return []string{role}
	}
	return nil
}

func openvpnSessionPrint(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)

	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var sessions, listErr = systemActivityAwait(c, func() ([]openvpn.Session, error) {
			return api.SessionList(args.String("search"), openvpnStatusTypes(args)...)
		})
		if listErr != nil {
			return listErr
		}
		if asJSON {
			for _, session := range sessions {
				if err := c.JSON(session.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		openvpnSessionShow(c, sessions, args.Bool("detail"))
		return nil
	})
}

func openvpnSessionShow(c *Context, sessions []openvpn.Session, detail bool) {
	var ids = make([]string, len(sessions))
	for i, session := range sessions {
		ids[i] = session.Id
	}
	if detail {
		var details = make([][][2]string, len(sessions))
		for i, session := range sessions {
			details[i] = [][2]string{
				{"instance", openvpnSessionInstance(session)},
				{"instance-id", session.InstanceId()},
				{"type", session.Type},
				{"status", openvpnSessionStatus(session)},
				{"common-name", session.CommonName},
				{"username", session.Username},
				{"real-address", session.RealAddress},
				{"virtual-address", session.VirtualAddress},
				{"virtual-address6", session.VirtualIpv6Address},
				{"connected-since", openvpnSessionSince(session)},
				{"bytes-in", openvpnSessionBytes(session.BytesReceived)},
				{"bytes-out", openvpnSessionBytes(session.BytesSent)},
				{"cipher", session.DataChannelCipher},
				{"client-id", session.ClientId},
				{"peer-id", session.PeerId},
			}
		}
		c.Details(details, ids)
		return
	}

	var rows = make([][]string, len(sessions))
	for i, session := range sessions {
		var virtual []string
		for _, address := range []string{session.VirtualAddress, session.VirtualIpv6Address} {
			if address != "" {
				virtual = append(virtual, address)
			}
		}
		rows[i] = []string{openvpnSessionInstance(session), session.Type, session.CommonName, session.RealAddress,
			strings.Join(virtual, ", "), openvpnSessionSince(session), openvpnSessionBytes(session.BytesReceived),
			openvpnSessionBytes(session.BytesSent), openvpnSessionStatus(session)}
	}
	c.Items([]string{"INSTANCE", "TYPE", "COMMON-NAME", "REAL-ADDRESS", "VIRTUAL-ADDRESS", "CONNECTED-SINCE", "BYTES-IN",
		"BYTES-OUT", "STATUS"}, rows, ids)
}

// openvpnSessionInstance names the instance by its description, by its id when it has none
func openvpnSessionInstance(session openvpn.Session) string {
	if session.Description != "" {
		return session.Description
	}
	return session.InstanceId()
}

// openvpnSessionStatus: connected (a client of a server), running (a server), stopped (not running), else the state
// of a client instance (connected, reconnecting, ...)
func openvpnSessionStatus(session openvpn.Session) string {
	switch {
	case session.IsClient:
		return "connected"
	case session.Status == "ok":
		return "running"
	case !session.Running():
		return "stopped"
	default:
		return session.Status
	}
}

func openvpnSessionSince(session openvpn.Session) string {
	if since, ok := session.ConnectedSinceTime(); ok {
		return since.Local().Format(time.DateTime)
	}
	return session.ConnectedSince
}

func openvpnSessionBytes(value string) string {
	if value == "" {
		return ""
	}
	return ifaceBytesText(value)
}

// openvpnSessionNames completes the item: the common names of the connected clients
func openvpnSessionNames(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var sessions, listErr = api.SessionList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, session := range sessions {
		if session.IsClient && session.CommonName != "" && !containsFold(names, session.CommonName) {
			names = append(names, session.CommonName)
		}
	}
	return names
}

func openvpnSessionRemove(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	sessions, err := api.SessionList("")
	if err != nil {
		return err
	}
	session, err := Select(c, args.String("item"), sessions,
		func(s openvpn.Session) string { return s.Id },
		func(s openvpn.Session) []string {
			if !s.IsClient {
				return nil
			}
			return []string{s.CommonName, s.RealAddress}
		})
	if err != nil {
		return err
	}
	if !session.IsClient {
		return fmt.Errorf("%s is the %s instance %s (%s), not a client session; stop instances in /vpn/openvpn/instance",
			args.String("item"), session.Type, openvpnSessionInstance(session), openvpnSessionStatus(session))
	}
	_, err = api.SessionKill(session.InstanceId(), session.RealAddress, session.CommonName)
	return err
}

func openvpnRoutePrint(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	routes, err := api.RouteList(args.String("search"), openvpnStatusTypes(args)...)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, route := range routes {
			if err := c.JSON(route.Raw); err != nil {
				return err
			}
		}
		return nil
	}

	var keys = make([]string, len(routes))
	var rows = make([][]string, len(routes))
	for i, route := range routes {
		keys[i] = route.Id + "_" + route.VirtualAddress
		var instance = route.Description
		if instance == "" {
			instance = route.Id
		}
		var lastRef = route.LastRef
		if route.LastRefEpoch > 0 {
			lastRef = time.Unix(route.LastRefEpoch, 0).Local().Format(time.DateTime)
		}
		rows[i] = []string{instance, route.VirtualAddress, route.CommonName, route.RealAddress, lastRef}
	}
	c.Items([]string{"INSTANCE", "TARGET", "COMMON-NAME", "REAL-ADDRESS", "LAST-REF"}, rows, keys)
	return nil
}
