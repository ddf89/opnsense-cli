package cli

import (
	"fmt"
	"strings"
	"time"

	"opnsense-cli/opnsense/api/wireguard"
)

// /vpn/wireguard/settings (the global enable switch of VPN > WireGuard, api/wireguard/general),
// /vpn/wireguard/status (VPN > WireGuard > Status, api/wireguard/service/show: wg show) and
// /vpn/wireguard/service (api/wireguard/service)

func init() {
	var settings = Root.Menu("vpn/wireguard/settings")
	settings.Help = "the global WireGuard switch (VPN > WireGuard, Enable WireGuard)"
	settings.Add(
		&Command{Name: "print", Help: "show whether WireGuard is enabled", Args: []Arg{
			{Name: "json", Type: Bool, Help: "print the settings as one JSON object"},
		}, Run: wireguardSettingsPrint},
		&Command{Name: "set", Help: "enable or disable WireGuard",
			Long: `Without enabled=yes no instance runs, whether it is enabled or not.
` + wireguardApplyHint,
			Args: []Arg{{Name: "enabled", Type: Bool, Required: true, Help: "run the enabled instances"}},
			Run:  wireguardSettingsSet},
	)

	var status = Root.Menu("vpn/wireguard/status")
	status.Help = "the state of the running instances and their peers: handshakes and transfer (VPN > WireGuard > Status)"
	status.Add(&Command{Name: "print", Help: "list the running instances and their peers (wg show), follow refreshes until Ctrl-C",
		Long: `Shows the WireGuard interfaces that are up with their peers. A peer is online when its latest handshake is
at most 300 seconds old (WireGuard renews it every 2 minutes while there is traffic), stale when it is older and offline
without handshake. SENT / RECEIVED are the bytes transferred to / from the peer.

follow repeats the query every interval until Ctrl-C.`,
		Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every interface and peer"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "search", Help: "only lines where any field contains this text"},
			{Name: "type", Values: []string{"interface", "peer"}, Help: "only interfaces (instances) or only peers"},
			{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
			{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
		},
		Run: wireguardStatusPrint,
	})

	var service = Root.Menu("vpn/wireguard/service")
	service.Help = "the WireGuard service"
	service.Add(
		&Command{Name: "status", Help: "show whether WireGuard is running", Run: wireguardServiceStatus},
		&Command{Name: "reconfigure", Aliases: []string{"apply"},
			Help: "apply the saved instances, peers and settings: (re)start the enabled instances, stop the others",
			Run:  wireguardServiceAction("reconfigure")},
		&Command{Name: "start", Help: "start the enabled instances", Run: wireguardServiceAction("start")},
		&Command{Name: "stop", Help: "stop all instances (until the next start or reconfigure)",
			Confirm: "This stops WireGuard and disconnects all its tunnels.", Run: wireguardServiceAction("stop")},
		&Command{Name: "restart", Help: "restart the enabled instances",
			Confirm: "This restarts WireGuard and briefly disconnects all its tunnels.", Run: wireguardServiceAction("restart")},
	)
}

// --- settings

func wireguardSettingsPrint(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	enabled, err := api.GeneralEnabled()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(map[string]string{"enabled": Flag(enabled)})
	}
	c.Fields([][2]string{{"enabled", YesNo(Flag(enabled))}})
	return nil
}

func wireguardSettingsSet(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	return api.GeneralSetEnabled(args.Bool("enabled"))
}

// --- status

func wireguardStatusPrint(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var types []string
	if statusType := strings.ToLower(args.String("type")); statusType != "" {
		types = []string{statusType}
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)
	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var statuses, listErr = systemActivityAwait(c, func() ([]wireguard.Status, error) {
			return api.StatusList(args.String("search"), types...)
		})
		if listErr != nil {
			return listErr
		}
		if asJSON {
			for _, status := range statuses {
				if err := c.JSON(status.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		wireguardStatusShow(c, statuses, args.Bool("detail"))
		return nil
	})
}

// wireguardStatusState is up / down for interfaces, online / stale / offline for peers
func wireguardStatusState(status wireguard.Status) string {
	if status.Type == "interface" {
		if status.InterfaceStatus == "" {
			return "down"
		}
		return status.InterfaceStatus
	}
	if status.PeerStatus == "" {
		return "offline"
	}
	return status.PeerStatus
}

func wireguardStatusHandshake(status wireguard.Status) string {
	if status.Type != "peer" || status.LatestHandshake <= 0 {
		return ""
	}
	return time.Unix(status.LatestHandshake, 0).Local().Format(time.DateTime)
}

func wireguardStatusAge(status wireguard.Status) string {
	if status.HandshakeAge == nil {
		return ""
	}
	return (time.Duration(*status.HandshakeAge) * time.Second).String()
}

func wireguardStatusBytes(status wireguard.Status, value int64) string {
	if status.Type != "peer" {
		return ""
	}
	return ifaceBytes(float64(value))
}

func wireguardStatusShow(c *Context, statuses []wireguard.Status, detail bool) {
	var ids = make([]string, len(statuses))
	for i, status := range statuses {
		ids[i] = status.Interface + "/" + status.PublicKey
	}
	if detail {
		var items = make([][][2]string, len(statuses))
		for i, status := range statuses {
			items[i] = [][2]string{
				{"device", status.Interface},
				{"instance", status.InstanceName},
				{"type", status.Type},
				{"name", status.Name},
				{"status", wireguardStatusState(status)},
				{"public-key", status.PublicKey},
				{"endpoint", status.Endpoint},
				{"allowed-ips", status.AllowedIps},
				{"latest-handshake", wireguardStatusHandshake(status)},
				{"handshake-age", wireguardStatusAge(status)},
				{"sent", wireguardStatusBytes(status, status.TransferTx)},
				{"received", wireguardStatusBytes(status, status.TransferRx)},
				{"keepalive", status.PersistentKeepalive},
			}
		}
		c.Details(items, ids)
		return
	}
	var rows = make([][]string, len(statuses))
	for i, status := range statuses {
		rows[i] = []string{status.Interface, status.Type, status.Name, wireguardStatusState(status), status.Endpoint,
			wireguardStatusAge(status), wireguardStatusBytes(status, status.TransferTx), wireguardStatusBytes(status, status.TransferRx)}
	}
	c.Items([]string{"DEVICE", "TYPE", "NAME", "STATUS", "ENDPOINT", "HANDSHAKE-AGE", "SENT", "RECEIVED"}, rows, ids)
}

// --- service

func wireguardServiceStatus(c *Context, _ *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	status, err := api.ServiceStatus()
	if err != nil {
		return err
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func wireguardServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = wireguardApi(c)
		if err != nil {
			return err
		}
		switch action {
		case "start":
			return api.ServiceStart()
		case "stop":
			return api.ServiceStop()
		case "restart":
			return api.ServiceRestart()
		case "reconfigure":
			return api.ServiceReconfigure()
		}
		return fmt.Errorf("unknown action %s", action)
	}
}
