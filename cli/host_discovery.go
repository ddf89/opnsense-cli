package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/hostdiscovery"
	"strconv"
	"strings"
	"time"
)

// /interface/host-discovery: Interfaces > Neighbors > Automatic Discovery (api/hostdiscovery). The hostwatch daemon
// passively records the IP / MAC pairs it sees in ARP and NDP traffic on the selected interfaces; print lists them
// (or the ARP and NDP tables while hostwatch does not run). /interface/host-discovery/settings holds its settings

const hostDiscoveryApplyHint = `Changes are only saved, run "/interface/host-discovery reconfigure" to apply them.`

func init() {
	var menu = Root.Menu("interface/host-discovery")
	menu.Help = "discovered hosts and the hostwatch service (Interfaces > Neighbors > Automatic Discovery)"
	menu.Add(
		&Command{Name: "print", Help: "list the discovered hosts (IP and MAC addresses per interface)",
			Long: `While hostwatch does not run, OPNsense lists the ARP and NDP tables instead (SOURCE arp-ndp, without
first and last seen).`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every host"},
				{Name: "json", Type: Bool, Help: "one JSON object per line with the API field names"},
				{Name: "search", Help: "only hosts where any field contains this text (case-insensitive)"},
				{Name: "interface", Help: "only hosts on this interface (its description, like LAN)"},
			}, Run: hostDiscoveryPrint},
		&Command{Name: "status", Help: "show whether hostwatch is running", Run: hostDiscoveryStatus},
		&Command{Name: "start", Help: "start hostwatch", Run: hostDiscoveryAction("start")},
		&Command{Name: "stop", Help: "stop hostwatch", Run: hostDiscoveryAction("stop")},
		&Command{Name: "restart", Help: "restart hostwatch", Run: hostDiscoveryAction("restart")},
		&Command{Name: "reconfigure", Help: "apply the saved settings: (re)starts hostwatch when enabled, stops it otherwise",
			Run: hostDiscoveryAction("reconfigure")},
	)

	var settings = Root.Menu("interface/host-discovery/settings")
	settings.Help = "settings of the host discovery"
	settings.Add(
		&Command{Name: "print", Help: "show the host discovery settings",
			Long: `options lists the interfaces that can be watched instead.`,
			Args: []Arg{
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object"},
				{Name: "options", Type: Bool, Help: "list the interfaces that can be watched"},
			}, Run: hostDiscoverySettingsPrint},
		&Command{Name: "set", Help: "change the host discovery settings, the others are kept",
			Long: `  set interfaces=lan,opt1 skip-nets=10.99.0.0/16 expire-ipv4=4h

` + hostDiscoveryApplyHint,
			Args: []Arg{
				{Name: "enabled", Type: Bool, Help: "run hostwatch"},
				{Name: "promisc", Type: Bool, Help: "put the watched interfaces in promiscuous mode (also see traffic of others on a switch port)"},
				{Name: "verbose", Type: Bool, Help: "log every discovery"},
				{Name: "interfaces", Type: List, Help: `the watched interfaces by key like lan,opt1, "" for all`, Complete: hostDiscoveryInterfaceKeys},
				{Name: "skip-nets", Type: List, Help: `networks whose addresses are not recorded like 10.99.0.0/16, "" for none`},
				{Name: "expire-ipv4", Type: Duration, Help: `forget IPv4 addresses not seen for this long (at least 1h), "" for the default`,
					Validate: hostDiscoveryValidateExpire},
				{Name: "expire-ipv6", Type: Duration, Help: `forget IPv6 addresses not seen for this long (at least 1h), "" for the default`,
					Validate: hostDiscoveryValidateExpire},
			}, Check: hostDiscoveryCheckSet, Run: hostDiscoverySettingsSet},
	)
}

func hostDiscoveryApi(c *Context) (*hostdiscovery.HostDiscoveryApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &hostdiscovery.HostDiscoveryApi{OPNsense: opn}, nil
}

func hostDiscoveryValidateExpire(value string) error {
	var duration, err = parseDuration(value)
	if err != nil {
		return err
	}
	if value != "" && (duration < time.Hour || duration%time.Second != 0) {
		return fmt.Errorf("must be whole seconds and at least 1h, got %q", value)
	}
	return nil
}

func hostDiscoveryInterfaceKeys(c *Context) []string {
	var api, err = hostDiscoveryApi(c)
	if err != nil {
		return nil
	}
	var settings, getErr = api.SettingsGet()
	if getErr != nil {
		return nil
	}
	var keys []string
	for _, option := range settings.InterfaceOptions {
		keys = append(keys, option.Key)
	}
	return keys
}

// --- hosts and service

func hostDiscoveryHostFields(host hostdiscovery.Host) [][2]string {
	return [][2]string{
		{"interface", host.Interface},
		{"ip", host.IP},
		{"mac", host.MAC},
		{"organization", host.Organization},
		{"first-seen", host.FirstSeen},
		{"last-seen", host.LastSeen},
		{"source", host.Source},
	}
}

func hostDiscoveryMatches(host hostdiscovery.Host, args *Args) bool {
	if name := args.String("interface"); name != "" && !strings.EqualFold(host.Interface, name) {
		return false
	}
	if search := strings.ToLower(args.String("search")); search != "" {
		var text = strings.ToLower(strings.Join([]string{host.Interface, host.IP, host.MAC, host.Organization,
			host.FirstSeen, host.LastSeen, host.Source}, "\n"))
		return strings.Contains(text, search)
	}
	return true
}

func hostDiscoveryPrint(c *Context, args *Args) error {
	var api, err = hostDiscoveryApi(c)
	if err != nil {
		return err
	}
	var all, listErr = api.HostList()
	if listErr != nil {
		return listErr
	}
	var hosts []hostdiscovery.Host
	for _, host := range all {
		if hostDiscoveryMatches(host, args) {
			hosts = append(hosts, host)
		}
	}
	switch {
	case args.Bool("json"):
		for _, host := range hosts {
			if err := c.JSON(host); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		for i, host := range hosts {
			if i > 0 {
				c.Println()
			}
			c.Fields(hostDiscoveryHostFields(host))
		}
	default:
		var rows = make([][]string, len(hosts))
		for i, host := range hosts {
			rows[i] = []string{host.Interface, host.IP, host.MAC, host.Organization, host.FirstSeen, host.LastSeen, host.Source}
		}
		c.Table([]string{"INTERFACE", "IP", "MAC", "ORGANIZATION", "FIRST-SEEN", "LAST-SEEN", "SOURCE"}, rows)
	}
	return nil
}

func hostDiscoveryStatus(c *Context, _ *Args) error {
	var api, err = hostDiscoveryApi(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.ServiceStatus()
	if statusErr != nil {
		return statusErr
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func hostDiscoveryAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = hostDiscoveryApi(c)
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
		default:
			return api.ServiceReconfigure()
		}
	}
}

// --- settings

// hostDiscoveryExpire renders an interval in seconds like 4h0m0s, "" as default
func hostDiscoveryExpire(seconds string) string {
	if seconds == "" {
		return "default"
	}
	if value, err := strconv.Atoi(seconds); err == nil {
		return (time.Duration(value) * time.Second).String()
	}
	return seconds
}

func hostDiscoverySettingsPrint(c *Context, args *Args) error {
	var api, err = hostDiscoveryApi(c)
	if err != nil {
		return err
	}
	var settings, getErr = api.SettingsGet()
	if getErr != nil {
		return getErr
	}
	if args.Bool("options") {
		var rows = make([][]string, len(settings.InterfaceOptions))
		for i, option := range settings.InterfaceOptions {
			rows[i] = []string{option.Key, option.Value, YesNo(Flag(option.Selected))}
		}
		c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		return nil
	}
	if args.Bool("json") {
		return c.JSON(map[string]string{
			"enabled": settings.Enabled, "promisc": settings.Promisc, "verbose": settings.Verbose,
			"skip_nets": settings.SkipNets, "expire4_interval": settings.Expire4Interval,
			"expire6_interval": settings.Expire6Interval, "interface": settings.Interfaces,
		})
	}
	var interfaces = settings.Interfaces
	if interfaces == "" {
		interfaces = "all"
	}
	c.Fields([][2]string{
		{"enabled", YesNo(settings.Enabled)},
		{"promisc", YesNo(settings.Promisc)},
		{"verbose", YesNo(settings.Verbose)},
		{"interfaces", interfaces},
		{"skip-nets", settings.SkipNets},
		{"expire-ipv4", hostDiscoveryExpire(settings.Expire4Interval)},
		{"expire-ipv6", hostDiscoveryExpire(settings.Expire6Interval)},
	})
	return nil
}

func hostDiscoveryCheckSet(args *Args) error {
	if len(args.Given()) == 0 {
		return errors.New("nothing to change, give the settings to set (type \"set ?\" for help)")
	}
	return nil
}

func hostDiscoverySettingsSet(c *Context, args *Args) error {
	var api, err = hostDiscoveryApi(c)
	if err != nil {
		return err
	}
	var fields hostdiscovery.SettingsFields
	var flag = func(name string, target **string) {
		if args.Has(name) {
			var value = Flag(args.Bool(name))
			*target = &value
		}
	}
	flag("enabled", &fields.Enabled)
	flag("promisc", &fields.Promisc)
	flag("verbose", &fields.Verbose)
	var list = func(name string, target **string) {
		if args.Has(name) {
			var value = strings.Join(args.List(name), ",")
			*target = &value
		}
	}
	list("interfaces", &fields.Interfaces)
	list("skip-nets", &fields.SkipNets)
	var seconds = func(name string, target **string) {
		if args.Has(name) {
			var value = ""
			if args.String(name) != "" {
				value = strconv.Itoa(int(args.Duration(name) / time.Second))
			}
			*target = &value
		}
	}
	seconds("expire-ipv4", &fields.Expire4Interval)
	seconds("expire-ipv6", &fields.Expire6Interval)
	return api.SettingsSet(fields)
}
