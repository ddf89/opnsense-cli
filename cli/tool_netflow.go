package cli

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
)

// /tool/netflow: NetFlow export of Reporting > NetFlow (api/diagnostics/netflow): capture settings, status, the flow
// cache, reconfigure and deleting the locally collected data. The collected data is shown by /tool/insight

const toolNetflowApplyHint = `Changes are only saved, run "/tool/netflow reconfigure" to apply them.`

func init() {
	var menu = Root.Menu("tool/netflow")
	menu.Help = "NetFlow export of the traffic to collectors and local collection for /tool/insight"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the NetFlow settings",
			Long: `Shows the capture settings: the interfaces whose traffic is exported, the interfaces of which only
outgoing traffic is captured (egress-only, for WAN interfaces with NAT), the NetFlow version, the collectors
(targets, ip:port) and whether the flows are collected on the firewall (collect, needed for /tool/insight;
OPNsense then adds the local collector 127.0.0.1:2056 to the targets). json prints the answer of OPNsense.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings as OPNsense returns them"}},
			Run:  toolNetflowPrint,
		},
		&Command{
			Name: "set",
			Help: "change NetFlow settings, the others are kept",
			Long: `Changes the given settings. interfaces= and egress-only= take interface names (lan, wan, opt1) or
descriptions, targets= collectors as ip:port ([ipv6]:port), an empty value clears a list. With collect OPNsense
adds 127.0.0.1:2056 to the targets; it stays there after collect=no until removed with targets=.
` + toolNetflowApplyHint + `

  set interfaces=lan targets=192.0.2.10:2055 version=v9
  set collect inactive-timeout=30`,
			Args: []Arg{
				{Name: "interfaces", Type: List, Help: "capture the traffic of these interfaces", Complete: toolNetflowCompleteInterfaces},
				{Name: "egress-only", Type: List, Help: "capture only the outgoing traffic of these interfaces", Complete: toolNetflowCompleteInterfaces},
				{Name: "version", Values: []string{"v5", "v9"}, Help: "NetFlow version"},
				{Name: "targets", Type: List, Help: "collectors as ip:port", Validate: toolNetflowValidateTargets},
				{Name: "collect", Type: Bool, Help: "collect and aggregate the flows on the firewall (Insight)"},
				{Name: "active-timeout", Help: "export long running flows after this many seconds", Validate: ValidateRange(1, 86400)},
				{Name: "inactive-timeout", Help: "export flows idle for this many seconds", Validate: ValidateRange(1, 86400)},
			},
			Check: func(args *Args) error {
				if len(args.Given()) == 0 {
					return errors.New(`nothing to change, give at least one setting like interfaces= (type "set ?" for help)`)
				}
				return nil
			},
			Run: toolNetflowSet,
		},
		&Command{
			Name: "status",
			Help: "show whether NetFlow is capturing and collecting",
			Long: `Shows whether the capture runs (and how many collectors it sends to), whether capture and local
collection are configured, and when the collected flows were last aggregated for /tool/insight.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the answers of OPNsense as one JSON object"}},
			Run:  toolNetflowStatus,
		},
		&Command{
			Name:    "reconfigure",
			Aliases: []string{"apply"},
			Help:    "apply the settings: restart the capture, start or stop the local collection",
			Run: func(c *Context, _ *Args) error {
				var api, err = ifaceDiagnostics(c)
				if err != nil {
					return err
				}
				return api.NetflowReconfigure()
			},
		},
		&Command{
			Name:    "reset-data",
			Help:    "delete all locally collected NetFlow data (the Insight data)",
			Confirm: "This deletes all locally collected NetFlow data, the Insight reports start empty.",
			Run: func(c *Context, _ *Args) error {
				var api, err = ifaceDiagnostics(c)
				if err != nil {
					return err
				}
				return api.NetflowReset()
			},
		},
	)

	var cache = Root.Menu("tool/netflow/cache")
	cache.Help = "the NetFlow flow cache of the captured interfaces"
	cache.Add(&Command{
		Name: "print",
		Help: "show the flows in the cache per captured interface",
		Long: `Shows the flow cache (flows not yet exported) of every captured interface: packets and distinct source
and destination addresses. Empty while nothing is captured.`,
		Args: []Arg{{Name: "json", Type: Bool, Help: "print the statistics as OPNsense returns them, one interface per line"}},
		Run:  toolNetflowCachePrint,
	})
}

func toolNetflowValidateTargets(value string) error {
	for _, target := range splitList(value) {
		var host, port, err = net.SplitHostPort(target)
		if err != nil || net.ParseIP(host) == nil || ValidatePort(port) != nil {
			return fmt.Errorf("must be collectors as ip:port like 192.0.2.10:2055, got %q", target)
		}
	}
	return nil
}

func toolNetflowCompleteInterfaces(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var settings, getErr = api.NetflowSettings()
	if getErr != nil {
		return nil
	}
	var names = make([]string, 0, len(settings.InterfaceOptions))
	for key := range settings.InterfaceOptions {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}

// toolNetflowInterfaces maps interface names or descriptions to the keys OPNsense offers
func toolNetflowInterfaces(names []string, options map[string]string) ([]string, error) {
	var keys = []string{}
	for _, name := range names {
		var found = ""
		for key, description := range options {
			if strings.EqualFold(key, name) || strings.EqualFold(description, name) {
				found = key
				break
			}
		}
		if found == "" {
			var available = make([]string, 0, len(options))
			for key := range options {
				available = append(available, key)
			}
			sort.Strings(available)
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("interface %q, NetFlow can capture %s", name, strings.Join(available, ", "))}
		}
		keys = append(keys, found)
	}
	return keys, nil
}

func toolNetflowPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var settings, getErr = api.NetflowSettings()
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		return c.JSON(settings.Raw)
	}
	c.Fields([][2]string{
		{"interfaces", strings.Join(settings.Interfaces, ",")},
		{"egress-only", strings.Join(settings.EgressOnly, ",")},
		{"version", settings.Version},
		{"targets", strings.Join(settings.Targets, ",")},
		{"collect", YesNo(Flag(settings.LocalCollection))},
		{"active-timeout", settings.ActiveTimeout},
		{"inactive-timeout", settings.InactiveTimeout},
	})
	return nil
}

func toolNetflowSet(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var fields diagnostics.NetflowSettingsFields
	if args.Has("interfaces") || args.Has("egress-only") {
		var settings, getErr = api.NetflowSettings()
		if getErr != nil {
			return getErr
		}
		for _, list := range []struct {
			arg    string
			target **[]string
		}{{"interfaces", &fields.Interfaces}, {"egress-only", &fields.EgressOnly}} {
			if !args.Has(list.arg) {
				continue
			}
			var keys, mapErr = toolNetflowInterfaces(args.List(list.arg), settings.InterfaceOptions)
			if mapErr != nil {
				return mapErr
			}
			*list.target = &keys
		}
	}
	if args.Has("version") {
		var version = strings.ToLower(args.String("version"))
		fields.Version = &version
	}
	if args.Has("targets") {
		var targets = args.List("targets")
		if targets == nil {
			targets = []string{}
		}
		fields.Targets = &targets
	}
	if args.Has("collect") {
		var collect = args.Bool("collect")
		fields.LocalCollection = &collect
	}
	if args.Has("active-timeout") {
		var timeout = args.String("active-timeout")
		fields.ActiveTimeout = &timeout
	}
	if args.Has("inactive-timeout") {
		var timeout = args.String("inactive-timeout")
		fields.InactiveTimeout = &timeout
	}
	return api.NetflowSetSettings(fields)
}

func toolNetflowStatus(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.NetflowStatus()
	if statusErr != nil {
		return statusErr
	}
	var capture, local, enabledErr = api.NetflowEnabled()
	if enabledErr != nil {
		return enabledErr
	}
	var metadata, metadataErr = api.InsightMetadata()
	if metadataErr != nil {
		return metadataErr
	}
	if args.Bool("json") {
		return c.JSON(map[string]any{"status": status.Raw, "netflow": Flag(capture), "local": Flag(local), "metadata": metadata.Raw})
	}
	var running = "inactive"
	if status.Active {
		running = "active"
		if status.Collectors != "" {
			running += " (" + status.Collectors + " collectors)"
		}
	}
	var lastSync = "never"
	if !metadata.LastSync.IsZero() {
		lastSync = metadata.LastSync.Format("2006-01-02 15:04:05")
	}
	c.Fields([][2]string{
		{"status", running},
		{"capture-configured", YesNo(Flag(capture))},
		{"collect", YesNo(Flag(local))},
		{"last-aggregation", lastSync},
	})
	return nil
}

func toolNetflowCachePrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var nodes, cacheErr = api.NetflowCache()
	if cacheErr != nil {
		return cacheErr
	}
	if args.Bool("json") {
		for _, node := range nodes {
			if err := c.JSON(node.Raw); err != nil {
				return err
			}
		}
		return nil
	}
	var names = map[string]string{}
	if len(nodes) > 0 {
		if interfaces, namesErr := api.InsightInterfaces(); namesErr == nil {
			names = interfaces
		}
	}
	var rows = make([][]string, 0, len(nodes))
	for _, node := range nodes {
		rows = append(rows, []string{node.Interface, names[node.Interface], strconv.FormatInt(node.Packets, 10),
			strconv.FormatInt(node.Sources, 10), strconv.FormatInt(node.Destinations, 10)})
	}
	c.Table([]string{"DEVICE", "INTERFACE", "PACKETS", "SOURCES", "DESTINATIONS"}, rows)
	return nil
}
