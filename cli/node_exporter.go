package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/nodeexporter"
)

// /node-exporter: the Prometheus node exporter of the plugin os-node_exporter (Services > Node Exporter):
// /node-exporter/settings (print, set) and /node-exporter/service (status, start, stop, restart, reconfigure).
// The menus are always registered, without the plugin every command explains how to install it

const nodeExporterApplyHint = `Changes are only saved, run "/node-exporter/service reconfigure" to apply them.`

func init() {
	Root.Menu("node-exporter").Help = "Prometheus node exporter (plugin " + nodeexporter.Plugin + ", Services > Node Exporter)"

	var settings = Root.Menu("node-exporter/settings")
	settings.Help = "the node exporter settings: enabled, listen address and port, collectors"
	settings.Add(
		&Command{
			Name: "print",
			Help: "show the node exporter settings",
			Long: `Shows the settings. collectors lists the enabled collectors of those the plugin switches (` +
				strings.Join(nodeexporter.CollectorNames, ", ") + `); node_exporter's other collectors keep their
defaults. json prints the settings as one object with the API field names.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings as one JSON object"}},
			Run:  nodeExporterRun(nodeExporterSettingsPrint),
		},
		&Command{
			Name: "set",
			Help: "change the node exporter settings, the others are kept",
			Long: `Changes the given settings, the others are kept. collectors are exactly the collectors to enable, the
others of the list are disabled (collectors= disables all). The plugin (1.2) does not pass the interrupts
collector on to node_exporter. The default listen address 0.0.0.0 exposes the metrics on every interface;
prefer a LAN address or 127.0.0.1.

  set enabled listen-address=192.168.1.1 collectors=cpu,filesystem,loadavg,meminfo,netdev
  set listen-port=9101

` + nodeExporterApplyHint,
			Args: []Arg{
				{Name: "enabled", Type: Bool, Help: "run the node exporter"},
				{Name: "listen-address", Help: "the IP address to listen on, 0.0.0.0 or :: for all", Validate: nodeExporterValidateAddress},
				{Name: "listen-port", Type: Int, Help: "the TCP port to listen on (default 9100)", Validate: nodeExporterValidatePort},
				{Name: "collectors", Type: List, Values: nodeexporter.CollectorNames, Help: "the collectors to enable (" + strings.Join(nodeexporter.CollectorNames, ", ") + "), the others are disabled"},
			},
			Check: func(args *Args) error {
				if len(args.Given()) == 0 {
					return errors.New(`nothing to change, give at least one setting (type "set ?" for help)`)
				}
				return nil
			},
			Run: nodeExporterRun(nodeExporterSettingsSet),
		},
	)

	var service = Root.Menu("node-exporter/service")
	service.Help = "the node exporter service"
	service.Add(
		&Command{Name: "status", Help: "show whether the node exporter is running (disabled: not enabled in the settings)",
			Run: nodeExporterRun(nodeExporterServiceStatus)},
		&Command{Name: "start", Help: "start the node exporter", Run: nodeExporterRun(nodeExporterServiceAction("start"))},
		&Command{Name: "stop", Help: "stop the node exporter (until the next reconfigure or boot)", Run: nodeExporterRun(nodeExporterServiceAction("stop"))},
		&Command{Name: "restart", Help: "restart the node exporter", Run: nodeExporterRun(nodeExporterServiceAction("restart"))},
		&Command{Name: "reconfigure", Aliases: []string{"apply"},
			Help: "apply the saved settings: regenerate the configuration, restart the node exporter when enabled, stop it otherwise",
			Run:  nodeExporterRun(nodeExporterServiceAction("reconfigure"))},
	)
}

// nodeExporterRun connects to the node exporter API and explains a missing plugin
func nodeExporterRun(run func(c *Context, api *nodeexporter.NodeExporterApi, args *Args) error) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var opn, err = c.Api()
		if err != nil {
			return err
		}
		return nodeExporterError(run(c, &nodeexporter.NodeExporterApi{OPNsense: opn}, args))
	}
}

// nodeExporterError replaces the HTTP 404 OPNsense answers without the plugin by an install hint
func nodeExporterError(err error) error {
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 404 {
		return fmt.Errorf("%s is not installed (install it with \"/system/firmware/plugin install %s\")", nodeexporter.Plugin, nodeexporter.Plugin)
	}
	return err
}

func nodeExporterValidateAddress(value string) error {
	if value == "" {
		return errors.New("must not be empty, use 0.0.0.0 to listen on all addresses")
	}
	return ValidateIP(value)
}

func nodeExporterValidatePort(value string) error {
	if value == "" {
		return errors.New("must not be empty, the default is 9100")
	}
	return ValidatePort(value)
}

func nodeExporterSettingsPrint(c *Context, api *nodeexporter.NodeExporterApi, args *Args) error {
	var settings, err = api.SettingsGet()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(settings)
	}
	c.Fields([][2]string{
		{"enabled", YesNo(settings.Enabled)},
		{"listen-address", settings.ListenAddress},
		{"listen-port", settings.ListenPort},
		{"collectors", strings.Join(settings.Collectors(), ",")},
	})
	return nil
}

func nodeExporterSettingsSet(c *Context, api *nodeexporter.NodeExporterApi, args *Args) error {
	var update nodeexporter.SettingsUpdate
	if args.Has("enabled") {
		var enabled = args.Bool("enabled")
		update.Enabled = &enabled
	}
	if args.Has("listen-address") {
		var address = args.String("listen-address")
		update.ListenAddress = &address
	}
	if args.Has("listen-port") {
		var port = args.Int("listen-port")
		update.ListenPort = &port
	}
	if args.Has("collectors") {
		update.Collectors = []string{}
		for _, name := range args.List("collectors") {
			update.Collectors = append(update.Collectors, strings.ToLower(name))
		}
	}
	if err := api.SettingsSet(update); err != nil {
		return err
	}
	// warn about metrics on every interface (the default address) when the result is enabled
	if update.Enabled != nil || update.ListenAddress != nil {
		if settings, err := api.SettingsGet(); err == nil && settings.Enabled == "1" && nodeExporterAllAddresses(settings.ListenAddress) {
			c.Infof("warning: the node exporter listens on all addresses (%s), including WAN; consider listen-address=<LAN address> or 127.0.0.1", settings.ListenAddress)
		}
	}
	return nil
}

func nodeExporterAllAddresses(address string) bool {
	var ip = net.ParseIP(address)
	return ip == nil || ip.IsUnspecified()
}

func nodeExporterServiceStatus(c *Context, api *nodeexporter.NodeExporterApi, _ *Args) error {
	var status, err = api.ServiceStatus()
	if err != nil {
		return err
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func nodeExporterServiceAction(action string) func(c *Context, api *nodeexporter.NodeExporterApi, _ *Args) error {
	return func(c *Context, api *nodeexporter.NodeExporterApi, _ *Args) error {
		switch action {
		case "start", "restart":
			// OPNsense answers OK without doing anything while node_exporter's rc.conf.d says NO (disabled, or
			// enabled but not applied yet): refuse when disabled, check the outcome otherwise
			var status, err = api.ServiceStatus()
			if err != nil {
				return err
			}
			if status == nodeexporter.StatusDisabled {
				return fmt.Errorf(`%s: the node exporter is disabled, run "/node-exporter/settings set enabled" and "/node-exporter/service reconfigure"`, action)
			}
			if action == "start" {
				err = api.ServiceStart()
			} else {
				err = api.ServiceRestart()
			}
			if err != nil {
				return err
			}
			return nodeExporterWaitRunning(c, api, action)
		case "stop":
			return api.ServiceStop()
		default:
			return api.ServiceReconfigure()
		}
	}
}

// nodeExporterWaitRunning polls the status for a few seconds after a start or restart
func nodeExporterWaitRunning(c *Context, api *nodeexporter.NodeExporterApi, action string) error {
	var status string
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			select {
			case <-c.Done():
				return nil
			case <-time.After(300 * time.Millisecond):
			}
		}
		var err error
		if status, err = api.ServiceStatus(); err != nil {
			return err
		}
		if status == nodeexporter.StatusRunning {
			return nil
		}
	}
	return fmt.Errorf(`%s: the node exporter is not running afterwards (status %s); apply changed settings with "/node-exporter/service reconfigure"`, action, status)
}
