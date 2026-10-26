package cli

import (
	"errors"
	"fmt"
	"strings"

	"opnsense-cli/opnsense/api/ddclient"
)

// /ddclient: the Dynamic DNS client of the os-ddclient plugin (Services > Dynamic DNS, api/dyndns).
// /ddclient/account are the DDNS accounts with their current address, /ddclient/settings the general settings,
// /ddclient/service the service. The menus exist without the plugin, their commands then fail with a hint how to
// install it

const ddclientApplyHint = `Changes are only saved, run "/ddclient/service reconfigure" to apply them.`

func init() {
	Root.Menu("ddclient").Help = "Dynamic DNS client, plugin os-ddclient (Services > Dynamic DNS)"

	var settings = Root.Menu("ddclient/settings")
	settings.Help = "general Dynamic DNS settings: enabled, interval, backend"
	settings.Add(
		&Command{Name: "print", Help: "show the settings",
			Long: `Shows the general settings. backend is native (OPNsense's own implementation) or ddclient (the ddclient
daemon). options=backend lists the choices of the backend.`,
			Args: []Arg{
				{Name: "options", Help: "list the choices of this setting instead", Values: []string{"backend"}},
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object with the API names"},
			},
			Run: ddclientRun(ddclientSettingsPrint)},
		&Command{Name: "set", Help: "change settings, the others are kept",
			Long: `Changes the given settings, the others are kept.

  set interval=600 verbose
  set backend=ddclient

The services an account can use depend on the backend (see "/ddclient/account print options=service"): accounts
of a service the other backend lacks can not be changed any more until their service is changed.
` + ddclientApplyHint,
			Args: []Arg{
				{Name: "enabled", Type: Bool, Help: "run the Dynamic DNS service"},
				{Name: "verbose", Type: Bool, Help: "log verbosely"},
				{Name: "allow-ipv6", Type: Bool, Help: "allow IPv6 addresses (ddclient backend)"},
				{Name: "interval", Type: Int, Help: "seconds between two checks of the address (1-86400)", Validate: ddclientNumber(1, 86400)},
				{Name: "backend", Help: "native (OPNsense's implementation) or ddclient (the ddclient daemon)", Values: []string{"native", "ddclient"}},
			},
			Run: ddclientRun(ddclientSettingsSet)},
	)

	var service = Root.Menu("ddclient/service")
	service.Help = "the Dynamic DNS service"
	service.Add(
		&Command{Name: "status", Help: "show whether the service is running", Run: ddclientRun(ddclientServiceStatus)},
		&Command{Name: "start", Help: "start the service (it updates the enabled accounts at their providers when needed)",
			Run: ddclientRun(ddclientServiceAction("start"))},
		&Command{Name: "stop", Help: "stop the service", Run: ddclientRun(ddclientServiceAction("stop"))},
		&Command{Name: "restart", Help: "restart the service", Run: ddclientRun(ddclientServiceAction("restart"))},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (write it and restart the service, stop it when disabled)",
			Run: ddclientRun(ddclientServiceAction("reconfigure"))},
	)
}

func ddclientApi(c *Context) (*ddclient.DdclientApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &ddclient.DdclientApi{OPNsense: opn}, nil
}

// ddclientNotInstalled explains the HTTP 404 of the plugin's endpoints, other errors are returned as they are
func ddclientNotInstalled(err error) error {
	if err != nil && ddclient.IsNotInstalled(err) {
		return fmt.Errorf(`%s is not installed (install it with "/system/firmware/plugin install %s")`, ddclient.PluginName, ddclient.PluginName)
	}
	return err
}

// ddclientRun wraps a command so a missing plugin is reported as such
func ddclientRun(run func(c *Context, args *Args) error) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		return ddclientNotInstalled(run(c, args))
	}
}

// ddclientNumber is a required number (the field can not be cleared) from min to max
func ddclientNumber(min int, max int) func(string) error {
	return func(value string) error {
		if value == "" {
			return errors.New("must not be empty, leave it out to keep the current value")
		}
		return ValidateRange(min, max)(value)
	}
}

// ddclientBackendName renders a backend key the way the GUI does (opnsense is "native")
func ddclientBackendName(key string) string {
	if key == "opnsense" {
		return "native"
	}
	return key
}

func ddclientSettingsPrint(c *Context, args *Args) error {
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	settings, err := api.SettingsGet()
	if err != nil {
		return err
	}
	if args.Has("options") {
		if args.Bool("json") {
			for _, option := range settings.BackendOptions {
				if err := c.JSON(option); err != nil {
					return err
				}
			}
			return nil
		}
		var rows [][]string
		for _, option := range settings.BackendOptions {
			rows = append(rows, []string{ddclientBackendName(option.Key), option.Key, YesNo(Flag(option.Selected))})
		}
		c.Table([]string{"NAME", "KEY", "SELECTED"}, rows)
		return nil
	}
	if args.Bool("json") {
		return c.JSON(settings.SettingsFields())
	}
	c.Fields([][2]string{
		{"enabled", YesNo(settings.Enabled)},
		{"verbose", YesNo(settings.Verbose)},
		{"allow-ipv6", YesNo(settings.AllowIpv6)},
		{"interval", settings.DaemonDelay},
		{"backend", ddclientBackendName(settings.Backend)},
	})
	return nil
}

func ddclientSettingsSet(c *Context, args *Args) error {
	var values = map[string]string{}
	for _, flag := range [][2]string{{"enabled", "enabled"}, {"verbose", "verbose"}, {"allow-ipv6", "allowipv6"}} {
		if args.Has(flag[0]) {
			values[flag[1]] = Flag(args.Bool(flag[0]))
		}
	}
	if args.Has("interval") {
		values["daemon_delay"] = args.String("interval")
	}
	if args.Has("backend") {
		values["backend"] = "opnsense"
		if strings.EqualFold(args.String("backend"), "ddclient") {
			values["backend"] = "ddclient"
		}
	}
	if len(values) == 0 {
		return errors.New(`set: nothing to change, give at least one setting like interval= (type "set ?" for help)`)
	}
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	return api.SettingsSet(values)
}

func ddclientServiceStatus(c *Context, _ *Args) error {
	var api, err = ddclientApi(c)
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

func ddclientServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = ddclientApi(c)
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
