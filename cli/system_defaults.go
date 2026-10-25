package cli

import (
	"opnsense-cli/opnsense/api/system"
)

// /system/defaults: factory defaults (System > Configuration > Defaults)

const systemDefaultsResetWarning = "A factory reset wipes the WHOLE configuration of the firewall and reboots it: all settings, " +
	"users and API keys (including the one used right now) are lost, there is no undo. Download a backup first if you might need it."

func init() {
	var menu = Root.Menu("system/defaults")
	menu.Help = "factory defaults (System > Configuration > Defaults)"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show what a factory reset resets the firewall to",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw answer as one JSON object"}},
			Run:  systemDefaultsPrint,
		},
		&Command{
			Name:    "reset",
			Help:    "reset the firewall to factory defaults and reboot it",
			Long:    "Download a backup first with /system/backup download.",
			Confirm: systemDefaultsResetWarning,
			Run:     systemDefaultsReset,
		},
	)
}

func systemDefaultsApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

func systemDefaultsPrint(c *Context, args *Args) error {
	var api, err = systemDefaultsApi(c)
	if err != nil {
		return err
	}
	defaults, err := api.DefaultsGet()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(defaults)
	}
	c.Fields([][2]string{{"default-ip", defaults.DefaultIp}})
	return nil
}

func systemDefaultsReset(c *Context, _ *Args) error {
	var api, err = systemDefaultsApi(c)
	if err != nil {
		return err
	}
	// also makes sure we talk to a working API before the destructive call
	defaults, err := api.DefaultsGet()
	if err != nil {
		return err
	}
	if err := api.DefaultsFactoryReset(); err != nil {
		return err
	}
	c.Infof("factory reset scheduled, the firewall reboots and comes back with LAN address %s", defaults.DefaultIp)
	return nil
}
