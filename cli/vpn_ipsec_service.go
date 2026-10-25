package cli

// /vpn/ipsec/service: the strongSwan service, the global IPsec switch (enable / disable, the "Enable IPsec"
// checkbox of VPN > IPsec > Connections) and the pending changes of key pairs (apply). Actions are POSTed and
// only succeed on an explicit OK of OPNsense

func init() {
	var menu = Root.Menu("vpn/ipsec/service")
	menu.Help = "the IPsec (strongSwan) service and the global IPsec switch"
	menu.Add(
		&Command{Name: "status", Help: "show whether IPsec is enabled and strongSwan is running", Run: vpnIpsecServiceStatus},
		&Command{Name: "enable", Help: "switch IPsec on (saved only, reconfigure applies it)",
			Long: `Sets the "Enable IPsec" switch. Like in the GUI this only saves it: "reconfigure" starts strongSwan with the
enabled connections, which may bring tunnels up.`,
			Run: vpnIpsecServiceEnabler(true)},
		&Command{Name: "disable", Help: "switch IPsec off (saved only, reconfigure applies it)",
			Long: `Clears the "Enable IPsec" switch, "reconfigure" then stops strongSwan and all tunnels go down.`,
			Run:  vpnIpsecServiceEnabler(false)},
		&Command{Name: "start", Help: "start strongSwan (nothing happens while IPsec is disabled)", Run: vpnIpsecServiceAction("start")},
		&Command{Name: "stop", Help: "stop strongSwan", Confirm: "This stops strongSwan, all IPsec tunnels go down.",
			Run: vpnIpsecServiceAction("stop")},
		&Command{Name: "restart", Help: "restart strongSwan", Confirm: "This restarts strongSwan, all IPsec tunnels are re-established.",
			Run: vpnIpsecServiceAction("restart")},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (connections, pools, VTIs, settings)",
			Long: `Registers the virtual tunnel interfaces, reloads the firewall rules, regenerates the strongSwan
configuration and reloads strongSwan (or stops it while IPsec is disabled). Changed connections may go down and
come up again.`,
			Run: vpnIpsecServiceAction("reconfigure")},
		&Command{Name: "apply", Help: "apply pending key pair changes (the Apply button of the key pairs page)",
			Long: `Runs the full IPsec configure like the Apply button of VPN > IPsec > Key Pairs and clears the pending flag
"status" shows.`,
			Run: vpnIpsecServiceAction("apply")},
	)
}

func vpnIpsecServiceStatus(c *Context, _ *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.ServiceStatus()
	if statusErr != nil {
		return statusErr
	}
	var legacy, legacyErr = api.LegacyStatus()
	if legacyErr != nil {
		return legacyErr
	}
	c.Fields([][2]string{
		{"enabled", YesNo(Flag(legacy.Enabled))},
		{"status", status},
		{"pending-changes", YesNo(Flag(legacy.Pending))},
	})
	if legacy.Pending {
		c.Infof(`key pair changes are pending, run "/vpn/ipsec/service apply" to apply them`)
	}
	return nil
}

func vpnIpsecServiceEnabler(enabled bool) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = vpnIpsecApi(c)
		if err != nil {
			return err
		}
		var current, currentErr = api.IsEnabled()
		if currentErr != nil {
			return currentErr
		}
		if current == enabled {
			c.Infof("IPsec is already %s", EnabledWord(enabled))
			return nil
		}
		if err := api.SetEnabled(enabled); err != nil {
			return err
		}
		c.Infof(`IPsec is %s, run "/vpn/ipsec/service reconfigure" to apply it`, EnabledWord(enabled))
		return nil
	}
}

func vpnIpsecServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = vpnIpsecApi(c)
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
		case "apply":
			return api.ApplyLegacy()
		default:
			return api.ServiceReconfigure()
		}
	}
}
