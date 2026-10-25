package cli

// /dnsmasq/service: the dnsmasq service. Actions are POSTed and only succeed on an explicit OK of OPNsense

func init() {
	var menu = Root.Menu("dnsmasq/service")
	menu.Help = "the dnsmasq service"
	menu.Add(
		&Command{Name: "status", Help: "show whether dnsmasq is running", Run: dnsmasqServiceStatus},
		&Command{Name: "start", Help: "start dnsmasq", Run: dnsmasqServiceAction("start")},
		&Command{Name: "stop", Help: "stop dnsmasq", Run: dnsmasqServiceAction("stop")},
		&Command{Name: "restart", Help: "restart dnsmasq", Run: dnsmasqServiceAction("restart")},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (regenerate the config and reload dnsmasq)",
			Run: dnsmasqServiceAction("reconfigure")},
	)
}

func dnsmasqServiceStatus(c *Context, _ *Args) error {
	var api, err = dnsmasqApi(c)
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

func dnsmasqServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = dnsmasqApi(c)
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
