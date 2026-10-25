package cli

import (
	"opnsense-cli/opnsense/api/unbound"
)

// /unbound/service: status, start, stop, restart and reconfigure of the Unbound DNS resolver

func init() {
	Root.Sub("unbound", "Unbound DNS resolver")
	var menu = Root.Menu("unbound/service")
	menu.Help = "the Unbound service"
	menu.Add(
		&Command{Name: "status", Help: "show whether Unbound is running", Run: unboundServiceStatus},
		&Command{Name: "start", Help: "start Unbound", Run: unboundServiceStart},
		&Command{Name: "stop", Help: "stop Unbound", Confirm: "This stops the DNS resolver of the firewall (and of its clients using it).",
			Run: unboundServiceStop},
		&Command{Name: "restart", Help: "restart Unbound", Run: unboundServiceRestart},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (e.g. changed host overrides) to Unbound",
			Long: `general also reloads the system DNS configuration and restarts the DHCP servers, as the General page does:
needed after "/unbound/settings set" (enabled, DHCP registration, ...).`,
			Args: []Arg{{Name: "general", Type: Bool, Help: "also reload the system DNS configuration and restart the DHCP servers"}},
			Run:  unboundServiceReconfigure},
	)
}

// unboundApi returns the Unbound API of the session's connection
func unboundApi(c *Context) (*unbound.UnboundApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &unbound.UnboundApi{OPNsense: opn}, nil
}

func unboundServiceStatus(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
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

func unboundServiceRestart(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.ServiceRestart()
}

func unboundServiceReconfigure(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	if args.Bool("general") {
		return api.ServiceReconfigureGeneral()
	}
	return api.ServiceReconfigure()
}

func unboundServiceStart(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.ServiceStart()
}

func unboundServiceStop(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.ServiceStop()
}
