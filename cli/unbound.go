package cli

import (
	"opnsense-cli/opnsense/api/unbound"
)

// /unbound/service: status, restart and reconfigure of the Unbound DNS resolver

func init() {
	Root.Sub("unbound", "Unbound DNS resolver")
	var menu = Root.Menu("unbound/service")
	menu.Help = "the Unbound service"
	menu.Add(
		&Command{Name: "status", Help: "show whether Unbound is running", Run: unboundServiceStatus},
		&Command{Name: "restart", Help: "restart Unbound", Run: unboundServiceRestart},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (e.g. changed host overrides) to Unbound", Run: unboundServiceReconfigure},
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

func unboundServiceReconfigure(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.ServiceReconfigure()
}
