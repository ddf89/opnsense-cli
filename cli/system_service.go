package cli

import (
	"encoding/json"
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/service: System > Diagnostics > Services, every service configd knows with its state. Items are selected
// by the # of print, the id (name, or name/instance for services with several instances like openvpn/1) or the
// name. Locked services are always needed (configd, webgui, pf ...): like the web UI only restart is offered for
// them. Stopping a service and restarting one that carries the management access ask for confirmation

const (
	systemServiceItemHelp    = "the #, id (name or name/instance) or name of the service"
	systemServiceStopWarning = "This stops the service until it is started again (or the firewall reboots), " +
		"its clients lose it (DNS, DHCP, VPN, ...)."
)

// systemServiceCritical are the services whose restart interrupts the management access or all traffic
var systemServiceCritical = map[string]string{
	"webgui":  "the web GUI and this API (the answer to the restart may get lost)",
	"configd": "every API action and the web GUI until configd is back",
	"openssh": "SSH access (open sessions survive)",
	"pf":      "all traffic while the packet filter reloads its rules",
	"routing": "routing while the gateways and routes are reconfigured",
}

func init() {
	var menu = Root.Menu("system/service")
	menu.Help = "start, stop and restart services (System > Diagnostics > Services)"
	var item = Arg{Name: "item", Help: systemServiceItemHelp, Positional: true, Required: true, Complete: systemServiceItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the services with their state",
			Long: `LOCKED services are needed by the system, they can only be restarted.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every service", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only services whose id, name or description contains this text"},
			}, Run: systemServicePrint},
		&Command{Name: "show", Help: "show one service", Args: []Arg{item}, Run: systemServiceShow},
		&Command{Name: "start", Help: "start a service",
			Long: `Does nothing for a service that is running already (use restart).`,
			Args: []Arg{item}, Run: systemServiceStart},
		&Command{Name: "stop", Help: "stop a service",
			Long: `Locked services (configd, webgui, pf, routing, ...) can not be stopped, only restarted. Does nothing for a
service that is not running.`,
			ConfirmHelp: "Asks for confirmation before stopping a running service: its clients lose it until it is started again.",
			ConfirmIf:   systemServiceConfirmStop,
			Args:        []Arg{item}, Run: systemServiceStop},
		&Command{Name: "restart", Help: "restart a service (starts it when it is stopped)",
			ConfirmHelp: "Asks for confirmation before restarting webgui, configd, openssh, pf or routing: that interrupts " +
				"the management access or the traffic for a moment.",
			ConfirmIf: systemServiceConfirmRestart,
			Args:      []Arg{item}, Run: systemServiceRestart},
	)
}

// systemServiceApi returns the system API on the session's connection (used by all core menus: service,
// firmware, ha, snapshot, license)
func systemServiceApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

func systemServiceUuid(service system.CoreService) string {
	return service.Id
}

func systemServiceNames(service system.CoreService) []string {
	return []string{service.Id, service.Name}
}

// systemServiceMatches is the client side search: OPNsense ignores searchPhrase on this endpoint
func systemServiceMatches(service system.CoreService, phrase string) bool {
	phrase = strings.ToLower(phrase)
	for _, text := range []string{service.Id, service.Name, service.Description} {
		if strings.Contains(strings.ToLower(text), phrase) {
			return true
		}
	}
	return false
}

func systemServiceSelect(c *Context, api *system.SystemApi, selector string) (system.CoreService, error) {
	var services, err = api.CoreServiceList()
	if err != nil {
		return system.CoreService{}, err
	}
	return Select(c, selector, services, systemServiceUuid, systemServiceNames)
}

func systemServiceItemNames(c *Context) []string {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil
	}
	var services, listErr = api.CoreServiceList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(services))
	for _, service := range services {
		names = append(names, service.Id)
	}
	return names
}

func systemServiceState(running bool) string {
	if running {
		return "running"
	}
	return "stopped"
}

func systemServiceFields(service system.CoreService) [][2]string {
	return [][2]string{
		{"id", service.Id},
		{"name", service.Name},
		{"description", service.Description},
		{"status", systemServiceState(service.Running)},
		{"locked", YesNo(Flag(service.Locked))},
	}
}

func systemServicePrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var all, raw, listErr = api.CoreServiceListRaw()
	if listErr != nil {
		return listErr
	}
	var services []system.CoreService
	var rows []json.RawMessage
	for i, service := range all {
		if !args.Has("search") || systemServiceMatches(service, args.String("search")) {
			services = append(services, service)
			rows = append(rows, raw[i])
		}
	}

	var ids = make([]string, len(services))
	for i, service := range services {
		ids[i] = service.Id
	}
	switch {
	case args.Bool("json"):
		for _, row := range rows {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(services))
		for i, service := range services {
			items[i] = systemServiceFields(service)
		}
		c.Details(items, ids)
	default:
		var table = make([][]string, len(services))
		for i, service := range services {
			table[i] = []string{service.Id, service.Description, systemServiceState(service.Running), YesNo(Flag(service.Locked))}
		}
		c.Items([]string{"ID", "DESCRIPTION", "STATUS", "LOCKED"}, table, ids)
	}
	return nil
}

func systemServiceShow(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemServiceFields(service))
	return nil
}

func systemServiceStart(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if service.Running {
		c.Infof("service %s is running already, use restart to restart it", service.Id)
		return nil
	}
	if err := api.CoreServiceStart(service.Id); err != nil {
		return err
	}
	systemServiceVerify(c, api, service.Id, true)
	return nil
}

// systemServiceConfirmStop warns before stopping a running service; a locked one fails before the question
func systemServiceConfirmStop(c *Context, args *Args) (string, error) {
	var api, err = systemServiceApi(c)
	if err != nil {
		return "", err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return "", selectErr
	}
	if service.Locked {
		return "", systemServiceLockedError(service)
	}
	if !service.Running {
		return "", nil
	}
	return systemServiceStopWarning, nil
}

func systemServiceLockedError(service system.CoreService) error {
	return fmt.Errorf("service %s is locked (the system needs it), it can only be restarted", service.Id)
}

func systemServiceStop(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if service.Locked {
		return systemServiceLockedError(service)
	}
	if !service.Running {
		c.Infof("service %s is not running", service.Id)
		return nil
	}
	if err := api.CoreServiceStop(service.Id); err != nil {
		return err
	}
	systemServiceVerify(c, api, service.Id, false)
	return nil
}

// systemServiceConfirmRestart warns before restarting a service that carries the management access or all traffic
func systemServiceConfirmRestart(c *Context, args *Args) (string, error) {
	var api, err = systemServiceApi(c)
	if err != nil {
		return "", err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return "", selectErr
	}
	if impact, critical := systemServiceCritical[service.Name]; critical {
		return fmt.Sprintf("Restarting %s interrupts %s.", service.Id, impact), nil
	}
	return "", nil
}

func systemServiceRestart(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var service, selectErr = systemServiceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if err := api.CoreServiceRestart(service.Id); err != nil {
		return err
	}
	if _, critical := systemServiceCritical[service.Name]; !critical {
		systemServiceVerify(c, api, service.Id, true)
	}
	return nil
}

// systemServiceVerify warns when the service is not in the expected state after an action: OPNsense answers "ok"
// whatever the rc script did
func systemServiceVerify(c *Context, api *system.SystemApi, id string, running bool) {
	var service, err = api.CoreServiceGet(id)
	if err != nil {
		c.Infof("warning: could not check the state of %s: %v", id, err)
		return
	}
	if service.Running != running {
		c.Infof("warning: service %s is %s (see /log for why)", id, systemServiceState(service.Running))
	}
}
