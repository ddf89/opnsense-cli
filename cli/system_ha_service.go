package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/system"
)

// /system/ha/service: the services of the backup node (System > High Availability > Status). Every action first
// pushes the configuration to the backup node (like the web UI), so all of them ask for confirmation. Items are
// selected by the # of print, the uid (name or name_instance) or the name

const systemHaServiceWarning = "This pushes the configuration of the selected sync items to the backup node first."

func init() {
	var menu = Root.Menu("system/ha/service")
	menu.Help = "services of the backup node (System > High Availability > Status)"
	var item = Arg{Name: "item", Help: "the #, uid (name or name_instance) or name of the service", Positional: true, Required: true,
		Complete: systemHaServiceItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the services of the backup node",
			Long: `Empty when no backup node is configured (/system/ha set synchronize-to-ip=…) or it does not answer.`,
			Args: []Arg{
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			},
			Run: systemHaServicePrint},
		&Command{Name: "start", Help: "sync the configuration and start a service on the backup node", Args: []Arg{item},
			Confirm: systemHaServiceWarning + " Then it starts the service there.", Run: systemHaServiceAction("start")},
		&Command{Name: "stop", Help: "sync the configuration and stop a service on the backup node", Args: []Arg{item},
			Confirm: systemHaServiceWarning + " Then it stops the service there.", Run: systemHaServiceAction("stop")},
		&Command{Name: "restart", Help: "sync the configuration and restart a service on the backup node", Args: []Arg{item},
			Confirm: systemHaServiceWarning + " Then it restarts the service there.", Run: systemHaServiceAction("restart")},
	)
}

func systemHaServiceUid(service system.HaRemoteService) string {
	return service.Uid
}

func systemHaServiceNames(service system.HaRemoteService) []string {
	return []string{service.Uid, service.Name}
}

func systemHaServiceItemNames(c *Context) []string {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil
	}
	var services, _, listErr = api.HaRemoteServiceListRaw()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(services))
	for _, service := range services {
		names = append(names, service.Uid)
	}
	return names
}

func systemHaServicePrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var services, raw, listErr = api.HaRemoteServiceListRaw()
	if listErr != nil {
		return listErr
	}
	if len(services) == 0 {
		c.Infof(`no services: no backup node is configured or it does not answer (see "/system/ha status")`)
	}
	if args.Bool("json") {
		for _, row := range raw {
			c.Println(string(row))
		}
		return nil
	}
	var rows = make([][]string, len(services))
	var uids = make([]string, len(services))
	for i, service := range services {
		rows[i] = []string{service.Uid, service.Description, systemServiceState(service.Running), YesNo(Flag(service.NoCheck))}
		uids[i] = service.Uid
	}
	c.Items([]string{"UID", "DESCRIPTION", "STATUS", "LOCKED"}, rows, uids)
	return nil
}

func systemHaServiceAction(action string) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = systemServiceApi(c)
		if err != nil {
			return err
		}
		var services, _, listErr = api.HaRemoteServiceListRaw()
		if listErr != nil {
			return listErr
		}
		var service, selectErr = Select(c, args.String("item"), services, systemHaServiceUid, systemHaServiceNames)
		if selectErr != nil {
			return selectErr
		}
		if action == "stop" && service.NoCheck {
			return fmt.Errorf("service %s of the backup node is locked, it can only be restarted", service.Uid)
		}
		return api.HaRemoteServiceAction(action, service.Name, service.Id)
	}
}
