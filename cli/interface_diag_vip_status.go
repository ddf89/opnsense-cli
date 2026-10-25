package cli

import (
	"strings"
)

// /interface/vip-status: Interfaces > Virtual IPs > Status (api/diagnostics/interface/get_vip_status,
// carp_status/<action>, get_pfsync_nodes): the CARP state of the virtual IPs and of this node

func init() {
	var menu = Root.Menu("interface/vip-status")
	menu.Help = "CARP state of the virtual IPs and of this node"
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the virtual IPs with a vhid (CARP and IP aliases on a vhid) and their CARP state",
			Long: `STATUS is MASTER, BACKUP, INIT, or DISABLED for configured virtual IPs that are not active.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw entries as JSON, one object per line"}},
			Run:  interfaceDiagVipStatusPrint,
		},
		&Command{
			Name: "status",
			Help: "show the CARP state of this node: enabled, maintenance mode, demotion",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw CARP state as one JSON object"}},
			Run:  interfaceDiagVipStatusStatus,
		},
		&Command{
			Name: "maintenance",
			Help: "enter or leave the persistent CARP maintenance mode",
			Long: `Entering demotes this node (net.inet.carp.demotion 240) so the CARP peer becomes MASTER of all virtual
IPs, also after a reboot; leaving restores the demotion. Both save the configuration. Nothing is sent when
the node already is in the requested mode.`,
			Args:    []Arg{{Name: "mode", Positional: true, Required: true, Values: []string{"enter", "leave"}, Help: "enter or leave"}},
			Confirm: "This changes the CARP maintenance mode of this node: entering hands MASTER of all CARP virtual IPs to the peer, leaving can take it back.",
			Run:     interfaceDiagVipStatusMaintenance,
		},
		&Command{
			Name:    "enable",
			Help:    "enable CARP on this node and configure its virtual IPs again",
			Confirm: "This enables CARP on this node: pfsync and all virtual IPs with a vhid are configured again and the node can become MASTER.",
			Run:     interfaceDiagVipStatusAction("enable"),
		},
		&Command{
			Name:    "disable",
			Help:    "disable CARP on this node until enabled again (not saved)",
			Long:    `Sets net.inet.carp.allow=0 and takes all virtual IPs with a vhid down until enable (or a reboot).`,
			Confirm: "This disables CARP on this node: all virtual IPs with a vhid go down and the CARP peer takes over.",
			Run:     interfaceDiagVipStatusAction("disable"),
		},
		&Command{
			Name: "pfsync-nodes",
			Help: "list the pfsync nodes the states come from by their host id",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw nodes as JSON, one object per line"}},
			Run:  interfaceDiagVipStatusPfsyncNodes,
		},
	)
}

func interfaceDiagVipStatusPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	entries, _, _, err := api.VipStatusGet()
	if err != nil {
		return err
	}
	var rows [][]string
	var ids []string
	for _, entry := range entries {
		if args.Bool("json") {
			if err := c.JSON(entry.Raw); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{entry.Interface, string(entry.Vhid), entry.Subnet, entry.Mode, entry.Status,
			string(entry.AdvBase), string(entry.AdvSkew)})
		ids = append(ids, string(entry.Vhid)+"/"+entry.Subnet)
	}
	if !args.Bool("json") {
		c.Items([]string{"INTERFACE", "VHID", "ADDRESS", "MODE", "STATUS", "ADVBASE", "ADVSKEW"}, rows, ids)
	}
	return nil
}

func interfaceDiagVipStatusStatus(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	_, status, _, err := api.VipStatusGet()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(status)
	}
	var fields = [][2]string{
		{"carp", EnabledWord(status.Enabled())},
		{"maintenance-mode", YesNo(Flag(status.MaintenanceMode))},
		{"demotion", string(status.Demotion)},
	}
	if status.Message != "" {
		fields = append(fields, [2]string{"message", status.Message})
	}
	c.Fields(fields)
	return nil
}

func interfaceDiagVipStatusMaintenance(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	_, status, _, err := api.VipStatusGet()
	if err != nil {
		return err
	}
	var enter = strings.EqualFold(args.String("mode"), "enter")
	if status.MaintenanceMode == enter {
		if enter {
			c.Infof("this node already is in CARP maintenance mode")
		} else {
			c.Infof("this node is not in CARP maintenance mode")
		}
		return nil
	}
	// the API toggles the mode
	_, err = api.CarpSetStatus("maintenance")
	return err
}

func interfaceDiagVipStatusAction(action string) func(c *Context, args *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = ifaceDiagnostics(c)
		if err != nil {
			return err
		}
		_, err = api.CarpSetStatus(action)
		return err
	}
}

func interfaceDiagVipStatusPfsyncNodes(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	nodes, err := api.PfsyncNodes()
	if err != nil {
		return err
	}
	var rows [][]string
	for _, node := range nodes {
		if args.Bool("json") {
			if err := c.JSON(node); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{node.CreatorId, YesNo(Flag(node.IsThis()))})
	}
	if !args.Bool("json") {
		c.Table([]string{"CREATOR-ID", "THIS-NODE"}, rows)
	}
	return nil
}
