package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/overview: Interfaces > Overview (api/interfaces/overview): the state of every network device with
// its assignment, the details and statistics of one device, and the Reload button. /interface/assignment: a
// read-only list of Interfaces > Assignments (changing assignments remotely can cut off the access, so it is not
// offered)

const interfaceOverviewItemHelp = "the #, device (vtnet0), identifier (lan, opt1) or description of the interface"

func init() {
	var menu = Root.Menu("interface/overview")
	menu.Help = "state, addresses and statistics of all network devices (Interfaces > Overview)"
	var item = Arg{Name: "item", Help: interfaceOverviewItemHelp, Positional: true, Required: true, Complete: interfaceOverviewComplete}
	menu.Add(
		&Command{Name: "print", Help: "list the network devices with their state and addresses",
			Long: `IDENTIFIER is the assignment (lan, wan, opt1), "-" for unassigned devices. IPV6 leaves out the link-local
addresses, detail shows them and more (link types, gateways, routes, flags).`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show more fields of every device"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only devices where the device, description, status, addresses, gateways or routes contain this text"},
			}, Run: interfaceOverviewPrint},
		&Command{Name: "show", Help: "show all details and statistics of one device",
			Args: []Arg{item, {Name: "json", Type: Bool, Help: "print the details as one JSON object with the API names"}},
			Run:  interfaceOverviewShow},
		&Command{Name: "reload", Help: "reconfigure an assigned interface like the Reload button of the overview",
			Long: `Applies the configuration of the interface again: its addresses are set again and its DHCP / PPP clients
are restarted. Traffic on the interface is interrupted, and on the interface you reach the firewall through the
access can be lost (e.g. when a DHCP lease is not renewed).`,
			Confirm: "This reconfigures the interface: its addresses are applied again and DHCP/PPP clients restarted, traffic on it is interrupted and access through it can be lost.",
			Args:    []Arg{item}, Run: interfaceOverviewReload},
	)

	var assignment = Root.Menu("interface/assignment")
	assignment.Help = "the interface assignments, read only (Interfaces > Assignments)"
	assignment.Add(
		&Command{Name: "print", Help: "list the assigned interfaces with their devices",
			Long: `Read only: changing assignments remotely can cut off the access to the firewall, use the GUI for it.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every assignment"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			}, Run: interfaceAssignmentPrint},
	)
}

// --- lookups

func interfaceOverviewDevice(i interfaces.OverviewInterface) string {
	return i.Device
}

func interfaceOverviewNames(i interfaces.OverviewInterface) []string {
	return []string{i.Identifier, i.Description}
}

func interfaceOverviewSelect(c *Context, api *interfaces.InterfacesApi, selector string) (interfaces.OverviewInterface, error) {
	var list, err = api.Overview("")
	if err != nil {
		return interfaces.OverviewInterface{}, err
	}
	return Select(c, selector, list, interfaceOverviewDevice, interfaceOverviewNames)
}

func interfaceOverviewComplete(c *Context) []string {
	var api, err = interfaceApi(c)
	if err != nil {
		return nil
	}
	var list, listErr = api.Overview("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, entry := range list {
		names = append(names, entry.Device)
		if entry.Identifier != "" {
			names = append(names, entry.Identifier)
		}
	}
	return names
}

// --- print

func interfaceOverviewAddresses(addresses []interfaces.OverviewAddress, linkLocal bool) string {
	var texts []string
	for _, address := range addresses {
		if !linkLocal && strings.HasPrefix(strings.ToLower(address.Address), "fe80:") {
			continue
		}
		var text = address.Address
		if address.Vhid != "" {
			text += fmt.Sprintf(" (vhid %s %s)", address.Vhid, address.Status)
			text = strings.Replace(text, " )", ")", 1)
		}
		texts = append(texts, text)
	}
	return strings.Join(texts, ", ")
}

func interfaceOverviewDetail(i interfaces.OverviewInterface) [][2]string {
	var enabled = ""
	if i.Identifier != "" {
		enabled = YesNo(Flag(i.Enabled))
	}
	return [][2]string{
		{"device", i.Device},
		{"identifier", i.Identifier},
		{"description", i.Description},
		{"status", i.Status},
		{"enabled", enabled},
		{"link-type", i.LinkType},
		{"link-type-v6", i.LinkTypeV6},
		{"ipv4", interfaceOverviewAddresses(i.IPv4, true)},
		{"ipv6", interfaceOverviewAddresses(i.IPv6, true)},
		{"gateways", strings.Join(i.Gateways, ", ")},
		{"routes", strings.Join(i.Routes, ", ")},
		{"vlan-tag", string(i.VlanTag)},
		{"mac-address", i.MacAddr},
		{"mtu", string(i.Mtu)},
		{"media", i.Media},
		{"physical", YesNo(Flag(i.IsPhysical))},
		{"flags", strings.Join(i.Flags, ",")},
		{"groups", strings.Join(i.Groups, ",")},
	}
}

func interfaceOverviewPrint(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Overview(args.String("search"))
	if listErr != nil {
		return listErr
	}
	var devices = make([]string, len(list))
	for i, entry := range list {
		devices[i] = entry.Device
	}
	switch {
	case args.Bool("json"):
		for _, entry := range list {
			if err := c.JSON(entry.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(list))
		for i, entry := range list {
			blocks[i] = interfaceOverviewDetail(entry)
		}
		c.Details(blocks, devices)
	default:
		var rows = make([][]string, len(list))
		for i, entry := range list {
			rows[i] = []string{entry.Device, entry.Identifier, entry.Description, entry.Status,
				interfaceOverviewAddresses(entry.IPv4, true), interfaceOverviewAddresses(entry.IPv6, false), entry.MacAddr}
		}
		c.Items([]string{"DEVICE", "IDENTIFIER", "DESCRIPTION", "STATUS", "IPV4", "IPV6", "MAC-ADDRESS"}, rows, devices)
	}
	return nil
}

// --- show

// interfaceOverviewKey turns an API name like "packets received" into packets-received
func interfaceOverviewKey(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), " ", "-"), "_", "-")
}

// interfaceOverviewValue renders a JSON value: lists comma separated, objects as key=value, addresses first
func interfaceOverviewValue(raw json.RawMessage) string {
	var decoded any
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return interfaceOverviewText(decoded)
}

func interfaceOverviewText(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return YesNo(Flag(typed))
	case json.Number:
		return typed.String()
	case []any:
		var texts = make([]string, 0, len(typed))
		for _, element := range typed {
			texts = append(texts, interfaceOverviewText(element))
		}
		return strings.Join(texts, ", ")
	case map[string]any:
		var keys = make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var parts []string
		if address, isText := typed["ipaddr"].(string); isText {
			parts = append(parts, address)
		}
		for _, key := range keys {
			if key == "ipaddr" {
				continue
			}
			if text := interfaceOverviewText(typed[key]); text != "" {
				parts = append(parts, key+"="+text)
			}
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprint(value)
}

func interfaceOverviewShow(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var selected, selectErr = interfaceOverviewSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var detail, getErr = api.OverviewGet(selected.Device)
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		// one object in API order
		var line bytes.Buffer
		line.WriteByte('{')
		for i, entry := range detail.Entries {
			if i > 0 {
				line.WriteByte(',')
			}
			var key, _ = json.Marshal(entry.Key)
			line.Write(key)
			line.WriteByte(':')
			var compact bytes.Buffer
			if json.Compact(&compact, entry.Value) != nil {
				compact.Reset()
				compact.WriteString("null")
			}
			line.Write(compact.Bytes())
		}
		line.WriteByte('}')
		c.Println(line.String())
		return nil
	}
	var fields = make([][2]string, 0, len(detail.Entries))
	for _, entry := range detail.Entries {
		fields = append(fields, [2]string{interfaceOverviewKey(entry.Key), interfaceOverviewValue(entry.Value)})
	}
	c.Fields(fields)
	return nil
}

// --- reload

func interfaceOverviewReload(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var selected, selectErr = interfaceOverviewSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if selected.Identifier == "" {
		return fmt.Errorf("device %s is not assigned to an interface, only assigned interfaces can be reloaded", selected.Device)
	}
	var _, reloadErr = api.OverviewReload(selected.Identifier)
	if reloadErr != nil {
		return fmt.Errorf("reload of %s: %w", selected.Identifier, reloadErr)
	}
	return nil
}

// --- assignment

func interfaceAssignmentPrint(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var assignments, listErr = api.Assignments()
	if listErr != nil {
		return listErr
	}
	var identifiers = make([]string, len(assignments))
	for i, assignment := range assignments {
		identifiers[i] = assignment.Identifier
	}
	switch {
	case args.Bool("json"):
		for _, assignment := range assignments {
			if err := c.JSON(assignment.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(assignments))
		for i, assignment := range assignments {
			blocks[i] = [][2]string{
				{"identifier", assignment.Identifier},
				{"description", assignment.Description},
				{"device", assignment.Device},
				{"device-info", assignment.DeviceText},
				{"group", assignment.Group},
				{"locked", YesNo(Flag(assignment.Locked))},
			}
		}
		c.Details(blocks, identifiers)
	default:
		var rows = make([][]string, len(assignments))
		for i, assignment := range assignments {
			rows[i] = []string{assignment.Identifier, assignment.Description, assignment.Device, YesNo(Flag(assignment.Locked))}
		}
		c.Items([]string{"IDENTIFIER", "DESCRIPTION", "DEVICE", "LOCKED"}, rows, identifiers)
	}
	return nil
}
