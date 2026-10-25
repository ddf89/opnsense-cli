package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
	"time"
)

// /interface/arp and /interface/ndp: Interfaces > Diagnostics > ARP Table / NDP Table
// (api/diagnostics/interface/get_arp, flush_arp, get_ndp)

func init() {
	var arp = Root.Menu("interface/arp")
	arp.Help = "the ARP table of the firewall (IPv4 neighbors)"
	arp.Add(
		&Command{
			Name: "print",
			Help: "list the ARP table",
			Long: `Lists the IPv4 neighbors the firewall knows (incomplete entries are left out). Host names come from the
DHCP leases, with resolve also from reverse DNS (slower). EXPIRES is the time until the entry is dropped.`,
			Args: []Arg{
				{Name: "interface", Type: List, Help: "only entries of these interfaces (description like LAN, or device like vtnet0)"},
				{Name: "search", Help: "only entries whose address, MAC, host name, manufacturer or interface contains this text"},
				{Name: "resolve", Type: Bool, Help: "look up host names by reverse DNS"},
				{Name: "detail", Type: Bool, Help: "show all fields of every entry"},
				{Name: "json", Type: Bool, Help: "print the raw entries as JSON, one object per line"},
			},
			Run: interfaceDiagArpPrint,
		},
		&Command{
			Name:    "flush",
			Help:    "delete all entries of the ARP table",
			Long:    `Runs "arp -da" on the firewall. The entries are learned again from the next packets.`,
			Confirm: "This deletes every entry of the ARP table of the firewall; until the neighbors are learned again traffic to them can stall briefly.",
			Run:     interfaceDiagArpFlush,
		},
	)

	var ndp = Root.Menu("interface/ndp")
	ndp.Help = "the NDP table of the firewall (IPv6 neighbors)"
	ndp.Add(&Command{
		Name: "print",
		Help: "list the NDP table",
		Args: []Arg{
			{Name: "interface", Type: List, Help: "only entries of these interfaces (description like LAN, or device like vtnet0)"},
			{Name: "search", Help: "only entries whose address, MAC, manufacturer or interface contains this text"},
			{Name: "json", Type: Bool, Help: "print the raw entries as JSON, one object per line"},
		},
		Run: interfaceDiagNdpPrint,
	})
}

// interfaceDiagMatches tells whether an entry passes the interface filter (names, empty for all) and the search
// text (case-insensitive, "" for all)
func interfaceDiagMatches(names []string, search string, device string, description string, texts ...string) bool {
	if len(names) > 0 {
		var found = false
		for _, name := range names {
			if strings.EqualFold(name, device) || strings.EqualFold(name, description) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	search = strings.ToLower(search)
	if search == "" {
		return true
	}
	for _, text := range append(texts, device, description) {
		if strings.Contains(strings.ToLower(text), search) {
			return true
		}
	}
	return false
}

// interfaceDiagInterface renders the interface of an entry: the description with the device, e.g. "LAN (vtnet0)"
func interfaceDiagInterface(device string, description string) string {
	if description == "" || strings.EqualFold(description, device) {
		return device
	}
	return fmt.Sprintf("%s (%s)", description, device)
}

func interfaceDiagArpExpires(entry diagnostics.ArpEntry) string {
	switch {
	case entry.Permanent:
		return "permanent"
	case entry.Expired:
		return "expired"
	case entry.Expires < 0:
		return ""
	}
	return (time.Duration(entry.Expires) * time.Second).String()
}

func interfaceDiagArpPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	entries, err := api.ArpList(args.Bool("resolve"))
	if err != nil {
		return err
	}
	var selected []diagnostics.ArpEntry
	var ids []string
	for _, entry := range entries {
		if interfaceDiagMatches(args.List("interface"), args.String("search"), entry.Interface, entry.InterfaceDescription, entry.Ip, entry.Mac, entry.Hostname, entry.Manufacturer) {
			selected = append(selected, entry)
			ids = append(ids, entry.Ip)
		}
	}
	switch {
	case args.Bool("json"):
		for _, entry := range selected {
			if err := c.JSON(entry.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(selected))
		for _, entry := range selected {
			items = append(items, [][2]string{
				{"address", entry.Ip}, {"mac-address", entry.Mac}, {"interface", entry.InterfaceDescription},
				{"device", entry.Interface}, {"hostname", entry.Hostname}, {"manufacturer", entry.Manufacturer},
				{"type", entry.Type}, {"permanent", YesNo(Flag(entry.Permanent))}, {"expired", YesNo(Flag(entry.Expired))},
				{"expires", interfaceDiagArpExpires(entry)},
			})
		}
		c.Details(items, ids)
	default:
		var rows = make([][]string, 0, len(selected))
		for _, entry := range selected {
			rows = append(rows, []string{
				entry.Ip, entry.Mac, interfaceDiagInterface(entry.Interface, entry.InterfaceDescription),
				entry.Hostname, entry.Manufacturer, interfaceDiagArpExpires(entry),
			})
		}
		c.Items([]string{"ADDRESS", "MAC-ADDRESS", "INTERFACE", "HOSTNAME", "MANUFACTURER", "EXPIRES"}, rows, ids)
	}
	return nil
}

func interfaceDiagArpFlush(c *Context, _ *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	deleted, err := api.ArpFlush()
	if err != nil {
		return err
	}
	c.Infof("deleted %d ARP entries", len(deleted))
	return nil
}

func interfaceDiagNdpPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	entries, err := api.NdpList()
	if err != nil {
		return err
	}
	var rows [][]string
	var ids []string
	for _, entry := range entries {
		if !interfaceDiagMatches(args.List("interface"), args.String("search"), entry.Interface, entry.InterfaceDescription, entry.Ip, entry.Mac, entry.Manufacturer) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(entry.Raw); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{entry.Ip, entry.Mac, interfaceDiagInterface(entry.Interface, entry.InterfaceDescription), entry.Manufacturer})
		ids = append(ids, entry.Ip)
	}
	if !args.Bool("json") {
		c.Items([]string{"ADDRESS", "MAC-ADDRESS", "INTERFACE", "MANUFACTURER"}, rows, ids)
	}
	return nil
}
