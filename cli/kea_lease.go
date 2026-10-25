package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"opnsense-cli/opnsense/api/dhcp"
)

// /kea/dhcp4/lease and /kea/dhcp6/lease: the leases of the running Kea servers. Leases have no uuid, the address
// identifies them (also as # of print)

func init() {
	for _, version := range []int{4, 6} {
		var menu = Root.Menu(fmt.Sprintf("kea/dhcp%d/lease", version))
		menu.Help = fmt.Sprintf("the leases of the Kea DHCPv%d server (Services > Kea DHCP > Leases DHCPv%d)", version, version)
		menu.Add(
			&Command{Name: "print", Help: "list the current leases",
				Long: `Only a running Kea server has leases. interface= keeps the leases of one interface, given by its key (lan),
description (LAN) or device (vtnet0).`,
				Args: []Arg{
					{Name: "detail", Type: Bool, Help: "show all fields of every lease"},
					{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
					{Name: "search", Help: "only leases where any field contains this text"},
					{Name: "interface", Help: "only leases of this interface (key, description or device)"},
				},
				Run: keaLeasePrint(version)},
			&Command{Name: "remove", Help: "delete a lease from the running server, the client gets a new one on its next request",
				Args: []Arg{{Name: "item", Help: "the # of print or the address of the lease", Positional: true, Required: true,
					Validate: keaValidateLeaseSelector(version)}},
				Run: keaLeaseRemove(version)},
		)
	}
}

// keaValidateLeaseSelector accepts a # of print or an address of the version
func keaValidateLeaseSelector(version int) func(string) error {
	return func(value string) error {
		if strings.Trim(value, "0123456789") == "" {
			return nil
		}
		return keaValidateAddress(version)(value)
	}
}

// keaLeaseFilter keeps the leases of an interface given by key, description or device
func keaLeaseFilter(leases []dhcp.KeaLease, raws []json.RawMessage, iface string) ([]dhcp.KeaLease, []json.RawMessage) {
	if iface == "" {
		return leases, raws
	}
	var keptLeases []dhcp.KeaLease
	var keptRaws []json.RawMessage
	for i, lease := range leases {
		for _, name := range []dhcp.Text{lease.InterfaceName, lease.InterfaceDescr, lease.Interface} {
			if name != "" && strings.EqualFold(string(name), iface) {
				keptLeases = append(keptLeases, lease)
				keptRaws = append(keptRaws, raws[i])
				break
			}
		}
	}
	return keptLeases, keptRaws
}

func keaLeaseExpiry(lease dhcp.KeaLease) string {
	if expire, ok := lease.ExpireTime(); ok {
		return expire.Local().Format(time.DateTime)
	}
	return "never"
}

func keaLeaseInterface(lease dhcp.KeaLease) string {
	if lease.InterfaceName != "" {
		return string(lease.InterfaceName)
	}
	return string(lease.Interface)
}

func keaLeaseClient(version int, lease dhcp.KeaLease) string {
	if version == 6 && lease.Duid != "" {
		return string(lease.Duid)
	}
	if lease.Hwaddr != "" {
		return string(lease.Hwaddr)
	}
	return string(lease.ClientId)
}

func keaLeaseAddress(version int, lease dhcp.KeaLease) string {
	if version == 6 && lease.Type == "IA_PD" && lease.PrefixLen != "" {
		return lease.Address + "/" + string(lease.PrefixLen)
	}
	return lease.Address
}

func keaLeasePrint(version int) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var dhcpApi, err = keaApi(c)
		if err != nil {
			return err
		}
		var leases, raws, leasesErr = dhcpApi.KeaLeases(version, args.String("search"))
		if leasesErr != nil {
			return leasesErr
		}
		leases, raws = keaLeaseFilter(leases, raws, strings.TrimSpace(args.String("interface")))
		if args.Bool("json") {
			for _, raw := range raws {
				c.Println(string(raw))
			}
			return nil
		}
		var addresses = make([]string, len(leases))
		for i, lease := range leases {
			addresses[i] = lease.Address
		}
		if args.Bool("detail") {
			var details = make([][][2]string, len(leases))
			for i, lease := range leases {
				details[i] = [][2]string{
					{"address", keaLeaseAddress(version, lease)},
					{"type", string(lease.Type)},
					{"hwaddr", string(lease.Hwaddr)},
					{"duid", string(lease.Duid)},
					{"client-id", string(lease.ClientId)},
					{"iaid", string(lease.Iaid)},
					{"hostname", string(lease.Hostname)},
					{"state", lease.StateText()},
					{"valid-lifetime", string(lease.ValidLifetime)},
					{"expires", keaLeaseExpiry(lease)},
					{"interface", keaLeaseInterface(lease)},
					{"interface-description", string(lease.InterfaceDescr)},
					{"lease-type", string(lease.LeaseType)},
					{"vendor", string(lease.MacInfo)},
				}
			}
			c.Details(details, addresses)
			return nil
		}
		var rows = make([][]string, len(leases))
		for i, lease := range leases {
			rows[i] = []string{keaLeaseAddress(version, lease), keaLeaseClient(version, lease), string(lease.Hostname),
				keaLeaseExpiry(lease), lease.StateText(), keaLeaseInterface(lease), string(lease.LeaseType)}
		}
		var client = "MAC/CLIENT-ID"
		if version == 6 {
			client = "DUID"
		}
		c.Items([]string{"ADDRESS", client, "HOSTNAME", "EXPIRES", "STATE", "INTERFACE", "TYPE"}, rows, addresses)
		return nil
	}
}

func keaLeaseRemove(version int) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var dhcpApi, err = keaApi(c)
		if err != nil {
			return err
		}
		var selector = strings.TrimSpace(args.String("item"))
		var address = selector
		if keaValidateAddress(version)(selector) != nil || selector == "" {
			// a # of print: resolve it with the current leases (the address is the item's uuid)
			var leases, _, leasesErr = dhcpApi.KeaLeases(version, "")
			if leasesErr != nil {
				return leasesErr
			}
			var lease, selectErr = Select(c, selector, leases,
				func(lease dhcp.KeaLease) string { return lease.Address },
				func(lease dhcp.KeaLease) []string { return []string{lease.Address} })
			if selectErr != nil {
				return selectErr
			}
			address = lease.Address
		}
		return dhcpApi.KeaLeaseRemove(version, address)
	}
}
