package cli

import (
	"opnsense-cli/opnsense/api/dnsmasq"
	"time"
)

// /dnsmasq/lease: the current DHCP leases (read only)

func init() {
	var menu = Root.Menu("dnsmasq/lease")
	menu.Help = "current DHCP leases"
	menu.Add(&Command{
		Name: "print",
		Help: "list the current DHCP leases",
		Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every lease"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "search", Help: "only leases where any field contains this text"},
		},
		Run: dnsmasqLeasePrint,
	})
}

func dnsmasqLeasePrint(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	raws, leases, err := dnsmasqSearch[dnsmasq.Lease](api, "leases", "search", args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return dnsmasqPrintJSON(c, raws)
	}

	// leases have no uuid, the addresses identify the printed rows
	var addresses = make([]string, len(leases))
	for i, lease := range leases {
		addresses[i] = lease.Address
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(leases))
		for i, lease := range leases {
			details[i] = [][2]string{
				{"address", lease.Address},
				{"hwaddr", lease.Hwaddr},
				{"iaid", lease.Iaid},
				{"hostname", dnsmasqLeaseOrEmpty(lease.Hostname)},
				{"client-id", dnsmasqLeaseOrEmpty(lease.ClientId)},
				{"expires", dnsmasqLeaseExpiry(lease)},
				{"interface", dnsmasqLeaseInterface(lease)},
				{"type", lease.LeaseType},
				{"vendor", lease.MacInfo},
			}
		}
		c.Details(details, addresses)
		return nil
	}

	var rows = make([][]string, len(leases))
	for i, lease := range leases {
		rows[i] = []string{lease.Address, lease.Hwaddr, dnsmasqLeaseOrEmpty(lease.Hostname), dnsmasqLeaseExpiry(lease),
			dnsmasqLeaseInterface(lease), lease.LeaseType}
	}
	c.Items([]string{"ADDRESS", "HWADDR", "HOSTNAME", "EXPIRES", "INTERFACE", "TYPE"}, rows, addresses)
	return nil
}

// dnsmasqLeaseOrEmpty maps dnsmasq's "*" placeholder (the client sent no hostname / client id) to empty
func dnsmasqLeaseOrEmpty(value string) string {
	if value == "*" {
		return ""
	}
	return value
}

// dnsmasqLeaseExpiry renders the expiry as local time, "never" for leases without expiry
func dnsmasqLeaseExpiry(lease dnsmasq.Lease) string {
	var expire, ok = lease.ExpireTime()
	if !ok {
		if lease.Expire.String() == "0" {
			return "never"
		}
		return lease.Expire.String()
	}
	return expire.Local().Format(time.DateTime)
}

// dnsmasqLeaseInterface prefers the OPNsense description (LAN) over the device name (igc1)
func dnsmasqLeaseInterface(lease dnsmasq.Lease) string {
	if lease.InterfaceDescr != "" {
		return lease.InterfaceDescr
	}
	return lease.Interface
}
