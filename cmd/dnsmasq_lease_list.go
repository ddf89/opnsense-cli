package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"
	"time"

	"github.com/spf13/cobra"
)

var dnsmasqLeaseListSearch string

var dnsmasqLeaseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the current DHCP leases",
	Args:  cobra.NoArgs,
	Run:   dnsmasqLeaseListRun,
}

func init() {
	dnsmasqLeaseListCmd.Flags().StringVarP(&dnsmasqLeaseListSearch, "search", "s", "", "only show leases matching this phrase (address, hwaddr, hostname, interface, ...)")
	dnsmasqLeaseCmd.AddCommand(dnsmasqLeaseListCmd)
}

func dnsmasqLeaseListRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var leases, err = dnsmasqApi.LeaseList(dnsmasqLeaseListSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(leases))
	for _, lease := range leases {
		rows = append(rows, []string{
			lease.Address,
			lease.Hwaddr,
			dnsmasqLeaseOrEmpty(lease.Hostname),
			dnsmasqLeaseExpiry(lease),
			dnsmasqLeaseInterface(lease),
			lease.LeaseType,
		})
	}
	printTable([]string{"ADDRESS", "HWADDR", "HOSTNAME", "EXPIRES", "INTERFACE", "TYPE"}, rows)
}

// dnsmasqLeaseOrEmpty maps dnsmasq's "*" placeholder (no hostname sent) to empty
func dnsmasqLeaseOrEmpty(value string) string {
	if value == "*" {
		return ""
	}
	return value
}

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

func dnsmasqLeaseInterface(lease dnsmasq.Lease) string {
	if lease.InterfaceDescr != "" {
		return lease.InterfaceDescr
	}
	return lease.Interface
}
