package cmd

import (
	"github.com/spf13/cobra"
)

var dnsmasqLeaseCmd = &cobra.Command{
	Use:     "leases",
	Aliases: []string{"lease"},
	Short:   "Show Dnsmasq DHCP leases",
}

func init() {
	dnsmasqCmd.AddCommand(dnsmasqLeaseCmd)
}
