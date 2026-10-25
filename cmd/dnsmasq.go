package cmd

import (
	"github.com/spf13/cobra"
)

var dnsmasqCmd = &cobra.Command{
	Use:   "dnsmasq",
	Short: "Manage Dnsmasq DNS & DHCP using the OPNsense API",
}

func init() {
	RootCmd.AddCommand(dnsmasqCmd)
}
