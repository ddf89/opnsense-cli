package cmd

import (
	"github.com/spf13/cobra"
)

var dnsmasqServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the Dnsmasq service",
}

func init() {
	dnsmasqCmd.AddCommand(dnsmasqServiceCmd)
}
