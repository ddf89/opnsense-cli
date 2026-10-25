package cmd

import (
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var powerCmd = &cobra.Command{
	Use:   "power",
	Short: "Reboot or power off the firewall (Power menu, needs --yes)",
}

func init() {
	RootCmd.AddCommand(powerCmd)
}

func powerApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}
