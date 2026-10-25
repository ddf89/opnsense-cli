package cmd

import (
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemDefaultsCmd = &cobra.Command{
	Use:   "defaults",
	Short: "Factory defaults (System > Configuration > Defaults)",
}

func init() {
	systemCmd.AddCommand(systemDefaultsCmd)
}

func systemDefaultsApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}
