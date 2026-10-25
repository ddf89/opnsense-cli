package cmd

import (
	"opnsense-cli/opnsense/api/diagnostics"

	"github.com/spf13/cobra"
)

var diagFirewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Firewall log: tail, follow, filter choices and statistics",
}

func init() {
	diagCmd.AddCommand(diagFirewallCmd)
}

func newDiagFirewallApi() *diagnostics.DiagnosticsApi {
	return &diagnostics.DiagnosticsApi{OPNsense: GetOPNsenseApi()}
}
