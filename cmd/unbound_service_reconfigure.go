package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"opnsense-cli/opnsense/api/unbound"
)

var unboundReconfigureCmd = &cobra.Command{
	Use:   "reconfigure",
	Short: "Reconfigure the unbound server",
	Run:   unboundReconfigureRun,
}

func init() {
	unboundServiceCmd.AddCommand(unboundReconfigureCmd)
}

func unboundReconfigureRun(_ *cobra.Command, _ []string) {
	var unboundApi = unbound.UnboundApi{OPNsense: GetOPNsenseApi()}

	var err = unboundApi.ServiceReconfigure()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service reconfigured")
}
