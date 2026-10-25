package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqServiceRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the dnsmasq service",
	Args:  cobra.NoArgs,
	Run:   dnsmasqServiceRestartRun,
}

func init() {
	dnsmasqServiceCmd.AddCommand(dnsmasqServiceRestartCmd)
}

func dnsmasqServiceRestartRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var err = dnsmasqApi.ServiceRestart()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service restarted")
}
