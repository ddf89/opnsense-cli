package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqServiceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the dnsmasq service",
	Args:  cobra.NoArgs,
	Run:   dnsmasqServiceStopRun,
}

func init() {
	dnsmasqServiceCmd.AddCommand(dnsmasqServiceStopCmd)
}

func dnsmasqServiceStopRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var err = dnsmasqApi.ServiceStop()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service stopped")
}
