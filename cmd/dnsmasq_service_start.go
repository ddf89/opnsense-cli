package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqServiceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the dnsmasq service",
	Args:  cobra.NoArgs,
	Run:   dnsmasqServiceStartRun,
}

func init() {
	dnsmasqServiceCmd.AddCommand(dnsmasqServiceStartCmd)
}

func dnsmasqServiceStartRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var err = dnsmasqApi.ServiceStart()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service started")
}
