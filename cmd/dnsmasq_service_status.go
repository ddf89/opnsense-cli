package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqServiceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Status of the dnsmasq service (running, stopped, disabled)",
	Args:  cobra.NoArgs,
	Run:   dnsmasqServiceStatusRun,
}

func init() {
	dnsmasqServiceCmd.AddCommand(dnsmasqServiceStatusCmd)
}

func dnsmasqServiceStatusRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var status, err = dnsmasqApi.ServiceStatus()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service status: %s", status)
}
