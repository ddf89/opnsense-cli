package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqServiceReconfigureCmd = &cobra.Command{
	Use:   "reconfigure",
	Short: "Apply the saved dnsmasq configuration (regenerate config and reload the service)",
	Args:  cobra.NoArgs,
	Run:   dnsmasqServiceReconfigureRun,
}

func init() {
	dnsmasqServiceCmd.AddCommand(dnsmasqServiceReconfigureCmd)
}

func dnsmasqServiceReconfigureRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}

	var err = dnsmasqApi.ServiceReconfigure()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Service reconfigured")
}
