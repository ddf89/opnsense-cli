package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var dnsmasqHostRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a Dnsmasq host override selected by --uuid or --host / --domain",
	Args:  cobra.NoArgs,
	Run:   dnsmasqHostRmRun,
}

func init() {
	dnsmasqHostSetupLookupFlags(dnsmasqHostRmCmd)
	dnsmasqHostCmd.AddCommand(dnsmasqHostRmCmd)
}

func dnsmasqHostRmRun(_ *cobra.Command, _ []string) {
	var api = newDnsmasqHostApi()

	var uuid = dnsmasqHostUuid
	if uuid == "" {
		uuid = dnsmasqHostLookup(api).Uuid
	}

	if err := api.HostRemove(uuid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted %s\n", uuid)
}
