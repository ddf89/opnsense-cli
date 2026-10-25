package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var dnsmasqDomainRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a Dnsmasq domain override",
	Long:  "Select the entry with --uuid, or with --domain (plus --ip if the domain is forwarded to several servers).",
	Run:   dnsmasqDomainRmRun,
}

func init() {
	dnsmasqDomainAddLookupFlags(dnsmasqDomainRmCmd)
	dnsmasqDomainCmd.AddCommand(dnsmasqDomainRmCmd)
}

func dnsmasqDomainRmRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasqDomainApi()
	var domainOverride = dnsmasqDomainLookup(dnsmasqApi)

	if err := dnsmasqApi.DomainOverrideRemove(domainOverride.Uuid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted successfully, uuid: %s\n", domainOverride.Uuid)
}
