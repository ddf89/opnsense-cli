package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var dnsmasqDomainShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a Dnsmasq domain override",
	Long:  "Select the entry with --uuid, or with --domain (plus --ip if the domain is forwarded to several servers).",
	Run:   dnsmasqDomainShowRun,
}

func init() {
	dnsmasqDomainAddLookupFlags(dnsmasqDomainShowCmd)
	dnsmasqDomainCmd.AddCommand(dnsmasqDomainShowCmd)
}

func dnsmasqDomainShowRun(_ *cobra.Command, _ []string) {
	var dnsmasqApi = dnsmasqDomainApi()
	var domainOverride = dnsmasqDomainLookup(dnsmasqApi)

	// the search row has no canonical ipset value, so always fetch the entry itself
	domainOverride, err := dnsmasqApi.DomainOverrideGet(domainOverride.Uuid)
	if err != nil {
		log.Fatal(err)
	}

	printFields([][2]string{
		{"uuid", domainOverride.Uuid},
		{"sequence", domainOverride.Sequence},
		{"domain", domainOverride.Domain},
		{"ip", domainOverride.Ip},
		{"port", domainOverride.Port},
		{"srcip", domainOverride.Srcip},
		{"ipset", domainOverride.Ipset},
		{"description", domainOverride.Description},
	})
}
