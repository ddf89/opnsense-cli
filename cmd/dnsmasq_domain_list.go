package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var dnsmasqDomainListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Dnsmasq domain overrides",
	Run:   dnsmasqDomainListRun,
}

func init() {
	dnsmasqDomainListCmd.Flags().StringVarP(&dnsmasqDomainSearch, "search", "", "", "only list entries containing this phrase in any column")
	dnsmasqDomainCmd.AddCommand(dnsmasqDomainListCmd)
}

func dnsmasqDomainListRun(_ *cobra.Command, _ []string) {
	var domainOverrides, err = dnsmasqDomainApi().DomainOverrideList(dnsmasqDomainSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(domainOverrides))
	for _, d := range domainOverrides {
		rows = append(rows, []string{d.Uuid, d.Sequence, d.Domain, d.Ip, d.Port, d.Srcip, d.Description})
	}
	printTable([]string{"UUID", "SEQ", "DOMAIN", "IP", "PORT", "SRCIP", "DESCRIPTION"}, rows)
}
