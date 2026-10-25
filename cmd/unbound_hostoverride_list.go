package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/unbound"

	"github.com/spf13/cobra"
)

var unboundHostOverrideListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all Unbound Host Override entries",
	Run:   hostEntryListRun,
}

func init() {
	unboundHostOverrideListCmd.Flags().StringVarP(&HOSTOVERRIDEsearch, "search", "", "", "only list entries where any field contains this text")

	unboundHostOverrideCmd.AddCommand(unboundHostOverrideListCmd)
}

func hostEntryListRun(_ *cobra.Command, _ []string) {
	var unboundApi = unbound.UnboundApi{OPNsense: GetOPNsenseApi()}

	var hostOverrideEntries, err = unboundApi.HostOverrideSearch(HOSTOVERRIDEsearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(hostOverrideEntries))
	for _, hostEntry := range hostOverrideEntries {
		rows = append(rows, []string{
			hostEntry.Uuid,
			hostEntry.Enabled,
			hostEntry.Host,
			hostEntry.Domain,
			hostEntry.Rr,
			hostOverrideValue(hostEntry),
			hostEntry.Ttl,
			hostEntry.Addptr,
			hostEntry.Description,
		})
	}
	printTable([]string{"UUID", "ENABLED", "HOST", "DOMAIN", "RR", "VALUE", "TTL", "PTR", "DESCRIPTION"}, rows)
}
