package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/unbound"

	"github.com/spf13/cobra"
)

var unboundHostOverrideRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a Unbound host override entry",
	Run:   hostEntryRmRun,
}

func init() {
	unboundHostOverrideRmCmd.Flags().StringVarP(&HOSTOVERRIDEhost, "host", "", "", "lookup entry by host / domain: the host part")
	unboundHostOverrideRmCmd.Flags().StringVarP(&HOSTOVERRIDEdomain, "domain", "", "", "lookup entry by host / domain: the domain part")
	unboundHostOverrideRmCmd.Flags().StringVarP(&HOSTOVERRIDEfilterRr, "rr", "", "", "lookup entry by host / domain: only entries of this record type, needed if the FQDN has several records")
	unboundHostOverrideRmCmd.Flags().StringVarP(&HOSTOVERRIDEuuid, "uuid", "", "", "delete by uuid explicitly")

	unboundHostOverrideCmd.AddCommand(unboundHostOverrideRmCmd)
}

func hostEntryRmRun(_ *cobra.Command, _ []string) {
	var unboundApi = unbound.UnboundApi{OPNsense: GetOPNsenseApi()}

	if HOSTOVERRIDEuuid == "" && (HOSTOVERRIDEhost == "" || HOSTOVERRIDEdomain == "") {
		log.Fatal("Please either set host and domain or set uuid")
	}

	if HOSTOVERRIDEuuid == "" {
		var entry, err = unboundApi.HostOverrideGetByFQDNAndRr(HOSTOVERRIDEhost, HOSTOVERRIDEdomain, HOSTOVERRIDEfilterRr)
		if err != nil {
			log.Fatal(hostOverrideLookupError(err))
		}
		HOSTOVERRIDEuuid = entry.Uuid
		log.Printf("Found Uuid %s for FQDN %s.%s", HOSTOVERRIDEuuid, HOSTOVERRIDEhost, HOSTOVERRIDEdomain)
	}

	var err = unboundApi.HostEntryRemove(HOSTOVERRIDEuuid)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted successfully, uuid: %s\n", HOSTOVERRIDEuuid)
}
