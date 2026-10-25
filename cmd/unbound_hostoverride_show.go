package cmd

import (
	"fmt"
	"log"
	opnsenseapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"

	"github.com/spf13/cobra"
)

var unboundHostOverrideShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show Unbound Host overrides by host / domain or uuid",
	Run:   hostOverrideShowRun,
}

func init() {
	unboundHostOverrideShowCmd.Flags().StringVarP(&HOSTOVERRIDEhost, "host", "", "", "lookup entries by host / domain: the host part")
	unboundHostOverrideShowCmd.Flags().StringVarP(&HOSTOVERRIDEdomain, "domain", "", "", "lookup entries by host / domain: the domain part")
	unboundHostOverrideShowCmd.Flags().StringVarP(&HOSTOVERRIDEfilterRr, "rr", "", "", "only show entries of this record type (A, AAAA, MX, TXT), defaults to all")
	unboundHostOverrideShowCmd.Flags().StringVarP(&HOSTOVERRIDEuuid, "uuid", "", "", "show the entry with this uuid")

	unboundHostOverrideCmd.AddCommand(unboundHostOverrideShowCmd)
}

func hostOverrideShowRun(_ *cobra.Command, _ []string) {
	var unboundApi = unbound.UnboundApi{OPNsense: GetOPNsenseApi()}

	var hostOverrides []unbound.HostOverride
	if HOSTOVERRIDEuuid != "" {
		var hostOverride, err = unboundApi.HostOverrideGet(HOSTOVERRIDEuuid)
		if err != nil {
			log.Fatal(err)
		}
		hostOverrides = append(hostOverrides, hostOverride)
	} else {
		if HOSTOVERRIDEhost == "" || HOSTOVERRIDEdomain == "" {
			log.Fatal("Please either set host and domain or set uuid")
		}

		var err error
		hostOverrides, err = unboundApi.HostOverrideFindByFQDN(HOSTOVERRIDEhost, HOSTOVERRIDEdomain, HOSTOVERRIDEfilterRr)
		if err != nil {
			log.Fatal(err)
		}
		if len(hostOverrides) == 0 {
			log.Fatal(&opnsenseapi.NotFoundError{Name: fmt.Sprintf("host override %s.%s", HOSTOVERRIDEhost, HOSTOVERRIDEdomain)})
		}
	}

	for i, hostOverride := range hostOverrides {
		if i > 0 {
			fmt.Println()
		}
		printFields(hostOverrideFields(hostOverride))
	}
}
