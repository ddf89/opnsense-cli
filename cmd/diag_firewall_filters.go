package cmd

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var diagFirewallFiltersCmd = &cobra.Command{
	Use:   "filters",
	Short: "Show the values the firewall log can be filtered by",
	Args:  cobra.NoArgs,
	Run:   diagFirewallFiltersRun,
}

func init() {
	diagFirewallCmd.AddCommand(diagFirewallFiltersCmd)
}

func diagFirewallFiltersRun(_ *cobra.Command, _ []string) {
	var api = newDiagFirewallApi()

	var filters, err = api.FirewallLogFilters()
	if err != nil {
		log.Fatal(err)
	}
	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil {
		log.Fatal(namesErr)
	}

	var devices = make([]string, 0, len(names))
	for device, name := range names {
		devices = append(devices, fmt.Sprintf("%s (%s)", device, name))
	}
	sort.Strings(devices)

	printFields([][2]string{
		{"action", strings.Join(filters.Action, ", ")},
		{"interface", strings.Join(filters.InterfaceName, ", ")},
		{"devices", strings.Join(devices, ", ")},
		{"dir", strings.Join(filters.Dir, ", ")},
	})
}
