package cmd

import (
	"github.com/spf13/cobra"
)

var systemLoggingDestinationShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a remote logging destination, selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run:   systemLoggingDestinationShowRun,
}

func init() {
	systemLoggingDestinationAddLookupFlags(systemLoggingDestinationShowCmd)
	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationShowCmd)
}

func systemLoggingDestinationShowRun(_ *cobra.Command, _ []string) {
	var destination = systemLoggingDestinationLookup(systemLoggingApi())

	printFields([][2]string{
		{"uuid", destination.Uuid},
		{"enabled", destination.Enabled},
		{"transport", destination.Transport},
		{"hostname", destination.Hostname},
		{"port", destination.Port},
		{"program", destination.Program},
		{"level", destination.Level},
		{"facility", destination.Facility},
		{"certificate", destination.Certificate},
		{"rfc5424", destination.Rfc5424},
		{"description", destination.Description},
	})
}
