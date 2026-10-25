package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemLoggingDestinationSearch string

var systemLoggingDestinationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all remote logging destinations",
	Args:  cobra.NoArgs,
	Run:   systemLoggingDestinationListRun,
}

func init() {
	systemLoggingDestinationListCmd.Flags().StringVar(&systemLoggingDestinationSearch, "search", "", "only list destinations containing this phrase in any column")
	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationListCmd)
}

func systemLoggingDestinationListRun(_ *cobra.Command, _ []string) {
	var destinations, err = systemLoggingApi().LoggingDestinationList(systemLoggingDestinationSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(destinations))
	for _, d := range destinations {
		rows = append(rows, []string{d.Uuid, d.Enabled, d.Transport, d.Hostname, d.Port, d.Program, d.Level, d.Facility, d.Description})
	}
	printTable([]string{"UUID", "ENABLED", "TRANSPORT", "HOSTNAME", "PORT", "PROGRAM", "LEVEL", "FACILITY", "DESCRIPTION"}, rows)
}
