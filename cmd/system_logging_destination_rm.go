package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemLoggingDestinationRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a remote logging destination, selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run:   systemLoggingDestinationRmRun,
}

func init() {
	systemLoggingDestinationAddLookupFlags(systemLoggingDestinationRmCmd)
	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationRmCmd)
}

func systemLoggingDestinationRmRun(_ *cobra.Command, _ []string) {
	var systemApi = systemLoggingApi()
	var destination = systemLoggingDestinationLookup(systemApi)

	if err := systemApi.LoggingDestinationRemove(destination.Uuid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted successfully, uuid: %s\n", destination.Uuid)
}
