package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemLoggingDestinationEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable a remote logging destination, selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run:   systemLoggingDestinationEnableRun,
}

var systemLoggingDestinationDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable a remote logging destination, selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run:   systemLoggingDestinationEnableRun,
}

func init() {
	systemLoggingDestinationAddLookupFlags(systemLoggingDestinationEnableCmd)
	systemLoggingDestinationAddLookupFlags(systemLoggingDestinationDisableCmd)
	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationEnableCmd)
	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationDisableCmd)
}

func systemLoggingDestinationEnableRun(cmd *cobra.Command, _ []string) {
	var enable = cmd.Name() == "enable"
	var systemApi = systemLoggingApi()
	var destination = systemLoggingDestinationLookup(systemApi)

	var changed, err = systemApi.LoggingDestinationSetEnabled(destination.Uuid, enable)
	if err != nil {
		log.Fatal(err)
	}
	if !changed {
		log.Printf("Destination was already %sd", cmd.Name())
	}
	fmt.Printf("%sd, uuid: %s\n", cmd.Name(), destination.Uuid)
}
