package cmd

import (
	"github.com/spf13/cobra"
)

var systemCronShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a cron job selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run:   systemCronShowRun,
}

func init() {
	systemCronSetupLookupFlags(systemCronShowCmd)

	systemCronCmd.AddCommand(systemCronShowCmd)
}

func systemCronShowRun(_ *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	printFields(systemCronFields(systemCronLookup(api)))
}
