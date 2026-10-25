package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemCronEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable a cron job selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		systemCronToggleRun(true)
	},
}

var systemCronDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable a cron job selected by --uuid or --description",
	Args:  cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		systemCronToggleRun(false)
	},
}

func init() {
	systemCronSetupLookupFlags(systemCronEnableCmd)
	systemCronSetupLookupFlags(systemCronDisableCmd)

	systemCronCmd.AddCommand(systemCronEnableCmd)
	systemCronCmd.AddCommand(systemCronDisableCmd)
}

func systemCronToggleRun(enabled bool) {
	var api = newSystemCronApi()

	var uuid = systemCronUuid
	if uuid == "" {
		uuid = systemCronLookup(api).Uuid
	}

	var changed, err = api.CronJobSetEnabled(uuid, enabled)
	if err != nil {
		log.Fatal(err)
	}

	var state = "disabled"
	if enabled {
		state = "enabled"
	}
	if changed {
		fmt.Printf("%s successfully, uuid: %s\n", state, uuid)
	} else {
		fmt.Printf("already %s, uuid: %s\n", state, uuid)
	}
}
