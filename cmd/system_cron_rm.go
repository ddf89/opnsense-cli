package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemCronRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a cron job selected by --uuid or --description",
	Long: `Remove a cron job selected by --uuid or --description.

Jobs registered by other services (origin other than "cron") cannot be removed, disable them instead.
Run "opn system cron apply" to activate the change.`,
	Args: cobra.NoArgs,
	Run:  systemCronRmRun,
}

func init() {
	systemCronSetupLookupFlags(systemCronRmCmd)

	systemCronCmd.AddCommand(systemCronRmCmd)
}

func systemCronRmRun(_ *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	var job = systemCronLookup(api)
	if job.Origin != system.CronOriginUser {
		log.Fatalf("the job was registered by %q and cannot be removed, disable it instead", job.Origin)
	}

	if err := api.CronJobRemove(job.Uuid); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted successfully, uuid: %s\n", job.Uuid)
}
