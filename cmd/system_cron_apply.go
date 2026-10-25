package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemCronApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Activate the cron job changes (writes the crontab)",
	Args:  cobra.NoArgs,
	Run:   systemCronApplyRun,
}

func init() {
	systemCronCmd.AddCommand(systemCronApplyCmd)
}

func systemCronApplyRun(_ *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	if err := api.CronReconfigure(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("cron reconfigured")
}
