package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemCronListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all cron jobs",
	Args:  cobra.NoArgs,
	Run:   systemCronListRun,
}

func init() {
	systemCronListCmd.Flags().StringVarP(&systemCronSearch, "search", "", "", "only list jobs where any field contains this text")

	systemCronCmd.AddCommand(systemCronListCmd)
}

func systemCronListRun(_ *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	var jobs, err = api.CronJobSearch(systemCronSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(jobs))
	for _, job := range jobs {
		rows = append(rows, []string{
			job.Uuid,
			job.Enabled,
			job.Schedule(),
			job.Who,
			job.Command,
			job.Parameters,
			job.Description,
			job.Origin,
		})
	}
	printTable([]string{"UUID", "ENABLED", "SCHEDULE", "WHO", "COMMAND", "PARAMETERS", "DESCRIPTION", "ORIGIN"}, rows)
}
