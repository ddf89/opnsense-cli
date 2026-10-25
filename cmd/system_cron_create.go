package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemCronCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a cron job",
	Long: `Create a cron job and print its uuid.

The schedule defaults to daily at 00:00, run as root. Run "opn system cron apply" to activate it.`,
	Args: cobra.NoArgs,
	Run:  systemCronCreateRun,
}

func init() {
	systemCronCreateCmd.Flags().StringVarP(&systemCronDescription, "description", "", "", "the job description")
	systemCronSetupFieldFlags(systemCronCreateCmd, true)

	_ = systemCronCreateCmd.MarkFlagRequired("command")
	_ = systemCronCreateCmd.MarkFlagRequired("description")

	systemCronCmd.AddCommand(systemCronCreateCmd)
}

func systemCronCreateRun(command *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	var flag = func(name string) string {
		var value, _ = command.Flags().GetString(name)
		return value
	}
	var job = system.CronJob{
		Enabled:     flag("enabled"),
		Minutes:     flag("minutes"),
		Hours:       flag("hours"),
		Days:        flag("days"),
		Months:      flag("months"),
		Weekdays:    flag("weekdays"),
		Who:         flag("who"),
		Command:     flag("command"),
		Parameters:  flag("parameters"),
		Description: systemCronDescription,
	}
	systemCronValidateCommand(api, job.Command)

	var uuid, err = api.CronJobCreate(job)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created successfully, uuid: %s\n", uuid)
}
