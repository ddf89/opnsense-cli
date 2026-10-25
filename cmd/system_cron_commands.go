package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemCronCommandsCmd = &cobra.Command{
	Use:   "commands",
	Short: "List the commands (configd actions) available for cron jobs",
	Args:  cobra.NoArgs,
	Run:   systemCronCommandsRun,
}

func init() {
	systemCronCmd.AddCommand(systemCronCommandsCmd)
}

func systemCronCommandsRun(_ *cobra.Command, _ []string) {
	var api = newSystemCronApi()

	var commands, err = api.CronCommands()
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(commands))
	for _, command := range commands {
		rows = append(rows, []string{command.Key, command.Description})
	}
	printTable([]string{"COMMAND", "DESCRIPTION"}, rows)
}
