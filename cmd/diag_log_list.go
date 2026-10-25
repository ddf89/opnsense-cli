package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var diagLogListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the available logs (as linked in the OPNsense menu)",
	Args:  cobra.NoArgs,
	Run:   diagLogListRun,
}

func init() {
	diagLogCmd.AddCommand(diagLogListCmd)
}

func diagLogListRun(_ *cobra.Command, _ []string) {
	var logFiles, err = diagLogApi().LogList()
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(logFiles))
	for _, logFile := range logFiles {
		rows = append(rows, []string{logFile.Name, logFile.Module, logFile.Scope, logFile.MenuPath})
	}
	printTable([]string{"NAME", "MODULE", "SCOPE", "MENU"}, rows)
}
