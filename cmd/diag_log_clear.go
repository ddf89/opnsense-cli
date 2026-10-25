package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var diagLogClearYes bool

var diagLogClearCmd = &cobra.Command{
	Use:   "clear <name>",
	Short: "Empty a log on the firewall (for everyone, cannot be undone), requires --yes",
	Args:  cobra.ExactArgs(1),
	Run:   diagLogClearRun,
}

func init() {
	diagLogClearCmd.Flags().BoolVar(&diagLogClearYes, "yes", false, "confirm clearing the log")
	diagLogCmd.AddCommand(diagLogClearCmd)
}

func diagLogClearRun(_ *cobra.Command, args []string) {
	if !diagLogClearYes {
		log.Fatalf("Clearing removes all lines of log %q for everyone, add --yes to confirm", args[0])
	}
	var diagnosticsApi = diagLogApi()
	var module, scope = diagLogResolve(diagnosticsApi, args[0])

	if err := diagnosticsApi.LogClear(module, scope); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cleared log %s/%s\n", module, scope)
}
