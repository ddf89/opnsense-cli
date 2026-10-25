package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemLoggingShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the general logging settings",
	Args:  cobra.NoArgs,
	Run:   systemLoggingShowRun,
}

func init() {
	systemLoggingCmd.AddCommand(systemLoggingShowCmd)
}

func systemLoggingShowRun(_ *cobra.Command, _ []string) {
	var general, err = systemLoggingApi().LoggingGeneralGet()
	if err != nil {
		log.Fatal(err)
	}

	printFields([][2]string{
		{"enabled", general.Enabled},
		{"loglocal", general.LogLocal},
		{"maxpreserve", general.MaxPreserve},
		{"maxfilesize", general.MaxFileSize},
	})
}
