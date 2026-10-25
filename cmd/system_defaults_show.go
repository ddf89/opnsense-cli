package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemDefaultsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show what a factory reset resets the firewall to",
	Args:  cobra.NoArgs,
	Run:   systemDefaultsShowRun,
}

func init() {
	systemDefaultsCmd.AddCommand(systemDefaultsShowCmd)
}

func systemDefaultsShowRun(_ *cobra.Command, _ []string) {
	var defaults, err = systemDefaultsApi().DefaultsGet()
	if err != nil {
		log.Fatal(err)
	}

	printFields([][2]string{
		{"default_ip", defaults.DefaultIp},
	})
}
