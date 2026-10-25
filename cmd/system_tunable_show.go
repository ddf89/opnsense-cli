package cmd

import (
	"github.com/spf13/cobra"
)

var systemTunableShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a System Tunable selected by --name or --uuid",
	Args:  cobra.NoArgs,
	Run:   systemTunableShowRun,
}

func init() {
	systemTunableSetupLookupFlags(systemTunableShowCmd)
	systemTunableCmd.AddCommand(systemTunableShowCmd)
}

func systemTunableShowRun(_ *cobra.Command, _ []string) {
	var tunable = systemTunableLookup(newSystemTunableApi())

	var valueLabel = "Value"
	if tunable.IsBuiltin() {
		valueLabel = "Runtime value"
	}
	printFields([][2]string{
		{"UUID", tunable.Uuid},
		{"Tunable", tunable.Tunable},
		{valueLabel, tunable.Value},
		{"Default", tunable.DefaultValue},
		{"Type", systemTunableTypeName(tunable.Type)},
		{"Source", systemTunableSource(tunable)},
		{"Description", tunable.Description},
	})
}
