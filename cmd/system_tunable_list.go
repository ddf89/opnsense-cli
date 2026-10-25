package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemTunableListCmd = &cobra.Command{
	Use:   "list",
	Short: "List System Tunables",
	Long: `List configured tunables and the built-in OPNsense defaults.

SOURCE is "built-in" for defaults which are not configured (VALUE is then the current runtime value),
"override" for a configured built-in and "custom" for other configured tunables.
An empty VALUE ("-") of a configured tunable means the DEFAULT is used.`,
	Args: cobra.NoArgs,
	Run:  systemTunableListRun,
}

func init() {
	systemTunableListCmd.Flags().StringVar(&systemTunableSearch, "search", "", "only list tunables containing this phrase in any column")
	systemTunableListCmd.Flags().BoolVar(&systemTunableChanged, "changed", false, "only list configured tunables whose value differs from the default")
	systemTunableCmd.AddCommand(systemTunableListCmd)
}

func systemTunableListRun(_ *cobra.Command, _ []string) {
	var tunables, err = newSystemTunableApi().TunableList(systemTunableSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(tunables))
	for _, tunable := range tunables {
		if systemTunableChanged && !tunable.IsChanged() {
			continue
		}
		rows = append(rows, []string{
			tunable.Uuid,
			tunable.Tunable,
			tunable.Value,
			tunable.DefaultValue,
			systemTunableTypeName(tunable.Type),
			systemTunableSource(tunable),
			systemTunableTruncate(tunable.Description, 60),
		})
	}
	printTable([]string{"UUID", "TUNABLE", "VALUE", "DEFAULT", "TYPE", "SOURCE", "DESCRIPTION"}, rows)
}
