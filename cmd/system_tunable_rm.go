package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemTunableRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove a configured System Tunable selected by --name or --uuid",
	Long: `Remove a configured System Tunable selected by --name or --uuid.

Removing an override of a built-in default brings back the built-in default, built-in defaults themselves
can not be removed. Activate the change with "opn system tunable apply".`,
	Args: cobra.NoArgs,
	Run:  systemTunableRmRun,
}

func init() {
	systemTunableSetupLookupFlags(systemTunableRmCmd)
	systemTunableCmd.AddCommand(systemTunableRmCmd)
}

func systemTunableRmRun(_ *cobra.Command, _ []string) {
	var api = newSystemTunableApi()
	var tunable = systemTunableLookup(api)
	if tunable.IsBuiltin() {
		log.Fatalf("%s is a built-in default which is not configured and can not be removed, use \"set --value\" to override it", tunable.Tunable)
	}

	if err := api.TunableRemove(tunable.Uuid); err != nil {
		log.Fatal(err)
	}
	if tunable.DefaultValue != "" {
		log.Printf("the built-in default %s=%s applies again", tunable.Tunable, tunable.DefaultValue)
	}
	systemTunableApplyHint()
	fmt.Printf("deleted %s\n", tunable.Uuid)
}
