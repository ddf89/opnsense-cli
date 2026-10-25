package cmd

import (
	"errors"
	"fmt"
	"log"
	coreapi "opnsense-cli/opnsense/api"

	"github.com/spf13/cobra"
)

var systemTunableSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create or update a System Tunable by name and print its uuid",
	Long: `Create or update a System Tunable by name and print its uuid.

A configured tunable gets the new value (and description when given), a built-in default or a new name is
added as configured tunable. --value "" uses the built-in default. Activate the change with "opn system tunable apply".`,
	Args: cobra.NoArgs,
	Run:  systemTunableSetRun,
}

func init() {
	systemTunableSetCmd.Flags().StringVar(&systemTunableName, "name", "", "tunable name, e.g. kern.ipc.maxsockbuf (required)")
	systemTunableSetCmd.Flags().StringVar(&systemTunableValue, "value", "", "value to set, \"\" to use the built-in default (required)")
	systemTunableSetCmd.Flags().StringVar(&systemTunableDescription, "description", "", "description, kept when not given")
	_ = systemTunableSetCmd.MarkFlagRequired("name")
	_ = systemTunableSetCmd.MarkFlagRequired("value")

	systemTunableCmd.AddCommand(systemTunableSetCmd)
}

func systemTunableSetRun(cmd *cobra.Command, _ []string) {
	var description *string
	if cmd.Flags().Changed("description") {
		description = &systemTunableDescription
	}

	var uuid, created, err = newSystemTunableApi().TunableSet(systemTunableName, systemTunableValue, description)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%v, please remove the duplicates with \"rm --uuid\"", err)
	}
	if err != nil {
		log.Fatal(err)
	}

	if created {
		log.Printf("created tunable %s", systemTunableName)
	} else {
		log.Printf("updated tunable %s", systemTunableName)
	}
	systemTunableApplyHint()
	fmt.Println(uuid)
}
