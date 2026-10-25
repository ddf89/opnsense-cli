package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var systemDefaultsResetYes bool

const systemDefaultsResetWarning = `WARNING: a factory reset wipes the WHOLE configuration of the firewall and reboots it.
All settings, users and API keys (including the one used right now) are lost, there is no undo.
Download a configuration backup first if you might need it.`

var systemDefaultsResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the firewall to factory defaults and reboot it (needs --yes)",
	Long:  systemDefaultsResetWarning,
	Args:  cobra.NoArgs,
	Run:   systemDefaultsResetRun,
}

func init() {
	systemDefaultsResetCmd.Flags().BoolVar(&systemDefaultsResetYes, "yes", false, "confirm that the whole configuration should be wiped")
	systemDefaultsCmd.AddCommand(systemDefaultsResetCmd)
}

func systemDefaultsResetRun(_ *cobra.Command, _ []string) {
	_, _ = fmt.Fprintln(os.Stderr, systemDefaultsResetWarning)
	if !systemDefaultsResetYes {
		log.Fatal("Refusing to reset without --yes")
	}

	var systemApi = systemDefaultsApi()
	// also makes sure we talk to a working API before the destructive call
	var defaults, err = systemApi.DefaultsGet()
	if err != nil {
		log.Fatal(err)
	}
	if err := systemApi.DefaultsFactoryReset(); err != nil {
		log.Fatal(err)
	}

	log.Printf("Factory reset scheduled, the firewall reboots and comes back with LAN address %s", defaults.DefaultIp)
}
