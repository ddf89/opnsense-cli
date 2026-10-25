package cmd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/system"
	"os"

	"github.com/spf13/cobra"
)

const powerOffWarning = `WARNING: powering off halts the firewall, all routing, VPN and services stop.
It does NOT come back by itself: powering it on again needs physical or console (IPMI, hypervisor) access.`

var powerOffYes bool

var powerOffCmd = &cobra.Command{
	Use:     "off",
	Aliases: []string{"halt", "poweroff"},
	Short:   "Power off the firewall (needs --yes)",
	Long:    powerOffWarning + "\nRequires --yes.",
	Example: "  opn power off --yes",
	Args:    cobra.NoArgs,
	Run:     powerOffRun,
}

func init() {
	powerOffCmd.Flags().BoolVar(&powerOffYes, "yes", false, "confirm powering off")
	powerCmd.AddCommand(powerOffCmd)
}

func powerOffRun(_ *cobra.Command, _ []string) {
	var api *system.SystemApi
	if powerOffYes {
		api = powerApi()
	}
	if err := powerOffExecute(api, os.Stderr, powerOffYes); err != nil {
		log.Fatal(err)
	}
}

// powerOffExecute powers off, messages go to out. Without yes it only prints the warning and fails,
// api is not touched (and may be nil)
func powerOffExecute(api *system.SystemApi, out io.Writer, yes bool) error {
	if !yes {
		_, _ = fmt.Fprintln(out, powerOffWarning)
		return errors.New("refusing to power off without --yes")
	}

	if err := api.PowerOff(); err != nil {
		return err
	}
	log.New(out, "", log.LstdFlags).Printf("Power off of %s initiated, it will not come back without physical or console access", api.BaseUrl.Host)
	return nil
}
