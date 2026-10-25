package cmd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/system"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const powerRebootWarning = `WARNING: rebooting interrupts all routing, VPN and services of the firewall (and this API) until it is back.`

var (
	powerRebootYes          bool
	powerRebootWait         bool
	powerRebootTimeout      time.Duration
	powerRebootPollInterval time.Duration
)

var powerRebootCmd = &cobra.Command{
	Use:   "reboot",
	Short: "Reboot the firewall (needs --yes)",
	Long: powerRebootWarning + `
Requires --yes. With --wait the command waits until the firewall went down and answers the API again,
polling the read-only api/core/system/status, and fails when that does not happen within --timeout.`,
	Example: `  opn power reboot --yes
  opn power reboot --yes --wait --timeout 15m`,
	Args: cobra.NoArgs,
	Run:  powerRebootRun,
}

func init() {
	powerRebootCmd.Flags().BoolVar(&powerRebootYes, "yes", false, "confirm the reboot")
	powerRebootCmd.Flags().BoolVar(&powerRebootWait, "wait", false, "wait until the firewall is back up")
	powerRebootCmd.Flags().DurationVar(&powerRebootTimeout, "timeout", system.PowerDefaultWaitTimeout, "how long --wait waits for the firewall to go down and come back")
	powerRebootCmd.Flags().DurationVar(&powerRebootPollInterval, "poll-interval", system.PowerDefaultPollInterval, "time between two status checks of --wait")
	_ = powerRebootCmd.Flags().MarkHidden("poll-interval")
	powerCmd.AddCommand(powerRebootCmd)
}

func powerRebootRun(cmd *cobra.Command, _ []string) {
	var options = powerRebootOptions{
		Yes:  powerRebootYes,
		Wait: powerRebootWait,
		WaitOptions: system.PowerWaitOptions{
			Timeout:      powerRebootTimeout,
			PollInterval: powerRebootPollInterval,
		},
	}
	if !powerRebootWait && (cmd.Flags().Changed("timeout") || cmd.Flags().Changed("poll-interval")) {
		log.Fatal("--timeout is only used together with --wait")
	}
	if powerRebootTimeout <= 0 || powerRebootPollInterval <= 0 {
		log.Fatal("--timeout must be positive")
	}

	var api *system.SystemApi
	if powerRebootYes {
		api = powerApi()
	}
	if err := powerRebootExecute(api, os.Stderr, options); err != nil {
		log.Fatal(err)
	}
}

type powerRebootOptions struct {
	Yes         bool
	Wait        bool
	WaitOptions system.PowerWaitOptions
}

// powerRebootExecute reboots (and optionally waits), progress goes to out. Without Yes it only prints the
// warning and fails, api is not touched (and may be nil)
func powerRebootExecute(api *system.SystemApi, out io.Writer, options powerRebootOptions) error {
	var logger = log.New(out, "", log.LstdFlags)
	if !options.Yes {
		_, _ = fmt.Fprintln(out, powerRebootWarning)
		return errors.New("refusing to reboot without --yes")
	}

	if err := api.PowerReboot(); err != nil {
		return err
	}
	logger.Printf("Reboot of %s initiated", api.BaseUrl.Host)
	if !options.Wait {
		return nil
	}

	var waitOptions = options.WaitOptions
	if waitOptions.Timeout <= 0 {
		waitOptions.Timeout = system.PowerDefaultWaitTimeout
	}
	waitOptions.Progress = func(event system.PowerWaitEvent) {
		switch event.State {
		case system.PowerStateDown:
			logger.Printf("Firewall went down after %s, waiting for it to come back", event.Elapsed.Round(time.Second))
		case system.PowerStateUp:
			logger.Printf("Firewall is back up after %s", event.Elapsed.Round(time.Second))
		}
	}
	logger.Printf("Waiting up to %s for the firewall to go down and come back up", waitOptions.Timeout)
	return api.PowerWaitUntilUp(waitOptions)
}
