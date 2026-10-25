package cmd

import (
	"log"
	"math"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var (
	systemLoggingSetEnabled     bool
	systemLoggingSetLogLocal    bool
	systemLoggingSetMaxPreserve string
	systemLoggingSetMaxFileSize string
)

var systemLoggingSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Change the general logging settings, only the given flags are changed",
	Long: `Change the general logging settings, only the given flags are sent.
Booleans are given as --loglocal / --loglocal=false. Run "opn system logging service reconfigure" to apply.`,
	Args: cobra.NoArgs,
	Run:  systemLoggingSetRun,
}

func init() {
	systemLoggingSetCmd.Flags().BoolVar(&systemLoggingSetEnabled, "enabled", true, "enable the logging service (general.enabled)")
	systemLoggingSetCmd.Flags().BoolVar(&systemLoggingSetLogLocal, "loglocal", true, "write logs to the local disk")
	systemLoggingSetCmd.Flags().StringVar(&systemLoggingSetMaxPreserve, "maxpreserve", "", "number of rotated log files to keep (OPNsense default 31)")
	systemLoggingSetCmd.Flags().StringVar(&systemLoggingSetMaxFileSize, "maxfilesize", "", "rotate a log file early once it exceeds this size, empty for no size limit")

	systemLoggingCmd.AddCommand(systemLoggingSetCmd)
}

func systemLoggingSetRun(cmd *cobra.Command, _ []string) {
	var fields system.LoggingGeneralFields
	var enabled, logLocal = systemLoggingBool(systemLoggingSetEnabled), systemLoggingBool(systemLoggingSetLogLocal)
	if cmd.Flags().Changed("enabled") {
		fields.Enabled = &enabled
	}
	if cmd.Flags().Changed("loglocal") {
		fields.LogLocal = &logLocal
	}
	if cmd.Flags().Changed("maxpreserve") {
		systemLoggingValidateRange("maxpreserve", systemLoggingSetMaxPreserve, 0, math.MaxInt32, false)
		fields.MaxPreserve = &systemLoggingSetMaxPreserve
	}
	if cmd.Flags().Changed("maxfilesize") {
		systemLoggingValidateRange("maxfilesize", systemLoggingSetMaxFileSize, 0, math.MaxInt, true)
		fields.MaxFileSize = &systemLoggingSetMaxFileSize
	}
	if fields == (system.LoggingGeneralFields{}) {
		log.Fatal("Nothing to change, please set at least one of --enabled, --loglocal, --maxpreserve, --maxfilesize")
	}

	if err := systemLoggingApi().LoggingGeneralSet(fields); err != nil {
		log.Fatal(err)
	}
	log.Printf("Logging settings saved, run \"opn system logging service reconfigure\" to apply them")
}
