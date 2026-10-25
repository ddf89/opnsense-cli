package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemLoggingDestinationUpdateFlags systemLoggingDestinationFlags

var systemLoggingDestinationUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a remote logging destination, only the given flags are changed",
	Long: `Select the destination with --uuid or --description (exact match), --description only selects,
use --new-description to change it. Only explicitly given flags are sent, pass an empty value
(e.g. --level "") to clear a list. Run "opn system logging service reconfigure" to apply.`,
	Args: cobra.NoArgs,
	Run:  systemLoggingDestinationUpdateRun,
}

func init() {
	systemLoggingDestinationAddLookupFlags(systemLoggingDestinationUpdateCmd)
	systemLoggingDestinationAddFieldFlags(systemLoggingDestinationUpdateCmd, &systemLoggingDestinationUpdateFlags, "new-description", false)

	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationUpdateCmd)
}

func systemLoggingDestinationUpdateRun(cmd *cobra.Command, _ []string) {
	var flags = &systemLoggingDestinationUpdateFlags
	systemLoggingDestinationValidate(cmd, flags, false)

	var fields system.LoggingDestinationFields
	var changed = func(flag string, value string) *string {
		if cmd.Flags().Changed(flag) {
			return &value
		}
		return nil
	}
	fields.Enabled = changed("enabled", systemLoggingBool(flags.enabled))
	fields.Transport = changed("transport", flags.transport)
	fields.Hostname = changed("hostname", flags.hostname)
	fields.Port = changed("port", flags.port)
	fields.Program = changed("program", flags.program)
	fields.Level = changed("level", flags.level)
	fields.Facility = changed("facility", flags.facility)
	fields.Certificate = changed("certificate", flags.certificate)
	fields.Rfc5424 = changed("rfc5424", systemLoggingBool(flags.rfc5424))
	fields.Description = changed("new-description", flags.description)

	if fields == (system.LoggingDestinationFields{}) {
		log.Fatal("Nothing to update, please set at least one field flag (see --help)")
	}

	var systemApi = systemLoggingApi()
	var destination = systemLoggingDestinationLookup(systemApi)
	if err := systemApi.LoggingDestinationUpdate(destination.Uuid, fields); err != nil {
		log.Fatal(err)
	}
	fmt.Println(destination.Uuid)
}
