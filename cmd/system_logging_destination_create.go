package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemLoggingDestinationCreateFlags systemLoggingDestinationFlags

var systemLoggingDestinationCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a remote logging destination, prints its uuid",
	Long: `Create a remote logging destination, prints its uuid.
Use a unique --description to be able to select it later by description.
Run "opn system logging service reconfigure" to apply.`,
	Args: cobra.NoArgs,
	Run:  systemLoggingDestinationCreateRun,
}

func init() {
	systemLoggingDestinationAddFieldFlags(systemLoggingDestinationCreateCmd, &systemLoggingDestinationCreateFlags, "description", true)
	_ = systemLoggingDestinationCreateCmd.MarkFlagRequired("hostname")

	systemLoggingDestinationCmd.AddCommand(systemLoggingDestinationCreateCmd)
}

func systemLoggingDestinationCreateRun(cmd *cobra.Command, _ []string) {
	var flags = &systemLoggingDestinationCreateFlags
	systemLoggingDestinationValidate(cmd, flags, true)

	var destination = system.LoggingDestination{
		Enabled:     systemLoggingBool(flags.enabled),
		Transport:   flags.transport,
		Hostname:    flags.hostname,
		Port:        flags.port,
		Program:     flags.program,
		Level:       flags.level,
		Facility:    flags.facility,
		Certificate: flags.certificate,
		Rfc5424:     systemLoggingBool(flags.rfc5424),
		Description: flags.description,
	}

	var uuid, err = systemLoggingApi().LoggingDestinationCreate(destination)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(uuid)
}
