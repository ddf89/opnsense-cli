package cmd

import (
	"errors"
	"log"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"strings"

	"github.com/spf13/cobra"
)

// systemLoggingDestinationFlags holds the field flags of create or update, separate per command since the defaults differ
type systemLoggingDestinationFlags struct {
	enabled     bool
	transport   string
	hostname    string
	port        string
	program     string
	level       string
	facility    string
	certificate string
	rfc5424     bool
	description string
}

var (
	// lookup flags of show / update / rm / enable / disable
	systemLoggingDestinationUuid        string
	systemLoggingDestinationDescription string
)

var systemLoggingDestinationCmd = &cobra.Command{
	Use:   "destination",
	Short: "Manage remote logging destinations (send logs to a remote syslog server)",
}

func init() {
	systemLoggingCmd.AddCommand(systemLoggingDestinationCmd)
}

// systemLoggingDestinationAddLookupFlags adds --uuid / --description used to select a single destination
func systemLoggingDestinationAddLookupFlags(command *cobra.Command) {
	command.Flags().StringVar(&systemLoggingDestinationUuid, "uuid", "", "select the destination by uuid")
	command.Flags().StringVar(&systemLoggingDestinationDescription, "description", "", "select the destination by its description (exact match)")
}

// systemLoggingDestinationAddFieldFlags adds the destination field flags, descriptionFlag is "description" on create, "new-description" on update
func systemLoggingDestinationAddFieldFlags(command *cobra.Command, flags *systemLoggingDestinationFlags, descriptionFlag string, create bool) {
	var defaultTransport, defaultPort = "", ""
	if create {
		defaultTransport, defaultPort = "udp4", "514"
	}
	command.Flags().BoolVar(&flags.enabled, "enabled", true, "enable the destination (--enabled=false to disable)")
	command.Flags().StringVar(&flags.transport, "transport", defaultTransport, "transport: "+strings.Join(system.LoggingTransports, ", ")+" (must match the address family of --hostname)")
	command.Flags().StringVar(&flags.hostname, "hostname", "", "IP address or hostname of the remote syslog server")
	command.Flags().StringVar(&flags.port, "port", defaultPort, "port of the remote syslog server")
	command.Flags().StringVar(&flags.program, "program", "", "comma separated applications to send, like filterlog,unbound, empty for all")
	command.Flags().StringVar(&flags.level, "level", "", "comma separated levels to send ("+strings.Join(system.LoggingLevels, ", ")+"), empty for all")
	command.Flags().StringVar(&flags.facility, "facility", "", "comma separated facilities to send (kern, user, daemon, auth, local0..local7, ...), empty for all")
	command.Flags().StringVar(&flags.certificate, "certificate", "", "refid of the client certificate, required for tls4 / tls6")
	command.Flags().BoolVar(&flags.rfc5424, "rfc5424", false, "send messages in RFC 5424 format instead of RFC 3164 (BSD)")
	command.Flags().StringVar(&flags.description, descriptionFlag, "", "Entry description")
}

// systemLoggingDestinationValidate checks the field flags, only the changed ones on update
func systemLoggingDestinationValidate(cmd *cobra.Command, flags *systemLoggingDestinationFlags, create bool) {
	var given = func(flag string) bool {
		return create || cmd.Flags().Changed(flag)
	}
	if given("hostname") && strings.TrimSpace(flags.hostname) == "" {
		log.Fatal("--hostname must not be empty")
	}
	if given("transport") {
		if flags.transport == "" {
			log.Fatal("--transport must not be empty")
		}
		systemLoggingValidateList("transport", flags.transport, system.LoggingTransports)
		if strings.Contains(flags.transport, ",") {
			log.Fatal("--transport takes a single value")
		}
	}
	if given("port") {
		systemLoggingValidateRange("port", flags.port, 1, 65535, false)
	}
	systemLoggingValidateList("level", flags.level, system.LoggingLevels)
	systemLoggingValidateList("facility", flags.facility, system.LoggingFacilities)
}

// systemLoggingDestinationLookup resolves --uuid / --description to a single destination or exits with a helpful message
func systemLoggingDestinationLookup(systemApi *system.SystemApi) system.LoggingDestination {
	if systemLoggingDestinationUuid != "" && systemLoggingDestinationDescription != "" {
		log.Fatal("Please use either --uuid or --description, not both")
	}
	if systemLoggingDestinationUuid == "" && systemLoggingDestinationDescription == "" {
		log.Fatal("Please set --uuid or --description to select the destination")
	}

	if systemLoggingDestinationUuid != "" {
		var destination, err = systemApi.LoggingDestinationGet(systemLoggingDestinationUuid)
		if err != nil {
			log.Fatal(err)
		}
		return destination
	}

	var destination, err = systemApi.LoggingDestinationFind(systemLoggingDestinationDescription)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%s\nThe lookup is ambiguous, please select the destination with --uuid", tooMany.Name)
	}
	if err != nil {
		log.Fatal(err)
	}
	return destination
}
