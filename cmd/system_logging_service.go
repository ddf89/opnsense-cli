package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemLoggingServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the logging service (syslog-ng)",
}

var systemLoggingServiceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Status of the logging service (running, stopped)",
	Args:  cobra.NoArgs,
	Run:   systemLoggingServiceStatusRun,
}

var systemLoggingServiceRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the logging service",
	Args:  cobra.NoArgs,
	Run:   systemLoggingServiceRestartRun,
}

var systemLoggingServiceReconfigureCmd = &cobra.Command{
	Use:   "reconfigure",
	Short: "Apply the saved logging configuration (regenerate the syslog-ng config and reload it)",
	Args:  cobra.NoArgs,
	Run:   systemLoggingServiceReconfigureRun,
}

func init() {
	systemLoggingServiceCmd.AddCommand(systemLoggingServiceStatusCmd)
	systemLoggingServiceCmd.AddCommand(systemLoggingServiceRestartCmd)
	systemLoggingServiceCmd.AddCommand(systemLoggingServiceReconfigureCmd)
	systemLoggingCmd.AddCommand(systemLoggingServiceCmd)
}

func systemLoggingServiceStatusRun(_ *cobra.Command, _ []string) {
	var status, err = systemLoggingApi().LoggingServiceStatus()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Service status: %s", status)
}

func systemLoggingServiceRestartRun(_ *cobra.Command, _ []string) {
	if err := systemLoggingApi().LoggingServiceRestart(); err != nil {
		log.Fatal(err)
	}
	log.Printf("Service restarted")
}

func systemLoggingServiceReconfigureRun(_ *cobra.Command, _ []string) {
	if err := systemLoggingApi().LoggingServiceReconfigure(); err != nil {
		log.Fatal(err)
	}
	log.Printf("Service reconfigured")
}
