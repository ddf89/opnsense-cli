package cmd

import (
	"log"
	opnsenseapi "opnsense-cli/opnsense/api"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "opn",
	Short: "OPNsense cli to operate with a opnsense API",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	// cobra already printed the error to stderr, keep stdout clean for scripts
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "log every API request with its status and duration to stderr")
}

func GetOPNsenseApi() *opnsenseapi.OPNsense {
	connection, err := opnsenseapi.ConfigureFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	connection.Verbose, _ = RootCmd.PersistentFlags().GetBool("verbose")
	return connection
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
