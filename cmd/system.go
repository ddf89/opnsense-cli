package cmd

import (
	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Manage System settings and configuration using the OPNsense API",
}

func init() {
	RootCmd.AddCommand(systemCmd)
}
