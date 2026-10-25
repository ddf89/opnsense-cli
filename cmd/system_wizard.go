package cmd

import (
	"github.com/spf13/cobra"
)

var systemWizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Setup wizard settings (System > Wizard)",
}

func init() {
	systemCmd.AddCommand(systemWizardCmd)
}
