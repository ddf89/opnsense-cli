package cmd

import (
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemBackupCmd = &cobra.Command{
	Use:     "backup",
	Aliases: []string{"backups"},
	Short:   "Configuration backups and history (System > Configuration > Backups / History)",
}

func init() {
	systemCmd.AddCommand(systemBackupCmd)
}

func newSystemBackupApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}

func systemBackupAddProviderFlag(command *cobra.Command, provider *string) {
	command.Flags().StringVarP(provider, "provider", "p", system.BackupProviderLocal, "backup provider, see 'backup providers'")
}
