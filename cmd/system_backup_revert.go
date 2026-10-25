package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var (
	systemBackupRevertId  string
	systemBackupRevertYes bool
)

var systemBackupRevertCmd = &cobra.Command{
	Use:   "revert",
	Short: "Restore a backup from the local history as running configuration",
	Long: `Restore a backup from the local history as running configuration.

This replaces the whole configuration, including users and API keys (your API key
may stop working). Services are not reconfigured automatically. Requires --yes.`,
	Args: cobra.NoArgs,
	Run:  systemBackupRevertRun,
}

func init() {
	systemBackupRevertCmd.Flags().StringVar(&systemBackupRevertId, "id", "", "backup id from 'backup list'")
	systemBackupRevertCmd.Flags().BoolVar(&systemBackupRevertYes, "yes", false, "confirm replacing the running configuration")
	_ = systemBackupRevertCmd.MarkFlagRequired("id")
	systemBackupCmd.AddCommand(systemBackupRevertCmd)
}

func systemBackupRevertRun(_ *cobra.Command, _ []string) {
	if !systemBackupRevertYes {
		log.Fatalf("Refusing to revert to %s without --yes: this replaces the running configuration", systemBackupRevertId)
	}
	if err := newSystemBackupApi().BackupRevert(systemBackupRevertId); err != nil {
		log.Fatal(err)
	}
	log.Printf("Reverted configuration to %s, reconfigure or reboot to apply it to running services", systemBackupRevertId)
}
