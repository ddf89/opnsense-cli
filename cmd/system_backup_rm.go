package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var (
	systemBackupRmId  string
	systemBackupRmYes bool
)

var systemBackupRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Delete a backup from the local history (requires --yes)",
	Long: `Delete a backup from the local history (requires --yes).

The newest entry is a copy of the running configuration: after deleting it, "current"
(download, diff --to) refers to the previous revision until the configuration is saved again.`,
	Args: cobra.NoArgs,
	Run:  systemBackupRmRun,
}

func init() {
	systemBackupRmCmd.Flags().StringVar(&systemBackupRmId, "id", "", "backup id from 'backup list'")
	systemBackupRmCmd.Flags().BoolVar(&systemBackupRmYes, "yes", false, "confirm the deletion")
	_ = systemBackupRmCmd.MarkFlagRequired("id")
	systemBackupCmd.AddCommand(systemBackupRmCmd)
}

func systemBackupRmRun(_ *cobra.Command, _ []string) {
	if !systemBackupRmYes {
		log.Fatalf("Refusing to delete %s without --yes", systemBackupRmId)
	}
	if err := newSystemBackupApi().BackupDelete(systemBackupRmId); err != nil {
		log.Fatal(err)
	}
	log.Printf("Deleted %s", systemBackupRmId)
}
