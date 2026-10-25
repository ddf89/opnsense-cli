package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var (
	systemBackupDiffProvider string
	systemBackupDiffFrom     string
	systemBackupDiffTo       string
)

var systemBackupDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show the changes between two backups as unified diff",
	Args:  cobra.NoArgs,
	Run:   systemBackupDiffRun,
}

func init() {
	systemBackupAddProviderFlag(systemBackupDiffCmd, &systemBackupDiffProvider)
	systemBackupDiffCmd.Flags().StringVar(&systemBackupDiffFrom, "from", "", "backup id to compare from (old side)")
	systemBackupDiffCmd.Flags().StringVar(&systemBackupDiffTo, "to", system.BackupCurrent, "backup id to compare to (new side), or current")
	_ = systemBackupDiffCmd.MarkFlagRequired("from")
	systemBackupCmd.AddCommand(systemBackupDiffCmd)
}

func systemBackupDiffRun(_ *cobra.Command, _ []string) {
	var lines, err = newSystemBackupApi().BackupDiff(systemBackupDiffProvider, systemBackupDiffFrom, systemBackupDiffTo)
	if err != nil {
		log.Fatal(err)
	}
	if len(lines) == 0 {
		log.Printf("No differences")
		return
	}
	for _, line := range lines {
		fmt.Println(line)
	}
}
