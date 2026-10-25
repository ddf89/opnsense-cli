package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/system"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

var systemBackupListProvider string

var systemBackupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the configuration history, newest first",
	Args:  cobra.NoArgs,
	Run:   systemBackupListRun,
}

func init() {
	systemBackupAddProviderFlag(systemBackupListCmd, &systemBackupListProvider)
	systemBackupCmd.AddCommand(systemBackupListCmd)
}

func systemBackupListRun(_ *cobra.Command, _ []string) {
	var backups, err = newSystemBackupApi().BackupList(systemBackupListProvider)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(backups))
	for _, backup := range backups {
		rows = append(rows, []string{
			backup.Id,
			systemBackupTime(backup),
			backup.Username,
			strconv.FormatInt(backup.Filesize, 10),
			backup.Description,
		})
	}
	printTable([]string{"ID", "TIME", "USER", "SIZE", "DESCRIPTION"}, rows)
}

func systemBackupTime(backup system.Backup) string {
	var timestamp, ok = backup.Timestamp()
	if !ok {
		return backup.TimeIso
	}
	return timestamp.Local().Format(time.DateTime)
}
