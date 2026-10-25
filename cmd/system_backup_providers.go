package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var systemBackupProvidersCmd = &cobra.Command{
	Use:   "providers",
	Short: "List the backup providers (\"this\" is the local firewall)",
	Args:  cobra.NoArgs,
	Run:   systemBackupProvidersRun,
}

func init() {
	systemBackupCmd.AddCommand(systemBackupProvidersCmd)
}

func systemBackupProvidersRun(_ *cobra.Command, _ []string) {
	var providers, err = newSystemBackupApi().BackupProviders()
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(providers))
	for _, provider := range providers {
		rows = append(rows, []string{provider.Name, provider.Description, provider.Dirname})
	}
	printTable([]string{"NAME", "DESCRIPTION", "DIRECTORY"}, rows)
}
