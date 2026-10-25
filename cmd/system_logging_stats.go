package cmd

import (
	"log"
	"sort"

	"github.com/spf13/cobra"
)

var systemLoggingStatsSearch string

var systemLoggingStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show the syslog-ng statistics (messages processed / dropped / queued per source and destination)",
	Args:  cobra.NoArgs,
	Run:   systemLoggingStatsRun,
}

func init() {
	systemLoggingStatsCmd.Flags().StringVar(&systemLoggingStatsSearch, "search", "", "only show counters containing this phrase in any column (case-insensitive)")
	systemLoggingCmd.AddCommand(systemLoggingStatsCmd)
}

func systemLoggingStatsRun(_ *cobra.Command, _ []string) {
	var stats, err = systemLoggingApi().LoggingStats(systemLoggingStatsSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, []string{s.SourceName, s.SourceId, s.SourceInstance, s.State, s.Type, s.Number})
	}
	// OPNsense returns the counters in random order
	sort.SliceStable(rows, func(i, j int) bool {
		for column := 0; column < 5; column++ {
			if rows[i][column] != rows[j][column] {
				return rows[i][column] < rows[j][column]
			}
		}
		return false
	})
	printTable([]string{"SOURCE", "ID", "INSTANCE", "STATE", "TYPE", "NUMBER"}, rows)
}
