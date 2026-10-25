package cmd

import (
	"log"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	diagFirewallStatsBy    string
	diagFirewallStatsLimit int
)

var diagFirewallStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Top 10 counts of the newest firewall log records, grouped by a field",
	Long: `Top 10 counts (plus "other") of the newest firewall log records, grouped by a field.

--by takes any firewall log field, e.g. interface (default), action, dir, protoname,
src, dst, srcport, dstport, label, rid. proto and rule are accepted for protoname and label.`,
	Args: cobra.NoArgs,
	Run:  diagFirewallStatsRun,
}

func init() {
	diagFirewallStatsCmd.Flags().StringVar(&diagFirewallStatsBy, "by", "interface", "field to group by")
	diagFirewallStatsCmd.Flags().IntVar(&diagFirewallStatsLimit, "limit", 5000, "number of newest records to count")
	diagFirewallCmd.AddCommand(diagFirewallStatsCmd)
}

func diagFirewallStatsRun(_ *cobra.Command, _ []string) {
	var groupBy = diagFirewallStatsBy
	switch groupBy {
	case "proto":
		groupBy = "protoname"
	case "rule":
		groupBy = "label"
	}

	var stats, err = newDiagFirewallApi().FirewallStats(groupBy, diagFirewallStatsLimit)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(stats))
	for _, stat := range stats {
		rows = append(rows, []string{stat.Label, strconv.Itoa(stat.Value)})
	}
	printTable([]string{strings.ToUpper(groupBy), "COUNT"}, rows)
}
