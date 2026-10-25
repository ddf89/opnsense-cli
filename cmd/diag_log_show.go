package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"time"

	"github.com/spf13/cobra"
)

var (
	diagLogShowLines    int
	diagLogShowSeverity string
	diagLogShowSearch   string
	diagLogShowJson     bool
	diagLogShowFollow   bool
)

var diagLogShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Print the newest lines of a log, oldest first (like tail), optionally following new lines",
	Long: `Print the newest lines of a log, oldest first, as "timestamp severity process[pid]: message".
<name> is a scope like system, configd, dnsmasq or <module>/<scope> like core/system, see "opn diag log list".

Filters are applied by OPNsense: --search matches lines containing every given word (case-insensitive),
--severity keeps lines with one of the given severities (lines without severity, like the boot log, always match).

With --follow new lines are streamed until Ctrl-C. A dropped stream is reconnected automatically, lines logged
in the meantime are printed once (up to 1000 lines).`,
	Args: cobra.ExactArgs(1),
	Run:  diagLogShowRun,
}

func init() {
	diagLogShowCmd.Flags().IntVarP(&diagLogShowLines, "lines", "n", 50, "number of lines to print (0-9999), with --follow 0 prints only new lines")
	diagLogShowCmd.Flags().StringVar(&diagLogShowSeverity, "severity", "", "comma separated severities: emergency, alert, critical, error, warning, notice, informational, debug (or emerg, crit, err, warn, info)")
	diagLogShowCmd.Flags().StringVar(&diagLogShowSearch, "search", "", "only lines containing all of these space separated words (case-insensitive)")
	diagLogShowCmd.Flags().BoolVar(&diagLogShowJson, "json", false, "print one JSON object per line (ndjson)")
	diagLogShowCmd.Flags().BoolVarP(&diagLogShowFollow, "follow", "f", false, "stream new lines until Ctrl-C")

	diagLogCmd.AddCommand(diagLogShowCmd)
}

func diagLogShowRun(_ *cobra.Command, args []string) {
	if diagLogShowLines < 0 || diagLogShowLines > 9999 {
		log.Fatalf("--lines must be between 0 and 9999: %d", diagLogShowLines)
	}
	var filter = diagnostics.LogFilter{
		SearchPhrase: diagLogShowSearch,
		Severities:   diagLogParseSeverities(diagLogShowSeverity),
	}
	var diagnosticsApi = diagLogApi()
	var module, scope = diagLogResolve(diagnosticsApi, args[0])

	var printRecord = func(record diagnostics.LogRecord) error {
		fmt.Println(diagLogFormat(record, diagLogShowJson))
		return nil
	}

	if !diagLogShowFollow {
		var records, err = diagnosticsApi.LogTail(module, scope, diagLogShowLines, filter)
		if err != nil {
			log.Fatal(err)
		}
		if len(records) == 0 && diagLogShowLines > 0 {
			log.Printf("No lines found in log %s/%s", module, scope)
		}
		for _, record := range records {
			_ = printRecord(record)
		}
		return
	}

	// the live stream sends the tail itself, so there is no gap between the tail and the new lines
	var ctx, cancel = diagStreamContext()
	defer cancel()
	var err = diagnosticsApi.LogFollow(ctx, module, scope, diagnostics.LogFollowOptions{
		Lines:  diagLogShowLines,
		Filter: filter,
		OnReconnect: func(err error, delay time.Duration) {
			log.Printf("log stream interrupted (%v), reconnecting in %s", err, delay)
		},
	}, printRecord)
	if err != nil {
		log.Fatal(err)
	}
}
