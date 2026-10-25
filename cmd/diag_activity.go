package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	diagActivityLines    int
	diagActivityFollow   bool
	diagActivityInterval time.Duration
	diagActivityJson     bool
)

var diagActivityCmd = &cobra.Command{
	Use:   "activity",
	Short: "Show the system activity (top), optionally refreshing it",
	Long: `Show the system activity like top (Diagnostics > Activity): load, CPU and memory summary
and the busiest threads. Every query takes about 2 seconds (top measures for that long).

--follow repeats the query every --interval until Ctrl-C, on a terminal the screen is
redrawn. --json prints the raw answers, one JSON object per line.`,
	Example: `  opn diag activity
  opn diag activity -n 10 --follow --interval 5s`,
	Args: cobra.NoArgs,
	Run:  diagActivityRun,
}

func init() {
	var flags = diagActivityCmd.Flags()
	flags.IntVarP(&diagActivityLines, "lines", "n", 20, "number of threads to show (0 for all)")
	flags.BoolVarP(&diagActivityFollow, "follow", "f", false, "refresh until Ctrl-C")
	flags.DurationVar(&diagActivityInterval, "interval", 2*time.Second, "pause between two refreshes of --follow")
	flags.BoolVar(&diagActivityJson, "json", false, "print the raw answer as JSON, one object per line")
	diagCmd.AddCommand(diagActivityCmd)
}

func diagActivityApi() *diagnostics.DiagnosticsApi {
	return &diagnostics.DiagnosticsApi{OPNsense: GetOPNsenseApi()}
}

func diagActivityRun(_ *cobra.Command, _ []string) {
	if diagActivityLines < 0 {
		log.Fatal("--lines must not be negative")
	}
	if diagActivityInterval <= 0 {
		log.Fatal("--interval must be positive")
	}
	var api = diagActivityApi()
	var ctx, cancel = diagStreamContext()
	defer cancel()

	var options = diagActivityOptions{
		Lines: diagActivityLines, Follow: diagActivityFollow, Interval: diagActivityInterval,
		Json: diagActivityJson, Clear: diagActivityIsTerminal(os.Stdout),
	}
	if err := diagActivityExecute(ctx, api, os.Stdout, options); err != nil {
		log.Fatal(err)
	}
}

type diagActivityOptions struct {
	Lines    int
	Follow   bool
	Interval time.Duration
	Json     bool
	Clear    bool                                      // redraw the screen on every refresh (terminal)
	Sleep    func(context.Context, time.Duration) bool // nil: diagActivitySleep
}

func diagActivityExecute(ctx context.Context, api *diagnostics.DiagnosticsApi, out io.Writer, options diagActivityOptions) error {
	var first = true
	var show = func() error {
		var activity, err = api.ActivityGet()
		if err != nil {
			return err
		}
		if options.Json {
			_, _ = fmt.Fprintln(out, diagActivityCompact(activity.Raw))
			return nil
		}
		diagActivityRefresh(out, options.Follow, options.Clear, first)
		first = false
		diagActivityPrint(out, activity, options.Lines)
		return nil
	}
	if !options.Follow {
		return show()
	}
	return diagActivityPollLoop(ctx, options.Interval, options.Sleep, show)
}

func diagActivityPrint(out io.Writer, activity *diagnostics.Activity, lines int) {
	for _, header := range activity.Headers {
		_, _ = fmt.Fprintln(out, header)
	}
	_, _ = fmt.Fprintln(out)

	var threads = activity.Threads
	if lines > 0 && len(threads) > lines {
		threads = threads[:lines]
	}
	var rows = make([][]string, 0, len(threads))
	for _, t := range threads {
		rows = append(rows, []string{t.Pid, t.Thread, t.User, t.Priority, t.Nice, t.Size, t.Resident, t.State, t.Cpu, t.Time, t.CpuUsage, t.Command})
	}
	diagActivityTable(out, []string{"PID", "THR", "USERNAME", "PRI", "NICE", "SIZE", "RES", "STATE", "C", "TIME", "WCPU", "COMMAND"}, rows)
}

// --- helpers shared by the diag activity / traffic / cpu / system commands

// diagActivityPollLoop calls fn, pauses interval and repeats until ctx is cancelled (nil) or fn fails.
// sleep returns false when ctx was cancelled while sleeping, nil uses diagActivitySleep
func diagActivityPollLoop(ctx context.Context, interval time.Duration, sleep func(context.Context, time.Duration) bool, fn func() error) error {
	if sleep == nil {
		sleep = diagActivitySleep
	}
	for {
		if err := fn(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ctx.Err() != nil || !sleep(ctx, interval) {
			return nil
		}
	}
}

// diagActivitySleep waits for d or until ctx is cancelled (false)
func diagActivitySleep(ctx context.Context, d time.Duration) bool {
	var timer = time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// diagActivityRefresh separates two refreshes of a followed view: the screen is cleared on a terminal,
// otherwise a timestamp line is printed
func diagActivityRefresh(out io.Writer, follow bool, clear bool, first bool) {
	if !follow {
		return
	}
	if clear {
		_, _ = fmt.Fprint(out, "\033[H\033[2J")
		return
	}
	if !first {
		_, _ = fmt.Fprintln(out)
	}
	_, _ = fmt.Fprintf(out, "--- %s\n", time.Now().Format(time.DateTime))
}

func diagActivityIsTerminal(file *os.File) bool {
	var info, err = file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// diagActivityTable prints rows as aligned columns to out, empty cells are shown as "-"
func diagActivityTable(out io.Writer, headers []string, rows [][]string) {
	var writer = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		var cells = make([]string, len(row))
		for i, cell := range row {
			if cell == "" {
				cell = "-"
			}
			cells[i] = cell
		}
		_, _ = fmt.Fprintln(writer, strings.Join(cells, "\t"))
	}
	_ = writer.Flush()
}

// diagActivityFields prints "key: value" lines aligned to out
func diagActivityFields(out io.Writer, fields [][2]string) {
	var writer = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, field := range fields {
		_, _ = fmt.Fprintf(writer, "%s:\t%s\n", field[0], field[1])
	}
	_ = writer.Flush()
}

// diagActivityCompact returns raw JSON on a single line
func diagActivityCompact(raw []byte) string {
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, raw); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return compacted.String()
}
