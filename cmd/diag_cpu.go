package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	diagCpuFollow bool
	diagCpuJson   bool
)

var diagCpuCmd = &cobra.Command{
	Use:   "cpu",
	Short: "Show the CPU usage, optionally streaming it every second",
	Long: `Show the CPU usage in percent (the CPU widget of the dashboard), measured by OPNsense over one second.

Without --follow one measurement is printed together with the CPU model, with --follow one line
per second is printed until Ctrl-C. --json prints the raw OPNsense events, one JSON object per line.`,
	Example: `  opn diag cpu
  opn diag cpu --follow`,
	Args: cobra.NoArgs,
	Run:  diagCpuRun,
}

func init() {
	diagCpuCmd.Flags().BoolVarP(&diagCpuFollow, "follow", "f", false, "keep streaming until Ctrl-C")
	diagCpuCmd.Flags().BoolVar(&diagCpuJson, "json", false, "print the raw events as JSON, one per line")
	diagCmd.AddCommand(diagCpuCmd)
}

func diagCpuRun(_ *cobra.Command, _ []string) {
	var api = diagActivityApi()
	var ctx, cancel = diagStreamContext()
	defer cancel()
	if err := diagCpuExecute(ctx, api, os.Stdout, diagCpuFollow, diagCpuJson, diagTrafficReconnect("CPU usage"), time.Now); err != nil {
		log.Fatal(err)
	}
}

var errDiagCpuDone = errors.New("done")

const diagCpuLineFormat = "%-8s  %5s  %5s  %5s  %5s  %5s  %5s\n"

func diagCpuExecute(ctx context.Context, api *diagnostics.DiagnosticsApi, out io.Writer, follow bool, asJson bool,
	reconnect diagnostics.TrafficFollowOptions, now func() time.Time) error {
	var model string
	if !follow && !asJson {
		var err error
		if model, err = api.CpuType(); err != nil {
			return err
		}
	}

	var headerPrinted = false
	var err = api.CpuWatch(ctx, reconnect, func(usage diagnostics.CpuUsage) error {
		switch {
		case asJson:
			_, _ = fmt.Fprintln(out, diagActivityCompact(usage.Raw))
		case follow:
			if !headerPrinted {
				headerPrinted = true
				_, _ = fmt.Fprintf(out, diagCpuLineFormat, "TIME", "TOTAL", "USER", "NICE", "SYS", "INTR", "IDLE")
			}
			_, _ = fmt.Fprintf(out, diagCpuLineFormat, now().Format("15:04:05"), diagCpuPercent(usage.Total),
				diagCpuPercent(usage.User), diagCpuPercent(usage.Nice), diagCpuPercent(usage.Sys),
				diagCpuPercent(usage.Intr), diagCpuPercent(usage.Idle))
		default:
			diagActivityFields(out, [][2]string{
				{"model", model},
				{"total", diagCpuPercent(usage.Total)},
				{"user", diagCpuPercent(usage.User)},
				{"nice", diagCpuPercent(usage.Nice)},
				{"system", diagCpuPercent(usage.Sys)},
				{"interrupt", diagCpuPercent(usage.Intr)},
				{"idle", diagCpuPercent(usage.Idle)},
			})
		}
		if !follow {
			return errDiagCpuDone
		}
		return nil
	})
	switch {
	case errors.Is(err, errDiagCpuDone):
		return nil
	}
	return err
}

func diagCpuPercent(value int) string {
	return fmt.Sprintf("%d%%", value)
}
