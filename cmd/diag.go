package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var diagCmd = &cobra.Command{
	Use:   "diag",
	Short: "Diagnostics: tail and stream log files, firewall log, traffic and activity",
}

func init() {
	RootCmd.AddCommand(diagCmd)
}

// diagStreamContext is cancelled on Ctrl-C / SIGTERM, so --follow commands can stop streaming and exit cleanly
func diagStreamContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
