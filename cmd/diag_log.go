package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"

	"github.com/spf13/cobra"
)

var diagLogCmd = &cobra.Command{
	Use:   "log",
	Short: "List, tail and follow the OPNsense log files",
	Long: `List, tail and follow the OPNsense log files (System > Log Files and the "Log File" pages of the services).
A log is named by its scope like system, configd or dnsmasq, or as <module>/<scope> like core/system
(plugins use their own module). "opn diag log list" shows the available logs.`,
}

func init() {
	diagCmd.AddCommand(diagLogCmd)
}

func diagLogApi() *diagnostics.DiagnosticsApi {
	return &diagnostics.DiagnosticsApi{OPNsense: GetOPNsenseApi()}
}

// diagLogResolve turns the <name> argument into module and scope or exits
func diagLogResolve(diagnosticsApi *diagnostics.DiagnosticsApi, name string) (string, string) {
	var module, scope, err = diagnosticsApi.LogResolve(name)
	if err != nil {
		log.Fatal(err)
	}
	return module, scope
}

// diagLogParseSeverities turns a comma separated --severity value into the OPNsense names or exits
func diagLogParseSeverities(value string) []string {
	var severities = make([]string, 0)
	if strings.TrimSpace(value) == "" {
		return severities
	}
	for _, severity := range strings.Split(value, ",") {
		var name, err = diagnostics.LogNormalizeSeverity(severity)
		if err != nil {
			log.Fatalf("--severity: %s", err)
		}
		severities = append(severities, name)
	}
	return severities
}

// diagLogFormat renders a record like "2026-10-25T00:03:13 Notice dhcp6c[31413]: Sending Solicit on vtnet1",
// or as a single line JSON object when asJson
func diagLogFormat(record diagnostics.LogRecord, asJson bool) string {
	if asJson {
		var encoded, err = json.Marshal(record)
		if err != nil {
			log.Fatal(err)
		}
		return string(encoded)
	}

	var severity = record.Severity
	if severity == "" {
		severity = "-"
	}
	var process = ""
	if record.ProcessName != "" {
		process = record.ProcessName
		if record.Pid != "" {
			process = fmt.Sprintf("%s[%s]", process, record.Pid)
		}
		process += ": "
	}
	return fmt.Sprintf("%s %s %s%s", record.Timestamp, severity, process, record.Line)
}
