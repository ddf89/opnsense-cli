package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"sort"
	"strconv"

	"github.com/spf13/cobra"
)

var diagTrafficInterfacesJson bool

var diagTrafficInterfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "Show the traffic totals per interface since boot",
	Long: `Show the traffic counters of every enabled interface since boot (or the last counter reset).
--json prints all counters OPNsense reports, keyed by interface.`,
	Args: cobra.NoArgs,
	Run:  diagTrafficInterfacesRun,
}

func init() {
	diagTrafficInterfacesCmd.Flags().BoolVar(&diagTrafficInterfacesJson, "json", false, "print all counters as JSON")
	diagTrafficCmd.AddCommand(diagTrafficInterfacesCmd)
}

func diagTrafficInterfacesRun(_ *cobra.Command, _ []string) {
	if err := diagTrafficInterfacesExecute(diagActivityApi(), os.Stdout, diagTrafficInterfacesJson); err != nil {
		log.Fatal(err)
	}
}

func diagTrafficInterfacesExecute(api *diagnostics.DiagnosticsApi, out io.Writer, asJson bool) error {
	var interfaces, err = api.TrafficInterfaces()
	if err != nil {
		return err
	}
	if asJson {
		var encoder = json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(interfaces)
	}

	var keys = make([]string, 0, len(interfaces))
	for key := range interfaces {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var rows = make([][]string, 0, len(keys))
	for _, key := range keys {
		var values = interfaces[key]
		var errors = diagTrafficInterfacesSum(values, "input errors", "output errors", "collisions")
		rows = append(rows, []string{
			key, values["name"], values["device"], values["mtu"],
			diagTrafficInterfacesBytes(values["bytes received"]), diagTrafficInterfacesBytes(values["bytes transmitted"]),
			values["packets received"], values["packets transmitted"], errors,
		})
	}
	diagActivityTable(out, []string{"INTERFACE", "NAME", "DEVICE", "MTU", "IN", "OUT", "IN PKTS", "OUT PKTS", "ERRORS"}, rows)
	return nil
}

func diagTrafficInterfacesBytes(value string) string {
	var number, err = strconv.ParseFloat(value, 64)
	if err != nil {
		return value
	}
	return diagTrafficBytes(number)
}

func diagTrafficInterfacesSum(values diagnostics.TrafficInterface, fields ...string) string {
	var sum int64
	for _, field := range fields {
		var number, err = strconv.ParseInt(values[field], 10, 64)
		if err != nil {
			if values[field] == "" {
				continue
			}
			return "?"
		}
		sum += number
	}
	return fmt.Sprint(sum)
}
