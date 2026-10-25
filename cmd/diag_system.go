package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var diagSystemJson bool

var diagSystemCmd = &cobra.Command{
	Use:   "system",
	Short: "Show a summary of the system: versions, uptime, load, memory, disks, temperatures",
	Long: `Show the system summary of the dashboard widgets: host name, versions, CPU model, uptime,
load averages, memory, swap and mbuf usage, file systems and temperature sensors.

--json prints the raw answers of all endpoints as one JSON object. Parts that cannot be read
(e.g. missing privileges) are reported and make the command fail after printing the rest.`,
	Args: cobra.NoArgs,
	Run:  diagSystemRun,
}

func init() {
	diagSystemCmd.Flags().BoolVar(&diagSystemJson, "json", false, "print the raw answers as one JSON object")
	diagCmd.AddCommand(diagSystemCmd)
}

func diagSystemRun(_ *cobra.Command, _ []string) {
	if err := diagSystemExecute(diagActivityApi(), os.Stdout, os.Stderr, diagSystemJson); err != nil {
		log.Fatal(err)
	}
}

// diagSystemExecute prints the summary to out, unreadable parts are reported on errOut and returned as error
func diagSystemExecute(api *diagnostics.DiagnosticsApi, out io.Writer, errOut io.Writer, asJson bool) error {
	var raws = map[string]json.RawMessage{}
	var failed []string
	var check = func(part string, raw json.RawMessage, err error) bool {
		if err != nil {
			failed = append(failed, part)
			_, _ = fmt.Fprintf(errOut, "%s: %v\n", part, err)
			return false
		}
		raws[part] = raw
		return true
	}

	var info, infoRaw, infoErr = api.SystemResourceInformation()
	var hasInfo = check("information", infoRaw, infoErr)
	var times, timeRaw, timeErr = api.SystemResourceTime()
	var hasTime = check("time", timeRaw, timeErr)
	var cpuModel, cpuErr = api.CpuType()
	var cpuRaw, _ = json.Marshal(cpuModel)
	var hasCpu = check("cpu", cpuRaw, cpuErr)
	var memory, memoryRaw, memoryErr = api.SystemResourceMemory()
	var hasMemory = check("memory", memoryRaw, memoryErr)
	var swap, swapRaw, swapErr = api.SystemResourceSwap()
	var hasSwap = check("swap", swapRaw, swapErr)
	var mbuf, mbufRaw, mbufErr = api.SystemResourceMbuf()
	var hasMbuf = check("mbuf", mbufRaw, mbufErr)
	var temperatures, temperatureRaw, temperatureErr = api.SystemResourceTemperatures()
	var hasTemperatures = check("temperature", temperatureRaw, temperatureErr)
	var disks, diskRaw, diskErr = api.SystemResourceDisks()
	var hasDisks = check("disk", diskRaw, diskErr)

	if asJson {
		if len(raws) > 0 {
			var encoder = json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(raws); err != nil {
				return err
			}
		}
	} else {
		var fields [][2]string
		if hasInfo {
			fields = append(fields, [2]string{"host", info.Name}, [2]string{"versions", strings.Join(info.Versions, ", ")})
		}
		if hasCpu {
			fields = append(fields, [2]string{"cpu", cpuModel})
		}
		if hasTime {
			fields = append(fields,
				[2]string{"uptime", fmt.Sprintf("%s (since %s)", times.Uptime, times.Boottime)},
				[2]string{"date", times.Datetime},
				[2]string{"load average", times.Loadavg},
				[2]string{"config changed", times.Config})
		}
		if hasMemory {
			fields = append(fields, [2]string{"memory", diagSystemMemory(memory)})
		}
		if hasSwap {
			fields = append(fields, [2]string{"swap", diagSystemSwap(swap)})
		}
		if hasMbuf {
			fields = append(fields, [2]string{"mbuf clusters", diagSystemMbuf(mbuf)})
		}
		if hasTemperatures {
			fields = append(fields, [2]string{"temperature", diagSystemTemperatures(temperatures)})
		}
		diagActivityFields(out, fields)

		if hasDisks && len(disks) > 0 {
			_, _ = fmt.Fprintln(out)
			var rows = make([][]string, 0, len(disks))
			for _, disk := range disks {
				var size = disk.Total
				if size == "" {
					size = disk.Blocks
				}
				rows = append(rows, []string{disk.Device, disk.Type, size, disk.Used, disk.Available,
					diagSystemPercent(disk.UsedPercent), disk.Mountpoint})
			}
			diagActivityTable(out, []string{"FILESYSTEM", "TYPE", "SIZE", "USED", "AVAIL", "USE%", "MOUNTED ON"}, rows)
		}
	}

	if len(failed) > 0 {
		return errors.New("could not read " + strings.Join(failed, ", "))
	}
	return nil
}

func diagSystemPercent(n diagnostics.SystemResourceNumber) string {
	if !n.Valid {
		return ""
	}
	return fmt.Sprintf("%.0f%%", n.Value)
}

const diagSystemMiB = 1024 * 1024

func diagSystemMemory(memory *diagnostics.SystemResourceMemory) string {
	if !memory.Total.Valid || !memory.Used.Valid || memory.Total.Value <= 0 {
		return "unknown"
	}
	var text = fmt.Sprintf("%.0f MiB of %.0f MiB used (%.0f%%)", memory.Used.Value/diagSystemMiB,
		memory.Total.Value/diagSystemMiB, memory.Used.Value*100/memory.Total.Value)
	if memory.Arc.Valid {
		text += fmt.Sprintf(", ZFS ARC %.0f MiB", memory.Arc.Value/diagSystemMiB)
	}
	return text
}

func diagSystemSwap(swap []diagnostics.SystemResourceSwap) string {
	var total, used float64
	for _, device := range swap {
		total += device.Total.Value
		used += device.Used.Value
	}
	if len(swap) == 0 || total <= 0 {
		return "none"
	}
	// swapinfo reports KiB
	return fmt.Sprintf("%.0f MiB of %.0f MiB used (%.0f%%)", used/1024, total/1024, used*100/total)
}

func diagSystemMbuf(mbuf diagnostics.SystemResourceMbuf) string {
	var current, limit = mbuf["cluster-total"], mbuf["cluster-max"]
	if !current.Valid || !limit.Valid || limit.Value <= 0 {
		return "unknown"
	}
	var text = fmt.Sprintf("%.0f of %.0f (%.0f%%)", current.Value, limit.Value, current.Value*100/limit.Value)
	var failures float64
	for key, value := range mbuf {
		if strings.HasSuffix(key, "-failures") && value.Valid {
			failures += value.Value
		}
	}
	if failures > 0 {
		text += fmt.Sprintf(", %.0f allocation failures", failures)
	}
	return text
}

func diagSystemTemperatures(sensors []diagnostics.SystemResourceTemperature) string {
	if len(sensors) == 0 {
		return "no sensors"
	}
	sensors = append([]diagnostics.SystemResourceTemperature(nil), sensors...)
	sort.SliceStable(sensors, func(i, j int) bool {
		if sensors[i].Type != sensors[j].Type {
			return sensors[i].Type < sensors[j].Type
		}
		return sensors[i].DeviceSeq < sensors[j].DeviceSeq
	})
	var parts = make([]string, 0, len(sensors))
	for _, sensor := range sensors {
		var label = sensor.TypeTranslated
		if label == "" {
			label = sensor.Type
		}
		var value = "?"
		if sensor.Temperature.Valid {
			value = fmt.Sprintf("%.1f °C", sensor.Temperature.Value)
		}
		parts = append(parts, fmt.Sprintf("%s %d: %s", label, sensor.DeviceSeq, value))
	}
	return strings.Join(parts, ", ")
}
