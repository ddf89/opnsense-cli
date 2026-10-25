package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"sort"
	"strings"
	"time"
)

// /system/resource: the system summary of the dashboard widgets (print, api/diagnostics/system/*) and the CPU usage
// stream of the CPU widget (monitor, api/diagnostics/cpu_usage/stream)

func init() {
	var menu = Root.Menu("system/resource")
	menu.Help = "system resources: versions, uptime, memory, disks, temperatures and CPU usage"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show versions, uptime, load, memory, swap, mbufs, temperatures and file systems",
			Long: `Shows the system summary of the dashboard widgets: host name, versions, CPU model, uptime, load
averages, memory, swap and mbuf usage, temperature sensors and file systems.

json prints the raw answers of all endpoints as one JSON object keyed by part. Parts that cannot be read
(e.g. missing privileges) are reported and make the command fail after printing the rest.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the raw answers as one JSON object"}},
			Run:  systemResourcePrint,
		},
		&Command{
			Name: "monitor",
			Help: "show the CPU usage every second until Ctrl-C",
			Long: `Shows the CPU usage in percent, measured by OPNsense every second, one line per second until Ctrl-C.
once prints a single measurement together with the CPU model. json prints the raw OPNsense events, one
JSON object per line. A dropped stream is reconnected.`,
			Args: []Arg{
				{Name: "once", Type: Bool, Help: "print one measurement with the CPU model and stop"},
				{Name: "json", Type: Bool, Help: "print the raw events as JSON, one per line"},
			},
			Run: systemResourceMonitor,
		},
	)
}

// --- print

func systemResourcePrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var raws = map[string]json.RawMessage{}
	var failed []string
	var check = func(part string, raw json.RawMessage, err error) bool {
		if err != nil {
			failed = append(failed, part)
			c.Infof("%s: %v", part, err)
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
	var hasCPU = check("cpu", cpuRaw, cpuErr)
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

	if args.Bool("json") {
		if len(raws) > 0 {
			if err := c.JSON(raws); err != nil {
				return err
			}
		}
	} else {
		var fields [][2]string
		if hasInfo {
			fields = append(fields, [2]string{"host", info.Name}, [2]string{"versions", strings.Join(info.Versions, ", ")})
		}
		if hasCPU {
			fields = append(fields, [2]string{"cpu", cpuModel})
		}
		if hasTime {
			fields = append(fields,
				[2]string{"uptime", fmt.Sprintf("%s (since %s)", times.Uptime, times.Boottime)},
				[2]string{"date", times.Datetime},
				[2]string{"load-average", times.Loadavg},
				[2]string{"config-changed", times.Config})
		}
		if hasMemory {
			fields = append(fields, [2]string{"memory", systemResourceMemory(memory)})
		}
		if hasSwap {
			fields = append(fields, [2]string{"swap", systemResourceSwap(swap)})
		}
		if hasMbuf {
			fields = append(fields, [2]string{"mbuf-clusters", systemResourceMbuf(mbuf)})
		}
		if hasTemperatures {
			fields = append(fields, [2]string{"temperature", systemResourceTemperatures(temperatures)})
		}
		c.Fields(fields)

		if hasDisks && len(disks) > 0 {
			c.Println()
			var rows = make([][]string, 0, len(disks))
			for _, disk := range disks {
				var size = disk.Total
				if size == "" {
					size = disk.Blocks
				}
				rows = append(rows, []string{disk.Device, disk.Type, size, disk.Used, disk.Available,
					systemResourcePercent(disk.UsedPercent), disk.Mountpoint})
			}
			c.Table([]string{"FILESYSTEM", "TYPE", "SIZE", "USED", "AVAIL", "USE%", "MOUNTED-ON"}, rows)
		}
	}

	if len(failed) > 0 {
		return errors.New("could not read " + strings.Join(failed, ", "))
	}
	return nil
}

func systemResourcePercent(n diagnostics.SystemResourceNumber) string {
	if !n.Valid {
		return ""
	}
	return fmt.Sprintf("%.0f%%", n.Value)
}

const systemResourceMiB = 1024 * 1024

func systemResourceMemory(memory *diagnostics.SystemResourceMemory) string {
	if !memory.Total.Valid || !memory.Used.Valid || memory.Total.Value <= 0 {
		return "unknown"
	}
	var text = fmt.Sprintf("%.0f MiB of %.0f MiB used (%.0f%%)", memory.Used.Value/systemResourceMiB,
		memory.Total.Value/systemResourceMiB, memory.Used.Value*100/memory.Total.Value)
	if memory.Arc.Valid {
		text += fmt.Sprintf(", ZFS ARC %.0f MiB", memory.Arc.Value/systemResourceMiB)
	}
	return text
}

func systemResourceSwap(swap []diagnostics.SystemResourceSwap) string {
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

func systemResourceMbuf(mbuf diagnostics.SystemResourceMbuf) string {
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

func systemResourceTemperatures(sensors []diagnostics.SystemResourceTemperature) string {
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

// --- monitor

var errSystemResourceDone = errors.New("done")

const systemResourceLineFormat = "%-8s  %5s  %5s  %5s  %5s  %5s  %5s\n"

func systemResourceMonitor(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var once = args.Bool("once")
	var asJSON = args.Bool("json")

	var model string
	if once && !asJSON {
		if model, err = api.CpuType(); err != nil {
			return err
		}
	}

	var headerPrinted = false
	err = api.CpuWatch(c.Context, ifaceReconnect(c, "CPU usage"), func(usage diagnostics.CpuUsage) error {
		switch {
		case asJSON:
			if err := c.JSON(usage.Raw); err != nil {
				return err
			}
		case once:
			c.Fields([][2]string{
				{"model", model},
				{"total", systemResourceCPUPercent(usage.Total)},
				{"user", systemResourceCPUPercent(usage.User)},
				{"nice", systemResourceCPUPercent(usage.Nice)},
				{"system", systemResourceCPUPercent(usage.Sys)},
				{"interrupt", systemResourceCPUPercent(usage.Intr)},
				{"idle", systemResourceCPUPercent(usage.Idle)},
			})
		default:
			if !headerPrinted {
				headerPrinted = true
				c.Printf(systemResourceLineFormat, "TIME", "TOTAL", "USER", "NICE", "SYS", "INTR", "IDLE")
			}
			c.Printf(systemResourceLineFormat, time.Now().Format("15:04:05"), systemResourceCPUPercent(usage.Total),
				systemResourceCPUPercent(usage.User), systemResourceCPUPercent(usage.Nice), systemResourceCPUPercent(usage.Sys),
				systemResourceCPUPercent(usage.Intr), systemResourceCPUPercent(usage.Idle))
		}
		if once {
			return errSystemResourceDone
		}
		return nil
	})
	if errors.Is(err, errSystemResourceDone) {
		return nil
	}
	return err
}

func systemResourceCPUPercent(value int) string {
	return fmt.Sprintf("%d%%", value)
}
