package diagnostics

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// System information of the dashboard widgets (api/diagnostics/system/*, OPNsense\Diagnostics\Api\SystemController),
// all read-only GETs:
//   - system_information: {"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD ...","OpenSSL ..."],"updates":"..."}
//   - system_time: {"uptime":"1 day, 00:42:37","datetime":"...","boottime":"...","config":"...","loadavg":"0.48, 0.58, 0.56"}
//   - system_resources: {"memory":{"total":"2102894592","total_frmt":"2005","used":599127070,"used_frmt":"571",
//     "arc":...,"arc_frmt":"...","arc_txt":"..."}} (bytes, *_frmt in MiB, arc only with ZFS, used "N/A" if unknown)
//   - system_disk: {"devices":[{"device":"/dev/...","type":"ufs","blocks":"2.8G","used":"2.0G","available":"540M",
//     "used_pct":80,"mountpoint":"/"}]} (newer versions add total and *_bytes)
//   - system_swap: {"swap":[{"device":"/dev/...","total":"1048576","used":"0"}]} (KiB)
//   - system_mbuf: {"mbuf-statistics":{...netstat -m...}}
//   - system_temperature: [{"device":"dev.cpu.0.temperature","device_seq":0,"temperature":"45.0","type":"cpu",
//     "type_translated":"CPU"}]

// SystemResourceNumber is a number OPNsense sends as JSON number or string, Valid is false for e.g. "N/A"
type SystemResourceNumber struct {
	Value float64
	Valid bool
}

func (n *SystemResourceNumber) UnmarshalJSON(data []byte) error {
	var text = strings.Trim(string(data), `"`)
	var value, err = strconv.ParseFloat(strings.TrimSpace(text), 64)
	*n = SystemResourceNumber{Value: value, Valid: err == nil}
	return nil
}

// SystemResourceInformation is the System Information widget
type SystemResourceInformation struct {
	Name     string   `json:"name"`     // host name with domain
	Versions []string `json:"versions"` // product, kernel and OpenSSL versions (and license)
	Updates  string   `json:"updates"`
}

// SystemResourceTime has the uptime and load (dates formatted like "Sun Oct 25 0:06:33 UTC 2026")
type SystemResourceTime struct {
	Uptime   string `json:"uptime"`
	Datetime string `json:"datetime"`
	Boottime string `json:"boottime"`
	Config   string `json:"config"` // time of the last configuration change
	Loadavg  string `json:"loadavg"`
}

// SystemResourceMemory is the memory usage in bytes, Arc is only set on ZFS systems
type SystemResourceMemory struct {
	Total SystemResourceNumber `json:"total"`
	Used  SystemResourceNumber `json:"used"`
	Arc   SystemResourceNumber `json:"arc"`
}

// SystemResourceDisk is one mounted file system. Sizes are human formatted (e.g. "2.8G"), the *Bytes values are
// only sent by newer versions
type SystemResourceDisk struct {
	Device         string               `json:"device"`
	Type           string               `json:"type"`
	Blocks         string               `json:"blocks"` // the total size
	Total          string               `json:"total"`
	TotalBytes     SystemResourceNumber `json:"total_bytes"`
	Used           string               `json:"used"`
	UsedBytes      SystemResourceNumber `json:"used_bytes"`
	Available      string               `json:"available"`
	AvailableBytes SystemResourceNumber `json:"available_bytes"`
	UsedPercent    SystemResourceNumber `json:"used_pct"`
	Mountpoint     string               `json:"mountpoint"`
}

// SystemResourceSwap is one swap device, sizes in KiB
type SystemResourceSwap struct {
	Device string               `json:"device"`
	Total  SystemResourceNumber `json:"total"`
	Used   SystemResourceNumber `json:"used"`
}

// SystemResourceMbuf are the mbuf statistics of "netstat -m" (e.g. "cluster-total", "cluster-max", "mbuf-failures")
type SystemResourceMbuf map[string]SystemResourceNumber

// SystemResourceTemperature is one temperature sensor, Temperature in degrees Celsius
type SystemResourceTemperature struct {
	Device         string               `json:"device"`
	DeviceSeq      int                  `json:"device_seq"`
	Temperature    SystemResourceNumber `json:"temperature"`
	Type           string               `json:"type"` // zone, amd, platform, cpu or other
	TypeTranslated string               `json:"type_translated"`
}

// systemResourceGet GETs api/diagnostics/system/<method>, decodes it into out and returns the raw answer
func (opn *DiagnosticsApi) systemResourceGet(method string, out any) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("system", method), nil, &raw); err != nil {
		return nil, err
	}
	if err := trafficDecodeObject(raw, out); err != nil {
		return nil, fmt.Errorf("unexpected answer from %s: %w", method, err)
	}
	return raw, nil
}

// SystemResourceInformation returns host name and versions
func (opn *DiagnosticsApi) SystemResourceInformation() (*SystemResourceInformation, json.RawMessage, error) {
	var info SystemResourceInformation
	var raw, err = opn.systemResourceGet("system_information", &info)
	if err != nil {
		return nil, nil, err
	}
	if info.Name == "" && len(info.Versions) == 0 {
		return nil, nil, fmt.Errorf("unexpected answer from system_information: %s", raw)
	}
	return &info, raw, nil
}

// SystemResourceTime returns uptime, boot time and load averages
func (opn *DiagnosticsApi) SystemResourceTime() (*SystemResourceTime, json.RawMessage, error) {
	var t SystemResourceTime
	var raw, err = opn.systemResourceGet("system_time", &t)
	if err != nil {
		return nil, nil, err
	}
	if t.Uptime == "" {
		return nil, nil, fmt.Errorf("unexpected answer from system_time: %s", raw)
	}
	return &t, raw, nil
}

// SystemResourceMemory returns the memory usage
func (opn *DiagnosticsApi) SystemResourceMemory() (*SystemResourceMemory, json.RawMessage, error) {
	var container struct {
		Memory *SystemResourceMemory `json:"memory"`
	}
	var raw, err = opn.systemResourceGet("system_resources", &container)
	if err != nil {
		return nil, nil, err
	}
	if container.Memory == nil {
		return nil, nil, fmt.Errorf("unexpected answer from system_resources: %s", raw)
	}
	return container.Memory, raw, nil
}

// SystemResourceDisks returns the usage of the mounted file systems
func (opn *DiagnosticsApi) SystemResourceDisks() ([]SystemResourceDisk, json.RawMessage, error) {
	var container struct {
		Devices []SystemResourceDisk `json:"devices"`
	}
	var raw, err = opn.systemResourceGet("system_disk", &container)
	if err != nil {
		return nil, nil, err
	}
	return container.Devices, raw, nil
}

// SystemResourceSwap returns the swap devices (empty without swap)
func (opn *DiagnosticsApi) SystemResourceSwap() ([]SystemResourceSwap, json.RawMessage, error) {
	var container struct {
		Swap *[]SystemResourceSwap `json:"swap"`
	}
	var raw, err = opn.systemResourceGet("system_swap", &container)
	if err != nil {
		return nil, nil, err
	}
	if container.Swap == nil {
		return nil, nil, fmt.Errorf("unexpected answer from system_swap: %s", raw)
	}
	return *container.Swap, raw, nil
}

// SystemResourceMbuf returns the mbuf statistics
func (opn *DiagnosticsApi) SystemResourceMbuf() (SystemResourceMbuf, json.RawMessage, error) {
	var container struct {
		Statistics SystemResourceMbuf `json:"mbuf-statistics"`
	}
	var raw, err = opn.systemResourceGet("system_mbuf", &container)
	if err != nil {
		return nil, nil, err
	}
	if container.Statistics == nil {
		return nil, nil, fmt.Errorf("unexpected answer from system_mbuf: %s", raw)
	}
	return container.Statistics, raw, nil
}

// SystemResourceTemperatures returns the temperature sensors (empty when there are none, e.g. in VMs)
func (opn *DiagnosticsApi) SystemResourceTemperatures() ([]SystemResourceTemperature, json.RawMessage, error) {
	var sensors []SystemResourceTemperature
	var raw, err = opn.systemResourceGet("system_temperature", &sensors)
	if err != nil {
		return nil, nil, err
	}
	return sensors, raw, nil
}
