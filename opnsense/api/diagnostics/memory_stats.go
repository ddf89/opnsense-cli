package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Kernel memory statistics of Diagnostics > Memory (api/diagnostics/system/memory, "vmstat -m" and "vmstat -z" as
// libxo JSON). 26.7 answers {"__version":"2","vmstat":{"malloc-statistics":{"memory":[{"type":"devbuf","in-use":4405,
// "memory-use":7355312,"requests":4445,"size":[16,32,...]}]},"memory-zone-statistics":{"zone":[{"name":"VNODE",
// "size":440,"limit":0,"used":48534,"free":39,"requests":51307,"fail":0,"sleep":0,"xdomain":0}]}}}.
// memory-use is in bytes, zone size in bytes per item and used/free count items. The controller expects the
// statistics at the top level (without "vmstat"), renames type to name and adds totals; because of the "vmstat"
// level this does not happen on 26.7, so both shapes are accepted. Zone names are not unique (one per memory domain)

// MemoryMalloc is one malloc type (vmstat -m)
type MemoryMalloc struct {
	Name     string // the malloc type
	InUse    int64  // allocations in use
	Bytes    int64  // memory in use
	Requests int64  // allocations since boot
	Sizes    []int64
	Raw      json.RawMessage
}

// MemoryZone is one UMA zone (vmstat -z)
type MemoryZone struct {
	Name     string
	Size     int64 // bytes per item
	Limit    int64 // maximum number of items, 0 for none
	Used     int64 // items in use
	Free     int64 // cached free items
	Requests int64
	Fail     int64
	Sleep    int64
	XDomain  int64
	Raw      json.RawMessage
}

// Bytes is the memory the zone holds: used and free items
func (z MemoryZone) Bytes() int64 {
	return z.Size * (z.Used + z.Free)
}

// MemoryStatistics are the malloc types and UMA zones of the kernel in API order
type MemoryStatistics struct {
	Malloc []MemoryMalloc
	Zones  []MemoryZone
	Raw    json.RawMessage
}

// MemoryStats returns the kernel memory statistics
func (opn *DiagnosticsApi) MemoryStats() (*MemoryStatistics, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("system", "memory"), nil, &raw); err != nil {
		return nil, err
	}
	type statistics struct {
		Malloc *struct {
			Memory []json.RawMessage `json:"memory"`
		} `json:"malloc-statistics"`
		Zones *struct {
			Zone []json.RawMessage `json:"zone"`
		} `json:"memory-zone-statistics"`
	}
	var answer struct {
		statistics
		Vmstat *statistics `json:"vmstat"`
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("no memory statistics in the answer of system/memory: %s", healthShorten(raw))
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("unexpected answer from system/memory: %w", err)
	}
	var stats = answer.statistics
	if answer.Vmstat != nil {
		stats = *answer.Vmstat
	}
	if stats.Malloc == nil && stats.Zones == nil {
		return nil, fmt.Errorf("no memory statistics in the answer of system/memory: %s", healthShorten(raw))
	}

	var result = &MemoryStatistics{Raw: raw}
	if stats.Malloc != nil {
		for _, item := range stats.Malloc.Memory {
			var decoded struct {
				Type     string  `json:"type"`
				Name     string  `json:"name"`
				InUse    int64   `json:"in-use"`
				Memory   int64   `json:"memory-use"`
				Requests int64   `json:"requests"`
				Size     []int64 `json:"size"`
			}
			if err := json.Unmarshal(item, &decoded); err != nil {
				return nil, fmt.Errorf("unexpected malloc statistics %s: %w", healthShorten(item), err)
			}
			var name = decoded.Name
			if name == "" {
				name = decoded.Type
			}
			result.Malloc = append(result.Malloc, MemoryMalloc{Name: name, InUse: decoded.InUse, Bytes: decoded.Memory,
				Requests: decoded.Requests, Sizes: decoded.Size, Raw: item})
		}
	}
	if stats.Zones != nil {
		for _, item := range stats.Zones.Zone {
			var decoded struct {
				Name     string `json:"name"`
				Size     int64  `json:"size"`
				Limit    int64  `json:"limit"`
				Used     int64  `json:"used"`
				Free     int64  `json:"free"`
				Requests int64  `json:"requests"`
				Fail     int64  `json:"fail"`
				Sleep    int64  `json:"sleep"`
				XDomain  int64  `json:"xdomain"`
			}
			if err := json.Unmarshal(item, &decoded); err != nil {
				return nil, fmt.Errorf("unexpected zone statistics %s: %w", healthShorten(item), err)
			}
			result.Zones = append(result.Zones, MemoryZone{Name: decoded.Name, Size: decoded.Size, Limit: decoded.Limit,
				Used: decoded.Used, Free: decoded.Free, Requests: decoded.Requests, Fail: decoded.Fail, Sleep: decoded.Sleep,
				XDomain: decoded.XDomain, Raw: item})
		}
	}
	return result, nil
}
