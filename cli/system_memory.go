package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"opnsense-cli/opnsense/api/diagnostics"
)

// /system/memory: the kernel memory statistics of Diagnostics > Memory (api/diagnostics/system/memory, vmstat -m
// and vmstat -z)

var systemMemorySortFields = []string{"memory", "name", "requests", "in-use", "free", "fail", "size"}

func init() {
	var menu = Root.Menu("system/memory")
	menu.Help = "kernel memory usage: malloc types and UMA zones (vmstat -m / -z)"
	menu.Add(&Command{
		Name: "print",
		Help: "show the kernel memory usage per malloc type, or per UMA zone",
		Long: `Shows the memory the kernel allocated with malloc per type (vmstat -m): allocations in use, memory in
use, requests since boot and the allocation sizes. zone shows the UMA zones instead (vmstat -z): item size,
limit, items in use and cached free, the memory they hold ((used + free) * size), requests, failed
allocations and sleeps. A zone name appears once per memory domain.

The busiest come first (sort=memory); sort=name sorts by name, the other columns sort descending. in-use is
the in-use column of malloc types and the used column of zones; free, fail and size apply to zones only.
search= shows only the names containing it (case-insensitive). The total of the listed rows is reported after
the table. json prints the rows as OPNsense returns them, one per line.

  print limit=10
  print zone search=mbuf
  print zone sort=fail`,
		Args: []Arg{
			{Name: "zone", Type: Bool, Help: "show the UMA zones (vmstat -z) instead of the malloc types"},
			{Name: "search", Help: "only names containing this"},
			{Name: "sort", Default: "memory", Values: systemMemorySortFields, Help: "order by this column"},
			{Name: "limit", Type: Int, Default: "0", Help: "show at most this many rows, 0 for all", Validate: ValidateRange(0, 1000000)},
			{Name: "json", Type: Bool, Help: "print the rows as JSON, one object per line"},
		},
		Check: func(args *Args) error {
			switch args.String("sort") {
			case "free", "fail", "size":
				if !args.Bool("zone") {
					return fmt.Errorf("sort=%s only with zone", args.String("sort"))
				}
			}
			return nil
		},
		Run: systemMemoryPrint,
	})
}

func systemMemoryPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var stats, statsErr = api.MemoryStats()
	if statsErr != nil {
		return statsErr
	}
	var search = strings.ToLower(args.String("search"))
	var matches = func(name string) bool {
		return search == "" || strings.Contains(strings.ToLower(name), search)
	}
	var limit = args.Int("limit")
	var sortBy = args.String("sort")

	if args.Bool("zone") {
		var zones []diagnostics.MemoryZone
		for _, zone := range stats.Zones {
			if matches(zone.Name) {
				zones = append(zones, zone)
			}
		}
		slices.SortStableFunc(zones, func(a, b diagnostics.MemoryZone) int {
			switch sortBy {
			case "name":
				return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
			case "requests":
				return cmp.Compare(b.Requests, a.Requests)
			case "in-use":
				return cmp.Compare(b.Used, a.Used)
			case "free":
				return cmp.Compare(b.Free, a.Free)
			case "fail":
				return cmp.Compare(b.Fail, a.Fail)
			case "size":
				return cmp.Compare(b.Size, a.Size)
			}
			return cmp.Compare(b.Bytes(), a.Bytes())
		})
		var total int64
		for _, zone := range zones {
			total += zone.Bytes()
		}
		var count = len(zones)
		if limit > 0 && len(zones) > limit {
			zones = zones[:limit]
		}
		if args.Bool("json") {
			for _, zone := range zones {
				if err := c.JSON(zone.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		var rows = make([][]string, 0, len(zones))
		for _, zone := range zones {
			rows = append(rows, []string{zone.Name, systemMemoryCount(zone.Size), systemMemoryCount(zone.Limit),
				systemMemoryCount(zone.Used), systemMemoryCount(zone.Free), systemMemoryBytes(zone.Bytes()),
				systemMemoryCount(zone.Requests), systemMemoryCount(zone.Fail), systemMemoryCount(zone.Sleep)})
		}
		c.Table([]string{"ZONE", "SIZE", "LIMIT", "USED", "FREE", "MEMORY", "REQUESTS", "FAIL", "SLEEP"}, rows)
		c.Infof("%s held by %d zones", systemMemoryBytes(total), count)
		return nil
	}

	var types []diagnostics.MemoryMalloc
	for _, item := range stats.Malloc {
		if matches(item.Name) {
			types = append(types, item)
		}
	}
	slices.SortStableFunc(types, func(a, b diagnostics.MemoryMalloc) int {
		switch sortBy {
		case "name":
			return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		case "requests":
			return cmp.Compare(b.Requests, a.Requests)
		case "in-use":
			return cmp.Compare(b.InUse, a.InUse)
		}
		return cmp.Compare(b.Bytes, a.Bytes)
	})
	var total int64
	for _, item := range types {
		total += item.Bytes
	}
	var count = len(types)
	if limit > 0 && len(types) > limit {
		types = types[:limit]
	}
	if args.Bool("json") {
		for _, item := range types {
			if err := c.JSON(item.Raw); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(types))
	for _, item := range types {
		var sizes = make([]string, 0, len(item.Sizes))
		for _, size := range item.Sizes {
			sizes = append(sizes, strconv.FormatInt(size, 10))
		}
		rows = append(rows, []string{item.Name, systemMemoryCount(item.InUse), systemMemoryBytes(item.Bytes),
			systemMemoryCount(item.Requests), strings.Join(sizes, ",")})
	}
	c.Table([]string{"TYPE", "IN-USE", "MEMORY", "REQUESTS", "SIZES"}, rows)
	c.Infof("%s in use by %d malloc types", systemMemoryBytes(total), count)
	return nil
}

func systemMemoryCount(n int64) string {
	return strconv.FormatInt(n, 10)
}

// systemMemoryBytes formats bytes with binary units, e.g. "32.0 MiB"
func systemMemoryBytes(bytes int64) string {
	var units = []string{"B", "KiB", "MiB", "GiB", "TiB"}
	var value = float64(bytes)
	var unit = 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}
