package unbound

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Query statistics of Reporting > Unbound DNS (api/unbound/overview/*, kept by Unbound in a DuckDB database
// when the general setting "stats" is enabled) and the unbound-control dumps of api/unbound/diagnostics/*

func (opn *UnboundApi) overviewEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("unbound", "overview", method)
}

func (opn *UnboundApi) diagnosticsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("unbound", "diagnostics", method)
}

// Number is a JSON number OPNsense sends as number or as string ("12.50", 0)
type Number string

func (n *Number) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) == nil {
		*n = Number(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("not a number: %s", data)
	}
	*n = Number(number.String())
	return nil
}

// Int returns the number as int64, 0 when it is none
func (n Number) Int() int64 {
	var value, err = strconv.ParseFloat(string(n), 64)
	if err != nil {
		return 0
	}
	return int64(value)
}

// Count is a number of queries and its share in percent
type Count struct {
	Total   Number `json:"total"`
	Percent Number `json:"pcnt"`
}

// DomainCount is a top (blocked) domain: number of queries, share in percent and, for blocked ones, the list
type DomainCount struct {
	Domain    string `json:"domain"`
	Total     Number `json:"total"`
	Percent   Number `json:"pcnt"`
	Blocklist string `json:"blocklist,omitempty"`
	Category  string `json:"category,omitempty"`
	// LatestPolicyUuid is the DNSBL policy that blocked the domain last
	LatestPolicyUuid string `json:"latest_policy_uuid,omitempty"`
}

// Totals are the query counters since StartTime (unix seconds) and the top queried and blocked domains
type Totals struct {
	// Available is false when there are no statistics (statistics disabled or nothing recorded yet)
	Available     bool
	Total         Number
	Passed        Number
	BlocklistSize Number
	Resolved      Count
	Blocked       Count
	Local         Count
	StartTime     Number
	// Top / TopBlocked are sorted by Total, descending
	Top        []DomainCount
	TopBlocked []DomainCount
}

// StatisticsEnabled tells whether Unbound records query statistics (general setting "stats")
func (opn *UnboundApi) StatisticsEnabled() (bool, error) {
	var answer struct {
		Enabled string `json:"enabled"`
	}
	if err := opn.DoJSON("GET", opn.overviewEndpoint("is_enabled"), nil, &answer); err != nil {
		return false, err
	}
	return answer.Enabled == "1", nil
}

// StatisticsTotals returns the counters and the top max queried and blocked domains
func (opn *UnboundApi) StatisticsTotals(top int) (Totals, error) {
	if top < 1 {
		return Totals{}, fmt.Errorf("top must be at least 1, got %d", top)
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", fmt.Sprintf("%s/%d", opn.overviewEndpoint("totals"), top), nil, &raw); err != nil {
		return Totals{}, err
	}
	// without statistics the script output is not parsed: []
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return Totals{}, nil
	}
	var answer struct {
		Total         Number       `json:"total"`
		Passed        Number       `json:"passed"`
		BlocklistSize Number       `json:"blocklist_size"`
		Resolved      Count        `json:"resolved"`
		Blocked       Count        `json:"blocked"`
		Local         Count        `json:"local"`
		StartTime     Number       `json:"start_time"`
		Top           domainCounts `json:"top"`
		TopBlocked    domainCounts `json:"top_blocked"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return Totals{}, fmt.Errorf("unexpected answer from unbound totals: %w", err)
	}
	return Totals{
		Available: true, Total: answer.Total, Passed: answer.Passed, BlocklistSize: answer.BlocklistSize,
		Resolved: answer.Resolved, Blocked: answer.Blocked, Local: answer.Local, StartTime: answer.StartTime,
		Top: sortedDomains(answer.Top), TopBlocked: sortedDomains(answer.TopBlocked),
	}, nil
}

// domainCounts is the domain map of the totals answer; PHP sends the empty map as [], which decodes to nil
type domainCounts map[string]DomainCount

func (d *domainCounts) UnmarshalJSON(data []byte) error {
	if trimmed := bytes.TrimSpace(data); bytes.HasPrefix(trimmed, []byte("[")) || bytes.Equal(trimmed, []byte("null")) {
		*d = nil
		return nil
	}
	return json.Unmarshal(data, (*map[string]DomainCount)(d))
}

// sortedDomains turns the domain map of the totals answer into a list sorted by count (descending), then name
func sortedDomains(domains domainCounts) []DomainCount {
	var result = make([]DomainCount, 0, len(domains))
	for domain, count := range domains {
		count.Domain = domain
		result = append(result, count)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Total.Int() != result[j].Total.Int() {
			return result[i].Total.Int() > result[j].Total.Int()
		}
		return result[i].Domain < result[j].Domain
	})
	return result
}

// Query is one logged DNS query, newest first
type Query struct {
	Time   Number `json:"time"` // unix seconds
	Client string `json:"client"`
	Family string `json:"family"`
	Type   string `json:"type"`
	Domain string `json:"domain"`
	// Action is Pass, Block or Drop; Source Recursion, Local, Local-data or Cache
	Action string `json:"action"`
	Source string `json:"source"`
	Rcode  string `json:"rcode"`
	// ResolveTimeMs is the resolve time in milliseconds
	ResolveTimeMs Number `json:"resolve_time_ms"`
	DnssecStatus  string `json:"dnssec_status"`
	Ttl           Number `json:"ttl"`
	Blocklist     string `json:"blocklist"`
	Category      string `json:"category"`
	Policy        string `json:"policy"`
	Uuid          string `json:"uuid"`
}

// StatisticsQueries returns the latest (up to 1000) queries where any column contains searchPhrase ("" for all)
func (opn *UnboundApi) StatisticsQueries(searchPhrase string) ([]Query, []json.RawMessage, error) {
	var raws, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.overviewEndpoint("search_queries"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var queries = make([]Query, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &queries[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected query from OPNsense: %w", err)
		}
	}
	return queries, raws, nil
}

// Interval are the query counters of one time interval starting at Start (unix seconds)
type Interval struct {
	Start    int64  `json:"start"`
	Total    Number `json:"total"`
	Passed   Number `json:"passed"`
	Blocked  Number `json:"blocked"`
	Dropped  Number `json:"dropped"`
	Resolved Number `json:"resolved"`
	Local    Number `json:"local"`
	Cached   Number `json:"cached"`
}

// StatisticsHistory returns the query counters of the last hours (1, 12 or 24) in intervals of 1 minute (1 hour)
// or 10 minutes, oldest first
func (opn *UnboundApi) StatisticsHistory(hours int) ([]Interval, error) {
	if hours != 1 && hours != 12 && hours != 24 {
		return nil, fmt.Errorf("hours must be 1, 12 or 24, got %d", hours)
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", fmt.Sprintf("%s/%d/0", opn.overviewEndpoint("rolling"), hours), nil, &raw); err != nil {
		return nil, err
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return nil, nil // no statistics
	}
	var answer map[string]Interval
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("unexpected answer from unbound rolling: %w", err)
	}
	var intervals = make([]Interval, 0, len(answer))
	for start, interval := range answer {
		var seconds, err = strconv.ParseFloat(start, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected interval start %q from unbound rolling", start)
		}
		interval.Start = int64(seconds)
		intervals = append(intervals, interval)
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].Start < intervals[j].Start })
	return intervals, nil
}

// StatisticsReset deletes the query statistics database and restarts Unbound
func (opn *UnboundApi) StatisticsReset() error {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.overviewEndpoint("reset"), struct{}{}, &answer); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(answer.Status), "ok") {
		return fmt.Errorf("resetting the unbound statistics failed: status %q", answer.Status)
	}
	return nil
}

// --- unbound-control

// Counters returns the unbound-control stats_noreset counters flattened to "total.num.queries" -> "18" (without
// the histogram)
func (opn *UnboundApi) Counters() (map[string]string, error) {
	var data map[string]json.RawMessage
	if err := opn.diagnostics("stats", &data); err != nil {
		return nil, err
	}
	var counters = map[string]string{}
	var walk func(prefix string, node map[string]json.RawMessage)
	walk = func(prefix string, node map[string]json.RawMessage) {
		for key, value := range node {
			var name = prefix + key
			if key == "__value__" {
				name = strings.TrimSuffix(prefix, ".")
			}
			var text string
			if json.Unmarshal(value, &text) == nil {
				counters[name] = text
				continue
			}
			var child map[string]json.RawMessage
			if json.Unmarshal(value, &child) == nil {
				walk(name+".", child)
			}
			// the histogram is a list, left out
		}
	}
	walk("", data)
	return counters, nil
}

// CacheEntry is a record of the DNS cache (dump_cache) or of the local data (list_local_data)
type CacheEntry struct {
	Name   string `json:"name"`
	Ttl    string `json:"ttl"`
	Class  string `json:"type"`
	Rrtype string `json:"rrtype"`
	Value  string `json:"value"`
}

// CacheDump returns the records in the DNS cache
func (opn *UnboundApi) CacheDump() ([]CacheEntry, error) {
	var rows []struct {
		Host string `json:"host"`
		CacheEntry
	}
	if err := opn.diagnostics("dumpcache", &rows); err != nil {
		return nil, err
	}
	var entries = make([]CacheEntry, len(rows))
	for i, row := range rows {
		entries[i] = row.CacheEntry
		entries[i].Name = row.Host
	}
	return entries, nil
}

// LocalData returns the local data (host overrides, PTR records, the default local zones' records)
func (opn *UnboundApi) LocalData() ([]CacheEntry, error) {
	var entries []CacheEntry
	return entries, opn.diagnostics("listlocaldata", &entries)
}

// LocalZone is a local zone and its type (static, transparent, ...)
type LocalZone struct {
	Zone string `json:"zone"`
	Type string `json:"type"`
}

// LocalZones returns the local zones
func (opn *UnboundApi) LocalZones() ([]LocalZone, error) {
	var zones []LocalZone
	return zones, opn.diagnostics("listlocalzones", &zones)
}

// InsecureZones returns the domains DNSSEC validation is disabled for
func (opn *UnboundApi) InsecureZones() ([]string, error) {
	var zones []string
	if err := opn.diagnostics("listinsecure", &zones); err != nil {
		return nil, err
	}
	return coreapi.Filter(zones, func(zone string) bool { return strings.TrimSpace(zone) != "" }), nil
}

// InfraEntry is an entry of the infrastructure cache: an upstream server address, the zone and its statistics
// (rtt, rto, ping, ttl, edns, lame, ...)
type InfraEntry struct {
	Ip    string
	Host  string
	Lame  bool
	Stats map[string]string
}

// InfraDump returns the infrastructure cache (dump_infra)
func (opn *UnboundApi) InfraDump() ([]InfraEntry, error) {
	var rows []map[string]any
	if err := opn.diagnostics("dumpinfra", &rows); err != nil {
		return nil, err
	}
	var entries = make([]InfraEntry, 0, len(rows))
	for _, row := range rows {
		var entry = InfraEntry{Stats: map[string]string{}}
		for key, value := range row {
			switch key {
			case "ip":
				entry.Ip = fmt.Sprint(value)
			case "host":
				entry.Host = fmt.Sprint(value)
			case "lame":
				entry.Lame = value == true
			default:
				entry.Stats[key] = fmt.Sprint(value)
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// diagnostics GETs api/unbound/diagnostics/<method>: {"status":"ok","data":...}, "failed" when Unbound does not run
func (opn *UnboundApi) diagnostics(method string, out any) error {
	var answer struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := opn.DoJSON("GET", opn.diagnosticsEndpoint(method), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("unbound %s failed (status %q), is Unbound running?", method, answer.Status)
	}
	if err := json.Unmarshal(answer.Data, out); err != nil {
		return fmt.Errorf("unexpected answer from unbound %s: %w", method, err)
	}
	return nil
}
