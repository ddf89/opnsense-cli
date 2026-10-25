package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Insight of Reporting > Insight, the aggregated local NetFlow data (api/diagnostics/networkinsight,
// OPNsense\Diagnostics\Api\NetworkinsightController, scripts/netflow/get_top_usage.py, get_timeseries.py,
// export_details.py). Times are unix timestamps in seconds; without local collection (/tool/netflow) all
// answers are empty:
//   - getMetadata: {"last_sync":1761400000,"aggregators":{"FlowInterfaceTotals":{"resolutions":[30,300,3600,86400]},
//     "FlowDstPortTotals":{...},"FlowSourceAddrTotals":{...},"FlowSourceAddrDetails":{"resolutions":[86400]}}}
//   - getInterfaces: {"vtnet0":"lan","vtnet1":"wan"} device to description (or key); getProtocols {"6":"tcp"} and
//     getServices {"443":"https"} from /etc/protocols and /etc/services
//   - top/<provider>/<from>/<to>/<fields>/<octets|packets>/<max hits>?filter_field=if,dst_port&filter_value=vtnet0,443:
//     [{"dst_port":443,"protocol":6,"total":1234,"last_seen":1761400000,"label":"https (tcp)","last_seen_str":"..."}]
//     grouped by the comma separated fields, sorted by total; rows beyond max hits are summed into one more row with
//     empty fields. Filters on fields the provider does not have are ignored silently. The provider picks its
//     resolution from the start time (the finest one still holding it)
//   - timeserie/<provider>/<measure>/<from>/<to>/<resolution>/<fields>: [{"key":"vtnet0,in","values":[[ms,value]],
//     "interface":"lan","direction":"in"}] (interface and direction only for FlowInterfaceTotals); measure is
//     octets, packets, octets_ps, packets_ps or bps
//   - export/<provider>/<from>/<to>/<resolution>: CSV (comma separated, a header line, local times) as
//     application/octet-stream, empty lines without data or for an unknown provider / resolution

// The insight providers (aggregators) and their fields
const (
	InsightInterfaceTotals   = "FlowInterfaceTotals"   // if, direction
	InsightDstPortTotals     = "FlowDstPortTotals"     // if, protocol, dst_port
	InsightSourceAddrTotals  = "FlowSourceAddrTotals"  // if, src_addr, direction
	InsightSourceAddrDetails = "FlowSourceAddrDetails" // if, direction, src_addr, dst_addr, service_port, protocol
)

// InsightMetadata describes the aggregation
type InsightMetadata struct {
	LastSync time.Time // zero when the aggregator never ran
	// Resolutions are the sample resolutions in seconds per provider
	Resolutions map[string][]int
	Raw         json.RawMessage
}

// InsightFilter restricts a top query to rows whose Field equals Value
type InsightFilter struct {
	Field string
	Value string
}

// InsightTopQuery is a top usage query
type InsightTopQuery struct {
	Provider string
	From, To time.Time
	Fields   []string // group by these fields
	Measure  string   // octets or packets
	MaxHits  int
	Filters  []InsightFilter
}

// InsightTopRow is one group of a top query
type InsightTopRow struct {
	// Fields are the values of the query fields, as text (ports and protocols are numbers)
	Fields   map[string]string
	Total    float64
	LastSeen time.Time // zero for the "rest" row
	Label    string    // service name of port queries, e.g. "https (tcp)"
	// Rest is the row summing up the groups beyond MaxHits
	Rest bool
	Raw  json.RawMessage
}

// InsightSeries is one time series of a timeserie query
type InsightSeries struct {
	Key       string // the field values, e.g. "vtnet0,in"
	Interface string // FlowInterfaceTotals: the interface description
	Direction string // FlowInterfaceTotals: in or out
	Points    []InsightPoint
}

// InsightPoint is one value of a series
type InsightPoint struct {
	Time  time.Time
	Value float64
}

func (opn *DiagnosticsApi) insightEndpoint(method string, params ...string) string {
	var endpoint = opn.endpoint("networkinsight", method)
	for _, param := range params {
		endpoint += "/" + url.PathEscape(param)
	}
	return endpoint
}

// insightFields joins field names for a path element, the commas stay unescaped like the GUI sends them
func insightFields(fields []string) string {
	var escaped = make([]string, len(fields))
	for i, field := range fields {
		escaped[i] = url.PathEscape(field)
	}
	return strings.Join(escaped, ",")
}

func insightUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// insightMap GETs an endpoint answering a flat string map ([] when empty)
func (opn *DiagnosticsApi) insightMap(method string) (map[string]string, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.insightEndpoint(method), nil, &raw); err != nil {
		return nil, err
	}
	var values = map[string]string{}
	if err := healthDecodeObject(raw, &values); err != nil {
		return nil, fmt.Errorf("unexpected answer from networkinsight %s: %s", method, healthShorten(raw))
	}
	return values, nil
}

// InsightInterfaces maps the interface devices of the flow data (vtnet0) to their description or key (lan)
func (opn *DiagnosticsApi) InsightInterfaces() (map[string]string, error) {
	return opn.insightMap("getInterfaces")
}

// InsightProtocols maps IP protocol numbers to names (6 = tcp)
func (opn *DiagnosticsApi) InsightProtocols() (map[string]string, error) {
	return opn.insightMap("getProtocols")
}

// InsightServices maps port numbers to service names (443 = https)
func (opn *DiagnosticsApi) InsightServices() (map[string]string, error) {
	return opn.insightMap("getServices")
}

// InsightMetadata returns the last aggregation time and the resolutions of the providers
func (opn *DiagnosticsApi) InsightMetadata() (*InsightMetadata, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.insightEndpoint("getMetadata"), nil, &raw); err != nil {
		return nil, err
	}
	var answer struct {
		LastSync    *float64 `json:"last_sync"`
		Aggregators map[string]struct {
			Resolutions []int `json:"resolutions"`
		} `json:"aggregators"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Aggregators == nil {
		return nil, fmt.Errorf("unexpected answer from networkinsight getMetadata: %s", healthShorten(raw))
	}
	var metadata = &InsightMetadata{Resolutions: map[string][]int{}, Raw: raw}
	if answer.LastSync != nil && *answer.LastSync > 0 {
		metadata.LastSync = time.Unix(int64(*answer.LastSync), 0)
	}
	for provider, aggregator := range answer.Aggregators {
		var resolutions = append([]int(nil), aggregator.Resolutions...)
		sort.Ints(resolutions)
		metadata.Resolutions[provider] = resolutions
	}
	return metadata, nil
}

// insightText renders a JSON field value as text: strings as they are, numbers without exponent, null as ""
func insightText(raw json.RawMessage) string {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(trimmed, &text) == nil {
		return text
	}
	var number float64
	if json.Unmarshal(trimmed, &number) == nil {
		return strconv.FormatFloat(number, 'f', -1, 64)
	}
	return string(trimmed)
}

// InsightTop runs a top usage query
func (opn *DiagnosticsApi) InsightTop(query InsightTopQuery) ([]InsightTopRow, error) {
	if len(query.Fields) == 0 {
		return nil, fmt.Errorf("no fields to group by")
	}
	var measure = query.Measure
	if measure == "" {
		measure = "octets"
	}
	var endpoint = opn.insightEndpoint("top", query.Provider, insightUnix(query.From), insightUnix(query.To)) + "/" +
		insightFields(query.Fields) + "/" + url.PathEscape(measure) + "/" + strconv.Itoa(query.MaxHits)
	if len(query.Filters) > 0 {
		var fields, values []string
		for _, filter := range query.Filters {
			if strings.Contains(filter.Field, ",") || strings.Contains(filter.Value, ",") {
				return nil, fmt.Errorf("filter %s=%s: values can not contain a comma", filter.Field, filter.Value)
			}
			fields = append(fields, filter.Field)
			values = append(values, filter.Value)
		}
		endpoint += "?" + url.Values{"filter_field": {strings.Join(fields, ",")}, "filter_value": {strings.Join(values, ",")}}.Encode()
	}

	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if err := healthDecodeList(raw, &items); err != nil {
		return nil, fmt.Errorf("unexpected answer from networkinsight top: %s", healthShorten(raw))
	}
	var rows = make([]InsightTopRow, 0, len(items))
	for _, item := range items {
		var values = map[string]json.RawMessage{}
		if err := json.Unmarshal(item, &values); err != nil {
			return nil, fmt.Errorf("unexpected row from networkinsight top: %s", healthShorten(item))
		}
		var row = InsightTopRow{Fields: map[string]string{}, Label: insightText(values["label"]), Raw: item}
		var total, err = strconv.ParseFloat(insightText(values["total"]), 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected total in networkinsight top: %s", healthShorten(item))
		}
		row.Total = total
		if seen, err := strconv.ParseFloat(insightText(values["last_seen"]), 64); err == nil && seen > 0 {
			row.LastSeen = time.Unix(int64(seen), 0)
		}
		row.Rest = true
		for _, field := range query.Fields {
			row.Fields[field] = insightText(values[field])
			if row.Fields[field] != "" {
				row.Rest = false
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// InsightTimeseries returns the time series of a provider grouped by fields, measure is octets, packets,
// octets_ps, packets_ps or bps, resolution one of the provider's resolutions in seconds
func (opn *DiagnosticsApi) InsightTimeseries(provider string, measure string, from time.Time, to time.Time, resolution int,
	fields []string) ([]InsightSeries, error) {
	var raw json.RawMessage
	var endpoint = opn.insightEndpoint("timeserie", provider, measure, insightUnix(from), insightUnix(to),
		strconv.Itoa(resolution)) + "/" + insightFields(fields)
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return nil, err
	}
	var items []struct {
		Key       string       `json:"key"`
		Values    [][]*float64 `json:"values"`
		Interface string       `json:"interface"`
		Direction string       `json:"direction"`
	}
	if err := healthDecodeList(raw, &items); err != nil {
		return nil, fmt.Errorf("unexpected answer from networkinsight timeserie: %s", healthShorten(raw))
	}
	var result = make([]InsightSeries, 0, len(items))
	for _, item := range items {
		var series = InsightSeries{Key: item.Key, Interface: item.Interface, Direction: item.Direction}
		for _, value := range item.Values {
			if len(value) != 2 || value[0] == nil {
				return nil, fmt.Errorf("unexpected value of %s in networkinsight timeserie: %v", item.Key, value)
			}
			var point = InsightPoint{Time: time.UnixMilli(int64(*value[0]))}
			if value[1] != nil {
				point.Value = *value[1]
			}
			series.Points = append(series.Points, point)
		}
		result = append(result, series)
	}
	return result, nil
}

// InsightExportCsv returns the detail data of a provider at a resolution (seconds) as CSV, nil when there is none
func (opn *DiagnosticsApi) InsightExportCsv(provider string, from time.Time, to time.Time, resolution int) ([]byte, error) {
	var content, err = healthDownload(opn.OPNsense, opn.insightEndpoint("export", provider, insightUnix(from), insightUnix(to),
		strconv.Itoa(resolution)))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	return content, nil
}
