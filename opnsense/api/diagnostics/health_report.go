package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// System health of Reporting > Health, the RRD graphs (api/diagnostics/systemhealth,
// OPNsense\Diagnostics\Api\SystemhealthController, scripts/health/listReports.py and fetchData.py):
//   - getRRDlist: {"data":{"system":["memory","processor"],"traffic":["lan","wan"]},"files":[{"key":"system-processor",
//     "filename":"system-processor.rrd"},{"key":"wan-traffic",...}],"interfaces":{"lan":{"descr":"LAN"}},"result":"ok"},
//     data and files are [] when there are no RRD files (collection disabled or not run yet). The file key is the
//     file name without .rrd, the report name getSystemHealth wants is <item>-<topic> (system-processor =
//     topic system, item processor; wan-traffic = topic traffic, item wan; a key without "-" = topic services)
//   - getSystemHealth/<item>-<topic>/<detail>: {"step":60,"lastupdate":1761400000,"set":{"count":2,"step_size":60,
//     "data":[{"key":"user","values":[[1761399940000,1.5],[1761400000000,null]]},...]},"title":"...","y-axis_label":"..."}
//     with timestamps in ms and null for unknown values. detail is the index of the AVERAGE archive (the GUI offers
//     0 = 1 minute, 1 = 5 minutes, 2 = 1 hour, 3 = 1 day), the whole archive is returned (no time range). An
//     unknown report answers {"set":[],"title":"error","y-axis_label":""}, a missing archive an empty set
//   - exportAsCSV/<item>-<topic>/<detail>: the same data as ";" separated CSV (iso_time and one column per data
//     source), an empty body without data or for unknown reports
//   - get / set: {"systemhealth":{"enabled":"1"}}, whether the RRD data is collected (by a cron job)
//   - reconfigure (POST): applies enabled, reconfigures the gateway monitors and restarts cron, {"status":"OK"}
//   - del_rrd[/<file key>] (POST): deletes the RRD data of one report or of all, {"status":"OK"}
//
// Actions must be POSTed, a GET answers {"status":"failed"} without doing anything

// HealthReport is one RRD report of the system health
type HealthReport struct {
	// Metric is the report name of HealthFetch: <item>-<topic>, e.g. processor-system, wan-traffic
	Metric string
	Topic  string // e.g. system, traffic, packets, quality, services
	Item   string // e.g. processor, wan
	// Key is the RRD file name without .rrd (e.g. system-processor), used by HealthReset
	Key      string
	Filename string
	// Description of an interface report (topic traffic or packets), the item otherwise
	Description string
}

// HealthResolution is one archive of the RRD files as offered by the GUI
type HealthResolution struct {
	Name   string // 1m, 5m, 1h, 1d
	Detail int    // the archive index of getSystemHealth
	Step   time.Duration
}

// HealthResolutions are the archives of the GUI (Granularity), finest first
var HealthResolutions = []HealthResolution{
	{"1m", 0, time.Minute},
	{"5m", 1, 5 * time.Minute},
	{"1h", 2, time.Hour},
	{"1d", 3, 24 * time.Hour},
}

// HealthSeries is the data of one report at one resolution, Rows are sorted by time
type HealthSeries struct {
	Metric     string
	Title      string
	YAxisLabel string
	StepSize   int // seconds between two rows
	LastUpdate time.Time
	// Columns are the data sources (e.g. "user", "system"), every row has one value per column
	Columns []string
	Rows    []HealthRow
	Raw     json.RawMessage
}

// HealthRow is one point in time, Values are NaN where the RRD has no value
type HealthRow struct {
	Time   time.Time
	Values []float64
}

func (opn *DiagnosticsApi) healthEndpoint(method string, params ...string) string {
	var endpoint = opn.endpoint("systemhealth", method)
	for _, param := range params {
		endpoint += "/" + url.PathEscape(param)
	}
	return endpoint
}

// healthSplitKey derives topic and item from an RRD file key like scripts/health/listReports.py does
func healthSplitKey(key string) (topic string, item string) {
	var parts = strings.Split(key, "-")
	switch {
	case parts[0] == "system" && len(parts) > 1:
		return "system", strings.Join(parts[1:], "-")
	case len(parts) == 1:
		return "services", key
	default:
		return parts[len(parts)-1], strings.Join(parts[:len(parts)-1], "-")
	}
}

// HealthReports lists the available reports in the order of the API (by file key) and returns the raw answer
func (opn *DiagnosticsApi) HealthReports() ([]HealthReport, json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.healthEndpoint("getRRDlist"), nil, &raw); err != nil {
		return nil, nil, err
	}
	var answer struct {
		Files      json.RawMessage `json:"files"`
		Interfaces json.RawMessage `json:"interfaces"`
		Result     string          `json:"result"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Result != "ok" {
		return nil, nil, fmt.Errorf("unexpected answer from getRRDlist: %s", healthShorten(raw))
	}
	var files []struct {
		Key      string `json:"key"`
		Filename string `json:"filename"`
	}
	if err := healthDecodeList(answer.Files, &files); err != nil {
		return nil, nil, fmt.Errorf("unexpected files in getRRDlist: %w", err)
	}
	var interfaces = map[string]struct {
		Descr string `json:"descr"`
	}{}
	if err := healthDecodeObject(answer.Interfaces, &interfaces); err != nil {
		return nil, nil, fmt.Errorf("unexpected interfaces in getRRDlist: %w", err)
	}

	var reports = make([]HealthReport, 0, len(files))
	for _, file := range files {
		var topic, item = healthSplitKey(file.Key)
		var report = HealthReport{Metric: item + "-" + topic, Topic: topic, Item: item, Key: file.Key,
			Filename: file.Filename, Description: item}
		if topic == "traffic" || topic == "packets" {
			if intf, found := interfaces[item]; found && intf.Descr != "" {
				report.Description = intf.Descr
			}
		}
		reports = append(reports, report)
	}
	return reports, raw, nil
}

// HealthFetch returns the data of a report (HealthReport.Metric) at the archive detail (HealthResolution.Detail).
// An unknown report is a *NotFoundError, a missing archive an empty series
func (opn *DiagnosticsApi) HealthFetch(metric string, detail int) (*HealthSeries, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.healthEndpoint("getSystemHealth", metric, strconv.Itoa(detail)), nil, &raw); err != nil {
		return nil, err
	}
	var answer struct {
		Title      string          `json:"title"`
		YAxisLabel string          `json:"y-axis_label"`
		LastUpdate int64           `json:"lastupdate"`
		Set        json.RawMessage `json:"set"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("unexpected answer from getSystemHealth: %s", healthShorten(raw))
	}
	var set struct {
		StepSize int `json:"step_size"`
		Data     []struct {
			Key    string       `json:"key"`
			Values [][]*float64 `json:"values"`
		} `json:"data"`
	}
	if trimmed := bytes.TrimSpace(answer.Set); len(trimmed) == 0 || trimmed[0] == '[' {
		// {"set":[],"title":"error"}: the report does not exist
		return nil, &coreapi.NotFoundError{Name: "health report " + metric}
	}
	if err := json.Unmarshal(answer.Set, &set); err != nil {
		return nil, fmt.Errorf("unexpected set in getSystemHealth: %w", err)
	}

	var series = &HealthSeries{Metric: metric, Title: answer.Title, YAxisLabel: answer.YAxisLabel, StepSize: set.StepSize, Raw: raw}
	if answer.LastUpdate > 0 {
		series.LastUpdate = time.Unix(answer.LastUpdate, 0)
	}
	// the data sources may start at different times (leading unknown values are left out), merge them by time
	var byTime = map[int64][]float64{}
	for column, source := range set.Data {
		series.Columns = append(series.Columns, source.Key)
		for _, value := range source.Values {
			if len(value) != 2 || value[0] == nil {
				return nil, fmt.Errorf("unexpected value of %s in getSystemHealth: %v", source.Key, value)
			}
			var ms = int64(*value[0])
			var row, found = byTime[ms]
			if !found {
				row = make([]float64, len(set.Data))
				for i := range row {
					row[i] = math.NaN()
				}
				byTime[ms] = row
			}
			if value[1] != nil {
				row[column] = *value[1]
			}
		}
	}
	var times = make([]int64, 0, len(byTime))
	for ms := range byTime {
		times = append(times, ms)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	for _, ms := range times {
		series.Rows = append(series.Rows, HealthRow{Time: time.UnixMilli(ms), Values: byTime[ms]})
	}
	return series, nil
}

// HealthExportCsv returns the CSV export of a report (";" separated, iso_time first), nil when there is no data
// (OPNsense answers unknown reports the same way)
func (opn *DiagnosticsApi) HealthExportCsv(metric string, detail int) ([]byte, error) {
	var content, err = healthDownload(opn.OPNsense, opn.healthEndpoint("exportAsCSV", metric, strconv.Itoa(detail)))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	return content, nil
}

// HealthSettings returns whether the RRD data is collected, and the raw answer
func (opn *DiagnosticsApi) HealthSettings() (bool, json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.healthEndpoint("get"), nil, &raw); err != nil {
		return false, nil, err
	}
	var answer struct {
		Systemhealth *struct {
			Enabled string `json:"enabled"`
		} `json:"systemhealth"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Systemhealth == nil {
		return false, nil, fmt.Errorf("unexpected answer from systemhealth get: %s", healthShorten(raw))
	}
	return answer.Systemhealth.Enabled == "1", raw, nil
}

// HealthSetEnabled saves whether the RRD data is collected, HealthReconfigure applies it
func (opn *DiagnosticsApi) HealthSetEnabled(enabled bool) error {
	var flag = "0"
	if enabled {
		flag = "1"
	}
	var _, err = opn.Mutate(opn.healthEndpoint("set"), map[string]any{"systemhealth": map[string]string{"enabled": flag}})
	return err
}

// HealthReconfigure applies the settings: it reconfigures the gateway monitors and restarts cron
func (opn *DiagnosticsApi) HealthReconfigure() error {
	return healthPostStatus(opn.OPNsense, opn.healthEndpoint("reconfigure"), "system health reconfigure")
}

// HealthReset deletes the collected data of one report (by HealthReport.Key), of all reports when key is ""
func (opn *DiagnosticsApi) HealthReset(key string) error {
	var endpoint = opn.healthEndpoint("del_rrd")
	if key != "" {
		endpoint = opn.healthEndpoint("del_rrd", key)
	}
	return healthPostStatus(opn.OPNsense, endpoint, "deleting the RRD data")
}

// healthPostStatus POSTs an action answering {"status":"OK"} (also "ok", or the output of a script ending in OK)
func healthPostStatus(opn *coreapi.OPNsense, endpoint string, what string) error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		var status = strings.TrimSpace(result.Status)
		if status == "" {
			status = "no status given"
		}
		return fmt.Errorf("%s failed: %s", what, status)
	}
	return nil
}

// healthDownload GETs a non JSON download (CSV), a JSON error answer or a non 200 status is an error
func healthDownload(opn *coreapi.OPNsense, endpoint string) ([]byte, error) {
	var request, err = http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/csv, application/octet-stream, application/json")
	response, err := opn.Send(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var mediaType, _, _ = mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaType == "application/json" {
		var container struct {
			Message      string `json:"message"`
			ErrorMessage string `json:"errorMessage"`
		}
		var message = strings.TrimSpace(string(content))
		if json.Unmarshal(content, &container) == nil {
			if container.Message != "" {
				message = container.Message
			} else if container.ErrorMessage != "" {
				message = container.ErrorMessage
			}
		}
		if response.StatusCode != http.StatusOK {
			return nil, &coreapi.HttpError{StatusCode: response.StatusCode, Message: message}
		}
		return nil, fmt.Errorf("expected CSV from %s, got: %s", endpoint, healthShorten([]byte(message)))
	}
	return content, nil
}

// healthDecodeList decodes a JSON list, null and {} (an empty PHP array) are empty lists
func healthDecodeList[T any](raw json.RawMessage, out *[]T) error {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == "{}" {
		*out = nil
		return nil
	}
	return json.Unmarshal(trimmed, out)
}

// healthDecodeObject decodes a JSON object, null and [] (an empty PHP array) are empty objects
func healthDecodeObject(raw json.RawMessage, out any) error {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == "[]" {
		return nil
	}
	return json.Unmarshal(trimmed, out)
}

// healthShorten keeps error messages with unexpected answers readable
func healthShorten(raw []byte) string {
	var text = strings.TrimSpace(string(raw))
	if len(text) > 200 {
		return text[:200] + "..."
	}
	return text
}
