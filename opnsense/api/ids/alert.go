package ids

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Alert is an alert of the Suricata eve log (api/ids/service/query_alerts). The log is read from the end, so the
// newest alert comes first. An alert is identified by its position in the log file and the log's id
type Alert struct {
	Timestamp string
	// Signature is the message of the rule that matched, Sid its signature id
	Signature string
	Sid       int64
	// Action is what Suricata did: allowed or blocked
	Action   string
	Proto    string
	SrcIp    string
	SrcPort  string
	DestIp   string
	DestPort string
	// InIface is the device (like vtnet1, "^" marks the host stack side in netmap mode)
	InIface string
	// FilePos is the byte position in the log file, FileId the log ("" for the current one, else its sequence)
	FilePos int64
	FileId  string
	// Raw is the alert as the API returned it (the eve record, with alert flattened to the signature)
	Raw json.RawMessage
}

func (a *Alert) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var filepos, err = strconv.ParseInt(rawText(raw["filepos"]), 10, 64)
	if err != nil {
		return fmt.Errorf("alert without file position: %s", raw["filepos"])
	}
	var sid, _ = strconv.ParseInt(rawText(raw["alert_sid"]), 10, 64)
	*a = Alert{
		Timestamp: rawText(raw["timestamp"]), Signature: rawText(raw["alert"]), Sid: sid,
		Action: rawText(raw["alert_action"]), Proto: rawText(raw["proto"]),
		SrcIp: rawText(raw["src_ip"]), SrcPort: rawText(raw["src_port"]),
		DestIp: rawText(raw["dest_ip"]), DestPort: rawText(raw["dest_port"]),
		InIface: strings.TrimSpace(rawText(raw["in_iface"])),
		FilePos: filepos, FileId: rawText(raw["fileid"]),
		Raw: append(json.RawMessage(nil), data...),
	}
	return nil
}

// AlertQuery selects alerts of one log
type AlertQuery struct {
	// Search is a substring match over the signature, action, source and destination address
	Search string
	// LogId selects an older log by its sequence (see AlertLogs), "" for the current log
	LogId string
	// Limit is the page size (1 or more, OPNsense would answer all alerts for 0), Page counts from 1
	Limit int
	Page  int
}

// AlertPage is one page of alerts
type AlertPage struct {
	Alerts []Alert
	// Total is the number of matching alerts on all pages, Origin the log file name (like eve.json)
	Total  int
	Origin string
}

// AlertValidateLogId accepts "" (the current log) or a log sequence number
func AlertValidateLogId(id string) error {
	if id == "" {
		return nil
	}
	if number, err := strconv.Atoi(id); err != nil || number < 0 {
		return fmt.Errorf("invalid alert log %q, use the sequence number of an older log", id)
	}
	return nil
}

// AlertSearch returns one page of the alerts matching query, newest first
func (opn *IdsApi) AlertSearch(query AlertQuery) (AlertPage, error) {
	if query.Limit < 1 {
		return AlertPage{}, errors.New("the page size must be at least 1")
	}
	if err := AlertValidateLogId(query.LogId); err != nil {
		return AlertPage{}, err
	}
	if err := RuleValidateFilter(query.Search); err != nil {
		return AlertPage{}, err
	}
	var body = map[string]any{"current": max(query.Page, 1), "rowCount": query.Limit, "searchPhrase": query.Search}
	if query.LogId != "" {
		body["fileid"] = query.LogId
	}
	var answer struct {
		Rows   []Alert `json:"rows"`
		Total  int     `json:"total"`
		Origin string  `json:"origin"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", "query_alerts"), body, &answer); err != nil {
		return AlertPage{}, err
	}
	return AlertPage{Alerts: answer.Rows, Total: answer.Total, Origin: answer.Origin}, nil
}

// AlertGet returns the alert at this position of the log (logId "" for the current one) or a *NotFoundError
func (opn *IdsApi) AlertGet(filepos int64, logId string) (Alert, error) {
	if filepos < 0 {
		return Alert{}, fmt.Errorf("invalid alert position %d", filepos)
	}
	if err := AlertValidateLogId(logId); err != nil {
		return Alert{}, err
	}
	var params = []string{strconv.FormatInt(filepos, 10)}
	if logId != "" {
		params = append(params, logId)
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("service", "get_alert_info", params...), nil, &raw); err != nil {
		return Alert{}, err
	}
	var name = fmt.Sprintf("alert at position %d", filepos)
	if logId != "" {
		name += " of log " + logId
	}
	if isEmptyAnswer(raw) {
		return Alert{}, &coreapi.NotFoundError{Name: name}
	}
	var alert Alert
	if err := json.Unmarshal(raw, &alert); err != nil {
		return Alert{}, fmt.Errorf("unexpected alert from OPNsense: %w", err)
	}
	// get_alert_info matches the position as a prefix ("12" finds an alert at 1250 too), so check it
	if alert.FilePos != filepos {
		return Alert{}, &coreapi.NotFoundError{Name: name}
	}
	return alert, nil
}

// AlertLog is one alert log file (the current eve.json and its rotated predecessors)
type AlertLog struct {
	Filename string `json:"filename"`
	// Modified is the time of the newest record like "2026/10/25 15:38"
	Modified string `json:"modified"`
	Size     int64  `json:"size"`
	// Sequence is the log id of rotated logs (eve.json.<sequence>), nil for the current log
	Sequence *int `json:"sequence"`
}

// Id returns the log id for AlertQuery.LogId: "" for the current log, else the sequence
func (l AlertLog) Id() string {
	if l.Sequence == nil {
		return ""
	}
	return strconv.Itoa(*l.Sequence)
}

// AlertLogs lists the alert logs, the current one first
func (opn *IdsApi) AlertLogs() ([]AlertLog, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("service", "get_alert_logs"), nil, &raw); err != nil {
		return nil, err
	}
	var logs []AlertLog
	if isEmptyAnswer(raw) {
		return logs, nil
	}
	if err := json.Unmarshal(raw, &logs); err != nil {
		return nil, fmt.Errorf("unexpected alert logs: %w", err)
	}
	return logs, nil
}

// AlertLogRemove deletes a rotated alert log, or empties the current one (eve.json). The file name must be one of
// AlertLogs, OPNsense answers "ok" for any name
func (opn *IdsApi) AlertLogRemove(filename string) error {
	var logs, err = opn.AlertLogs()
	if err != nil {
		return err
	}
	var found = false
	for _, log := range logs {
		found = found || log.Filename == filename
	}
	if !found {
		return &coreapi.NotFoundError{Name: "alert log " + filename}
	}
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", "drop_alert_log"), map[string]string{"filename": filename}, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("drop_alert_log failed: status %q", answer.Status)
	}
	return nil
}
