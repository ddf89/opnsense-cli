package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The system status is the bell in the header of the web GUI (api/core/system/status, OPNsense\System\SystemStatus):
// notices of subsystems that need attention, like a full disk, firewall rules that failed to load or crash
// reports. Subsystems without a problem are left out. Notices that are scoped to a page of the GUI are only
// returned for that page and are not part of StatusNotices.

// Status codes of a notice (SystemStatusCode), lower is more severe
const (
	StatusCodeError   = -1
	StatusCodeWarning = 0
	StatusCodeNotice  = 1
)

// StatusNotice is one notice of the system status
type StatusNotice struct {
	// Subject is the name of the subsystem (diskspace, firewall, crashreporter, ...), dismiss_status takes it
	Subject string `json:"-"`
	Title   string `json:"title"`
	// StatusCode is StatusCodeError, StatusCodeWarning or StatusCodeNotice, Status its name (ERROR, WARNING, NOTICE)
	StatusCode int    `json:"statusCode"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	// Location is the GUI page that shows the details, empty for notices without one (they can not be dismissed)
	Location string `json:"location"`
	// Timestamp is the unix time the problem was noticed, 0 when unknown; Age renders it ("3 hours ago")
	Timestamp int64  `json:"-"`
	Age       string `json:"age"`
	// Persistent notices can not be dismissed, they stay until their cause is fixed
	Persistent bool `json:"persistent"`
	IsBanner   bool `json:"isBanner"`
	// Priority orders notices of the same status code, lower first
	Priority int `json:"priority"`
	// Raw is the notice as the API returned it
	Raw json.RawMessage `json:"-"`
}

// Dismissable returns whether OPNsense lets this notice be dismissed: not persistent and with a GUI location
func (n StatusNotice) Dismissable() bool {
	return !n.Persistent && n.Location != ""
}

func (n *StatusNotice) UnmarshalJSON(data []byte) error {
	type plain StatusNotice
	var decoded struct {
		plain
		Timestamp json.RawMessage `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*n = StatusNotice(decoded.plain)
	// an mtime (number), null when unknown; accept a numeric string as well
	var timestamp = strings.Trim(string(bytes.TrimSpace(decoded.Timestamp)), `"`)
	if timestamp != "" && timestamp != "null" {
		var seconds, err = strconv.ParseFloat(timestamp, 64)
		if err != nil {
			return fmt.Errorf("invalid timestamp %s of a status notice", decoded.Timestamp)
		}
		n.Timestamp = int64(seconds)
	}
	n.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// StatusNotices returns the pending notices in the order of the web GUI: most severe first, then by priority
func (opn *SystemApi) StatusNotices() ([]StatusNotice, error) {
	var endpoint = opn.powerEndpoint("status")
	var container struct {
		Metadata   json.RawMessage `json:"metadata"`
		Subsystems json.RawMessage `json:"subsystems"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(container.Metadata), []byte("{")) {
		return nil, fmt.Errorf("unexpected answer from %s: no metadata", endpoint)
	}
	var notices, err = statusDecodeNotices(container.Subsystems)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from %s: %w", endpoint, err)
	}
	return notices, nil
}

// statusDecodeNotices decodes the subsystems object keeping the order of OPNsense (a Go map would lose it).
// PHP encodes an empty list of subsystems as []
func statusDecodeNotices(raw json.RawMessage) ([]StatusNotice, error) {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil || len(list) != 0 {
			return nil, errors.New("subsystems is a non-empty list, want an object")
		}
		return nil, nil
	}

	var decoder = json.NewDecoder(bytes.NewReader(trimmed))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("subsystems is not an object")
	}
	var notices []StatusNotice
	for decoder.More() {
		var token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		var subject, _ = token.(string)
		var notice StatusNotice
		if err := decoder.Decode(&notice); err != nil {
			return nil, fmt.Errorf("subsystem %s: %w", subject, err)
		}
		notice.Subject = subject
		notices = append(notices, notice)
	}
	return notices, nil
}

// StatusDismiss dismisses the notice of subject (StatusNotice.Subject), like the dismiss button of the web GUI.
// Some subsystems clean up their cause: dismissing crashreporter deletes the crash reports and the PHP error log,
// firewall the message of the failed rules. OPNsense refuses persistent notices and those without a location
func (opn *SystemApi) StatusDismiss(subject string) error {
	if strings.TrimSpace(subject) == "" {
		return errors.New("no notice given to dismiss")
	}
	var container struct {
		Status string `json:"status"`
	}
	// must be POSTed with the subject, anything else answers {"status":"failed"}
	if err := opn.DoJSON("POST", opn.powerEndpoint("dismiss_status"), map[string]string{"subject": subject}, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("OPNsense did not dismiss the notice %s (status %q): it is unknown, gone already, persistent or "+
			"has no page this user may open", subject, container.Status)
	}
	return nil
}
