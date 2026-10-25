package monit

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
)

var statusTags = regexp.MustCompile(`<[^>]*>`)

// statusPlain turns the HTML of the status page into text: tags removed, entities decoded
func statusPlain(text string) string {
	return strings.Trim(html.UnescapeString(statusTags.ReplaceAllString(text, "")), "\n")
}

// StatusText returns the Monit status report as text (api/monit/status/get/text, like "monit status"). When Monit
// is not running the error carries OPNsense's explanation
func (opn *MonitApi) StatusText() (string, error) {
	var answer struct {
		Result string `json:"result"`
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("status", "get", "text"), nil, &answer); err != nil {
		return "", err
	}
	var text = statusPlain(answer.Status)
	if answer.Result != "ok" {
		return "", fmt.Errorf("monit status failed: %s", strings.Join(strings.Fields(text), " "))
	}
	return text, nil
}

// StatusXml returns the Monit status as the JSON form OPNsense makes of Monit's XML status (api/monit/status/get/xml):
// {"server":{...},"platform":{...},"service":[{"@attributes":{"type":...},"name":...,"status":...},...]}
func (opn *MonitApi) StatusXml() (json.RawMessage, error) {
	var answer struct {
		Result string          `json:"result"`
		Status json.RawMessage `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("status", "get", "xml"), nil, &answer); err != nil {
		return nil, err
	}
	if answer.Result != "ok" {
		var text string
		_ = json.Unmarshal(answer.Status, &text)
		return nil, fmt.Errorf("monit status failed: %s", strings.Join(strings.Fields(statusPlain(text)), " "))
	}
	return answer.Status, nil
}

// Daemon states of DaemonStatus
const (
	DaemonRunning  = "running"
	DaemonStopped  = "stopped"
	DaemonDisabled = "disabled"
)

// DaemonStatus returns the state of the Monit daemon (api/monit/service/status): running, stopped (enabled but not
// running), disabled or unknown
func (opn *MonitApi) DaemonStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	return answer.Status, nil
}

// daemonAction POSTs service/<action>: start, stop and restart answer {"response":"OK"}, reconfigure
// {"status":"ok"} or {"status":"failed","status_msg":"..."}
func (opn *MonitApi) daemonAction(action string) error {
	var answer struct {
		Response  any    `json:"response"`
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("service", action), struct{}{}, &answer); err != nil {
		return err
	}
	var result = strings.TrimSpace(answer.Status)
	if text, ok := answer.Response.(string); ok && result == "" {
		result = strings.TrimSpace(text)
	}
	if !strings.EqualFold(result, "ok") {
		var reason = answer.StatusMsg
		if reason == "" {
			reason = result
		}
		if reason == "" {
			reason = "no status given"
		}
		return fmt.Errorf("monit %s failed: %s", action, reason)
	}
	return nil
}

// DaemonStart starts Monit
func (opn *MonitApi) DaemonStart() error { return opn.daemonAction("start") }

// DaemonStop stops Monit
func (opn *MonitApi) DaemonStop() error { return opn.daemonAction("stop") }

// DaemonRestart restarts Monit
func (opn *MonitApi) DaemonRestart() error { return opn.daemonAction("restart") }

// DaemonReconfigure applies the saved settings: it writes the Monit configuration and starts Monit or makes it
// reload the configuration when enabled, stops it when disabled
func (opn *MonitApi) DaemonReconfigure() error { return opn.daemonAction("reconfigure") }
