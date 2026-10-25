package ids

import (
	"fmt"
	"strings"
)

// Service states of ServiceStatus
const (
	ServiceRunning  = "running"
	ServiceStopped  = "stopped"
	ServiceDisabled = "disabled"
)

// ServiceStatus returns the state of Suricata: running, stopped (enabled but not running), disabled or unknown
func (opn *IdsApi) ServiceStatus() (string, error) {
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("service", "status"), nil, &answer); err != nil {
		return "", err
	}
	return answer.Status, nil
}

// serviceAction POSTs service/<action>, which answers {"response":"OK"} (start, stop, restart) or {"status":"OK"}
// (reconfigure, reload_rules); everything else is an error
func (opn *IdsApi) serviceAction(action string) error {
	var answer struct {
		Response any    `json:"response"`
		Status   string `json:"status"`
	}
	// actions must be POSTed, a GET does nothing
	if err := opn.DoJSON("POST", opn.endpoint("service", action), struct{}{}, &answer); err != nil {
		return err
	}
	var result = strings.TrimSpace(answer.Status)
	if text, ok := answer.Response.(string); ok && result == "" {
		result = strings.TrimSpace(text)
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("ids %s failed: %s", strings.ReplaceAll(action, "_", " "), firstNonEmpty(result, "no status given"))
	}
	return nil
}

// ServiceStart starts Suricata
func (opn *IdsApi) ServiceStart() error { return opn.serviceAction("start") }

// ServiceStop stops Suricata
func (opn *IdsApi) ServiceStop() error { return opn.serviceAction("stop") }

// ServiceRestart restarts Suricata
func (opn *IdsApi) ServiceRestart() error { return opn.serviceAction("restart") }

// ServiceReconfigure applies the saved settings: it writes the Suricata configuration, installs the rules and
// starts / restarts Suricata when enabled, stops it when disabled. On the first run OPNsense also creates the daily
// rule update cron job
func (opn *IdsApi) ServiceReconfigure() error { return opn.serviceAction("reconfigure") }

// ServiceReloadRules installs the rules with the current rule set, policy and adjustment changes and makes a running
// Suricata reload them. OPNsense reports an error ("Error (1)") when Suricata is not running, the rules are installed
// anyway
func (opn *IdsApi) ServiceReloadRules() error { return opn.serviceAction("reload_rules") }
