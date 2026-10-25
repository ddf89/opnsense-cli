//go:build integration

package integrationids

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ids"
)

// the small rule set used to get installed rules
const testRuleset = "abuse.ch.feodotracker.rules"

func TestIdsReadOnly(t *testing.T) {
	var lib = idsApi(t)
	var status, err = lib.ServiceStatus()
	if err != nil {
		t.Fatal(err)
	}
	var shownStatus = mustOpn(t, "/ids/service", "status")
	requireContains(t, shownStatus, shownStatus.stdout, "status:", status)

	var printed = mustOpn(t, "/ids/settings", "print")
	requireContains(t, printed, printed.stdout, "enabled:", "mode:", "interfaces:", "home-networks:", "eve-tls-custom:")
	var options = mustOpn(t, "/ids/settings", "print", "options=mode")
	requireContains(t, options, options.stdout, "pcap", "netmap", "divert")

	var rulesets = mustOpn(t, "/ids/ruleset", "print")
	requireContains(t, rulesets, rulesets.stdout, "FILENAME", testRuleset)
	mustOpn(t, "/ids/ruleset/property", "print")
	mustOpn(t, "/ids/alert", "print", "limit=5")
	mustOpn(t, "/ids/alert/log", "print")
	mustOpn(t, "/ids/policy/adjustment", "print")
	// confirmation guards: nothing runs without confirm=yes
	for _, command := range []string{"start", "restart", "reconfigure"} {
		var refused = mustFailOpn(t, "/ids/service", command)
		requireContains(t, refused, refused.stderr, "confirm=yes")
	}
	if after, _ := lib.ServiceStatus(); after != status {
		t.Errorf("the service state changed from %s to %s", status, after)
	}
}

func TestIdsSettingsRoundTrip(t *testing.T) {
	var lib = idsApi(t)
	var before, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var restore = map[string]string{"AlertSaveLogs": before["AlertSaveLogs"].Value, "syslog": before["syslog"].Value,
		"detect.Profile": before["detect.Profile"].Value}
	t.Cleanup(func() {
		if err := lib.SettingsSet(restore); err != nil {
			t.Errorf("restoring the settings failed: %v", err)
		}
	})

	var keep = "7"
	if before["AlertSaveLogs"].Value == keep {
		keep = "8"
	}
	var syslog = map[string]string{"0": "yes", "1": "no"}[before["syslog"].Value]
	if out := mustOpn(t, "/ids/settings", "set", "alert-log-keep="+keep, "syslog="+syslog, "detect-profile=medium"); out.stdout != "" {
		t.Errorf("set must be silent:\n%s", out)
	}
	var after, _ = lib.SettingsGet()
	if after["AlertSaveLogs"].Value != keep || after["syslog"].Value == before["syslog"].Value || after["detect.Profile"].Value != "medium" {
		t.Errorf("settings not changed: %v %v %v", after["AlertSaveLogs"], after["syslog"], after["detect.Profile"])
	}
	if after["enabled"].Value != before["enabled"].Value || after["mode"].Value != before["mode"].Value {
		t.Errorf("set changed other settings")
	}
	mustFailOpn(t, "/ids/settings", "set", "interfaces=a8nope")
	var printed = mustOpn(t, "/ids/settings", "print")
	requireContains(t, printed, printed.stdout, "detect-profile:              medium")
}

// withRules makes sure the test rule set is enabled and downloaded, it returns an installed sid of it
func withRules(t *testing.T, lib *ids.IdsApi) int64 {
	t.Helper()
	var ruleset, err = lib.RulesetGet(testRuleset)
	if err != nil {
		t.Fatalf("rule set %s: %v", testRuleset, err)
	}
	if !ruleset.Enabled {
		mustOpn(t, "/ids/ruleset", "enable", testRuleset)
		t.Cleanup(func() {
			if err := lib.RulesetSetEnabled([]string{testRuleset}, false); err != nil {
				t.Errorf("disabling %s again failed: %v", testRuleset, err)
			}
		})
	}
	var page, searchErr = lib.RuleSearch(ids.RuleQuery{Filters: map[string]string{"source": testRuleset}, Limit: 1})
	if searchErr != nil {
		t.Fatal(searchErr)
	}
	if page.Total == 0 {
		var result = runOpn(t, "/ids/ruleset", "update")
		if result.exitCode != 0 {
			t.Skipf("rule download failed (no internet access?):\n%s", result)
		}
		if page, searchErr = lib.RuleSearch(ids.RuleQuery{Filters: map[string]string{"source": testRuleset}, Limit: 1}); searchErr != nil || page.Total == 0 {
			t.Skipf("no rules of %s after the download: %v", testRuleset, searchErr)
		}
	}
	return page.Rules[0].Sid
}

func TestIdsRules(t *testing.T) {
	var lib = idsApi(t)
	var sid = withRules(t, lib)
	var sidText = strconv.FormatInt(sid, 10)

	var printed = mustOpn(t, "/ids/rule", "print", "ruleset="+testRuleset, "limit=2")
	requireContains(t, printed, printed.stdout, "SID", "RULESET", testRuleset)
	requireContains(t, printed, printed.stderr, "rules 1-")
	var asJSON = mustOpn(t, "/ids/rule", "print", "search="+sidText, "json")
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(asJSON.stdout), "\n")[0]), &row); err != nil || row["source"] != testRuleset {
		t.Errorf("json: %v %v\n%s", row, err, asJSON)
	}
	var shown = mustOpn(t, "/ids/rule", "show", sidText)
	requireContains(t, shown, shown.stdout, "sid:", sidText, "ruleset:", testRuleset, "default-action:")
	mustFailOpn(t, "/ids/rule", "show", "1")

	// adjustments: only for a rule without one, reset afterwards
	var adjustments, _, err = lib.AdjustmentSearch("")
	if err != nil {
		t.Fatal(err)
	}
	for _, adjustment := range adjustments {
		if adjustment.Sid == sidText {
			t.Skipf("rule %d has an adjustment already, not touching it", sid)
		}
	}
	t.Cleanup(func() {
		if err := lib.RuleReset([]int64{sid}); err != nil && !api.IsNotFound(err) {
			t.Errorf("resetting rule %d failed: %v", sid, err)
		}
	})
	mustOpn(t, "/ids/rule", "set", sidText, "action=drop", "disabled")
	var rule, _, getErr = lib.RuleGet(sid)
	if getErr != nil || rule.Enabled || rule.Action != "drop" {
		t.Errorf("after set: %+v %v", rule, getErr)
	}
	mustOpn(t, "/ids/rule", "enable", sidText)
	if rule, _, _ = lib.RuleGet(sid); !rule.Enabled || rule.Action != "drop" {
		t.Errorf("enable must keep the action: %+v", rule)
	}
	var listed = mustOpn(t, "/ids/policy/adjustment", "print", "search="+sidText)
	requireContains(t, listed, listed.stdout, sidText, "drop")
	mustOpn(t, "/ids/rule", "reset", sidText)
	if rule, _, _ = lib.RuleGet(sid); rule.Enabled != rule.EnabledDefault || rule.Action != rule.ActionDefault {
		t.Errorf("reset must restore the default: %+v", rule)
	}
	mustFailOpn(t, "/ids/rule", "reset", sidText)
	mustFailOpn(t, "/ids/rule", "set", "1", "action=drop")
}

func TestIdsRuleUpdateBackground(t *testing.T) {
	var lib = idsApi(t)
	withRules(t, lib)
	var status, err = lib.RulesUpdate(context.Background(), true)
	if err != nil || status == "" {
		t.Errorf("background update: %q %v", status, err)
	}
}

func TestIdsPolicyCli(t *testing.T) {
	var lib = idsApi(t)
	withRules(t, lib)
	var description = runPrefix + " policy"
	var added = mustOpn(t, "/ids/policy", "add", "description="+description, "disabled", "rulesets="+testRuleset,
		"metadata=classtype:trojan-activity", "match-action=alert", "new-action=drop", "priority=3")
	var uuid = uuidFrom(t, added)
	t.Cleanup(func() {
		if err := lib.PolicyRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of policy %s: %v", uuid, err)
		}
	})
	var policy, err = lib.PolicyGet(uuid)
	if err != nil || policy.Enabled != "0" || policy.RulesetNames != testRuleset || policy.Content != "classtype.trojan-activity" ||
		policy.NewAction != "drop" || policy.Prio != "3" || policy.Action != "alert" {
		t.Errorf("added policy %+v %v", policy, err)
	}
	var shown = mustOpn(t, "/ids/policy", "show", description)
	requireContains(t, shown, shown.stdout, "disabled:", "yes", "metadata:", "classtype:trojan-activity", "rulesets:", testRuleset)
	var exists = mustFailOpn(t, "/ids/policy", "add", "description="+description)
	requireContains(t, exists, exists.stderr, "exists already", uuid)

	mustOpn(t, "/ids/policy", "set", description, "metadata=", "rulesets=", "priority=4")
	if policy, _ = lib.PolicyGet(uuid); policy.Content != "" || policy.Rulesets != "" || policy.Prio != "4" || policy.NewAction != "drop" {
		t.Errorf("after set %+v", policy)
	}
	var replaced = mustOpn(t, "/ids/policy", "add", "description="+description, "replace", "disabled")
	if uuidFrom(t, replaced) != uuid {
		t.Errorf("replace must keep the uuid")
	}
	if policy, _ = lib.PolicyGet(uuid); policy.NewAction != "alert" || policy.Prio != "0" || policy.Enabled != "0" {
		t.Errorf("after replace %+v", policy)
	}
	mustFailOpn(t, "/ids/policy", "set", description, "rulesets=a8nope.rules")
	mustOpn(t, "/ids/policy", "remove", description)
	if _, err := lib.PolicyGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the policy must be gone: %v", err)
	}
}

func TestIdsUserRuleCli(t *testing.T) {
	var lib = idsApi(t)
	var description = runPrefix + " user rule"
	var uuid = uuidFrom(t, mustOpn(t, "/ids/user-rule", "add", "description="+description, "disabled", "source=192.0.2.0/24", "action=alert"))
	t.Cleanup(func() {
		if err := lib.UserRuleRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of user rule %s: %v", uuid, err)
		}
	})
	var printed = mustOpn(t, "/ids/user-rule", "print", "search="+runPrefix)
	requireContains(t, printed, printed.stdout, description, "192.0.2.0/24", "alert")
	mustOpn(t, "/ids/user-rule", "set", description, "destination=198.51.100.7", "action=drop")
	var rule, err = lib.UserRuleGet(uuid)
	if err != nil || rule.Destination != "198.51.100.7" || rule.Source != "192.0.2.0/24" || rule.Action != "drop" || rule.Enabled != "0" {
		t.Errorf("after set %+v %v", rule, err)
	}
	var already = mustOpn(t, "/ids/user-rule", "disable", description)
	requireContains(t, already, already.stderr, "already disabled")
	mustFailOpn(t, "/ids/user-rule", "set", description, "source=a8nonsense")
	mustOpn(t, "/ids/user-rule", "remove", uuid)
	if _, err := lib.UserRuleGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the user rule must be gone: %v", err)
	}
}
