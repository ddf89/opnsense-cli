package ids

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Rule actions of installed rules and rule adjustments
const (
	RuleActionAlert = "alert"
	RuleActionDrop  = "drop"
)

// Rule is an installed rule (a signature of a downloaded rule set or a user defined rule) with its current state:
// the rule set's default overlaid with the local adjustment or policy
type Rule struct {
	Sid       int64
	Rev       string
	Gid       string
	Msg       string
	Reference string
	// Source is the file name of the rule set the rule comes from
	Source         string
	Enabled        bool
	Action         string // alert or drop
	EnabledDefault bool
	ActionDefault  string
	// MatchedPolicy is the description of the policy that changed the rule, "__manual__" for a rule adjustment,
	// "" for none
	MatchedPolicy string
	Classtype     string
	// Metadata are the other fields of the rule, like affected_product or signature_severity (RuleGet fills more)
	Metadata map[string]string
}

// ruleKnownFields are decoded into the Rule fields, everything else goes to Metadata
var ruleKnownFields = map[string]bool{
	"sid": true, "rev": true, "gid": true, "msg": true, "reference": true, "source": true, "enabled": true,
	"action": true, "enabled_default": true, "action_default": true, "matched_policy": true, "classtype": true,
	"status": true, "reference_html": true,
}

// rawText renders a JSON value as text: strings as they are, numbers and booleans as written, null as "", an option
// map as its selected keys (comma separated) and anything else as compact JSON
func rawText(raw json.RawMessage) string {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(trimmed, &text) == nil {
		return text
	}
	if options, ok := optionChoices(trimmed); ok {
		var selected []string
		for _, option := range options {
			if option.Selected {
				selected = append(selected, option.Key)
			}
		}
		return strings.Join(selected, ",")
	}
	switch string(trimmed) {
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return string(trimmed)
}

func (r *Rule) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var sid, err = strconv.ParseInt(rawText(raw["sid"]), 10, 64)
	if err != nil {
		return fmt.Errorf("rule without valid sid: %s", raw["sid"])
	}
	*r = Rule{
		Sid: sid, Rev: rawText(raw["rev"]), Gid: rawText(raw["gid"]), Msg: rawText(raw["msg"]),
		Reference: rawText(raw["reference"]), Source: rawText(raw["source"]),
		Enabled: rawText(raw["enabled"]) == "1", Action: strings.ToLower(rawText(raw["action"])),
		EnabledDefault: rawText(raw["enabled_default"]) == "1", ActionDefault: strings.ToLower(rawText(raw["action_default"])),
		MatchedPolicy: rawText(raw["matched_policy"]), Classtype: rawText(raw["classtype"]),
		Metadata: map[string]string{},
	}
	for key, value := range raw {
		if !ruleKnownFields[key] {
			if text := rawText(value); text != "" {
				r.Metadata[key] = text
			}
		}
	}
	return nil
}

// RuleQuery selects installed rules. Filters are exact, case-insensitive matches of a field (action, status
// "enabled"/"disabled", source, matched_policy) or of rule metadata (like classtype), see RuleMetadata
type RuleQuery struct {
	// Search is a substring match over msg, source and sid
	Search  string
	Filters map[string]string
	// Limit is the page size (1 or more, required: OPNsense answers all rules for 0), Page counts from 1
	Limit int
	Page  int
}

// RulePage is one page of installed rules
type RulePage struct {
	Rules []Rule
	// Raw are the rows as the API returned them
	Raw []json.RawMessage
	// Total is the number of matching rules on all pages
	Total int
}

// ruleReservedParams are the request parameters of search_installed_rules that are not filters
var ruleReservedParams = map[string]bool{"current": true, "rowCount": true, "sort": true, "searchPhrase": true}

// RuleValidateFilter checks a filter value: OPNsense quotes it in a shell like command line
func RuleValidateFilter(value string) error {
	if strings.ContainsAny(value, "\"'\\\n\r") {
		return fmt.Errorf("invalid filter value %q: quotes, backslashes and newlines are not allowed", value)
	}
	return nil
}

// RuleSearch returns one page of the installed rules matching query, ordered by sid
func (opn *IdsApi) RuleSearch(query RuleQuery) (RulePage, error) {
	if query.Limit < 1 {
		return RulePage{}, errors.New("the page size must be at least 1")
	}
	var page = max(query.Page, 1)
	var body = map[string]any{"current": page, "rowCount": query.Limit}
	if query.Search != "" {
		if err := RuleValidateFilter(query.Search); err != nil {
			return RulePage{}, err
		}
		body["searchPhrase"] = query.Search
	}
	for key, value := range query.Filters {
		if ruleReservedParams[key] || key == "" || strings.ContainsAny(key, " /\"'") {
			return RulePage{}, fmt.Errorf("invalid rule filter %q", key)
		}
		if err := RuleValidateFilter(value); err != nil {
			return RulePage{}, err
		}
		body[key] = value
	}

	var answer struct {
		Rows  []json.RawMessage `json:"rows"`
		Total int               `json:"total"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("settings", "search_installed_rules"), body, &answer); err != nil {
		return RulePage{}, err
	}
	var result = RulePage{Raw: answer.Rows, Total: answer.Total, Rules: make([]Rule, len(answer.Rows))}
	for i, row := range answer.Rows {
		if err := json.Unmarshal(row, &result.Rules[i]); err != nil {
			return RulePage{}, fmt.Errorf("unexpected rule from OPNsense: %w", err)
		}
	}
	return result, nil
}

// RuleGet returns the installed rule with this sid with all its metadata, or a *NotFoundError. raw is the answer
// of get_rule_info
func (opn *IdsApi) RuleGet(sid int64) (Rule, json.RawMessage, error) {
	if sid <= 0 {
		return Rule{}, nil, fmt.Errorf("invalid sid %d", sid)
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get_rule_info", strconv.FormatInt(sid, 10)), nil, &raw); err != nil {
		return Rule{}, nil, err
	}
	if isEmptyAnswer(raw) {
		return Rule{}, nil, &coreapi.NotFoundError{Name: fmt.Sprintf("rule with sid %d", sid)}
	}
	var rule Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return Rule{}, nil, fmt.Errorf("unexpected rule from OPNsense: %w", err)
	}
	return rule, raw, nil
}

func ruleSidList(sids []int64) string {
	var texts = make([]string, len(sids))
	for i, sid := range sids {
		texts[i] = strconv.FormatInt(sid, 10)
	}
	return strings.Join(texts, ",")
}

// RuleSetEnabled enables or disables installed rules (keeping their action) by adding or changing their rule
// adjustments. All sids are checked first. Like all rule changes it takes effect after ServiceReloadRules
func (opn *IdsApi) RuleSetEnabled(sids []int64, enabled bool) error {
	if len(sids) == 0 {
		return errors.New("no sid given")
	}
	for _, sid := range sids {
		if _, _, err := opn.RuleGet(sid); err != nil {
			return err
		}
	}
	var answer json.RawMessage
	if err := opn.DoJSON("POST", opn.endpoint("settings", "toggle_rule", ruleSidList(sids), flag(enabled)), struct{}{}, &answer); err != nil {
		return err
	}
	var result coreapi.MutationResult
	if isEmptyAnswer(answer) || json.Unmarshal(answer, &result) != nil || result.Result != "saved" {
		return fmt.Errorf("toggle_rule failed: %s", answer)
	}
	return nil
}

// RuleSetAction sets the action (alert or drop) of an installed rule and, when enabled is not nil, its state
func (opn *IdsApi) RuleSetAction(sid int64, action string, enabled *bool) error {
	// set_rule saves the state before it validates the action, refuse invalid actions before sending anything
	if action != RuleActionAlert && action != RuleActionDrop {
		return fmt.Errorf("invalid rule action %q, must be alert or drop", action)
	}
	if _, _, err := opn.RuleGet(sid); err != nil {
		return err
	}
	var body = map[string]string{"action": action}
	if enabled != nil {
		body["enabled"] = flag(*enabled)
	}
	_, err := opn.Mutate(opn.endpoint("settings", "set_rule", strconv.FormatInt(sid, 10)), body)
	return err
}

// RuleMetadata returns the metadata properties of the installed rules with their values (like classtype →
// [trojan-activity, ...]) and matched_policy with the enabled policies, usable as RuleQuery filters
func (opn *IdsApi) RuleMetadata() (map[string][]string, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("settings", "list_rule_metadata"), nil, &raw); err != nil {
		return nil, err
	}
	var metadata = map[string][]string{}
	if isEmptyAnswer(raw) {
		return metadata, nil
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, fmt.Errorf("unexpected rule metadata: %w", err)
	}
	for _, values := range metadata {
		sort.Strings(values)
	}
	return metadata, nil
}

// Adjustment is a rule adjustment (Policy > Rule adjustments, api/ids/settings/*_policy_rule): the state and
// action set for one rule by sid, they win over the policies. RuleSetEnabled and RuleSetAction create them
type Adjustment struct {
	Uuid    string `json:"uuid"`
	Sid     string `json:"sid"`
	Enabled string `json:"enabled"`
	Action  string `json:"action"`
	// Msg and Source describe the installed rule, empty when the rule is not installed (any more)
	Msg    string `json:"msg"`
	Source string `json:"source"`
}

// AdjustmentSearch returns the rule adjustments where any column contains searchPhrase ("" for all), by sid
func (opn *IdsApi) AdjustmentSearch(searchPhrase string) ([]Adjustment, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("settings", "search_policy_rule"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var adjustments = make([]Adjustment, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &adjustments[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected rule adjustment from OPNsense: %w", err)
		}
	}
	return adjustments, rows, nil
}

// RuleReset removes the rule adjustments of these sids, the rules go back to their default (or policy) state and
// action. A sid without adjustment is a *NotFoundError (checked for all sids first)
func (opn *IdsApi) RuleReset(sids []int64) error {
	if len(sids) == 0 {
		return errors.New("no sid given")
	}
	var adjustments, _, err = opn.AdjustmentSearch("")
	if err != nil {
		return err
	}
	var uuids []string
	for _, sid := range sids {
		var found = ""
		for _, adjustment := range adjustments {
			if adjustment.Sid == strconv.FormatInt(sid, 10) {
				found = adjustment.Uuid
			}
		}
		if found == "" {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("rule adjustment for sid %d (the rule has its default or policy state)", sid)}
		}
		uuids = append(uuids, found)
	}
	for _, uuid := range uuids {
		if err := opn.AdjustmentRemove(uuid); err != nil {
			return err
		}
	}
	return nil
}

// AdjustmentRemove deletes a rule adjustment, the rule goes back to its default (or policy) state and action
func (opn *IdsApi) AdjustmentRemove(uuid string) error {
	if err := validateUuid("rule adjustment", uuid); err != nil {
		return err
	}
	_, err := opn.Mutate(opn.endpoint("settings", "del_policy_rule", uuid), nil)
	return notFound("rule adjustment", uuid, err)
}
