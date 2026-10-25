package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/ids"
	"sort"
	"strconv"
	"strings"
)

// /ids/rule: the installed rules (Administration > Rules), tens of thousands with the big rule sets, so print shows
// one page. Rules are selected by their sid (signature id), not by a #, because sids are numbers themselves.
// /ids/policy/adjustment: the rule adjustments (Policy > Rule adjustments), what enable / disable / set of a rule
// stores

const idsRuleSidHelp = "the sid (signature id) of the rule"

func init() {
	var menu = Root.Menu("ids/rule")
	menu.Help = "installed rules (Administration > Rules), by sid"
	var sids = Arg{Name: "sid", Type: List, Help: "the sids of the rules, comma separated", Positional: true, Required: true, Validate: idsRuleValidateSids}
	menu.Add(
		&Command{Name: "print", Help: "list one page of the installed rules",
			Long: `Lists the installed rules ordered by sid, limit per page (page=2 for the next one). The filters are
exact (case-insensitive), search is a substring match over the message, the rule set file and the sid.
ACTION and DISABLED are the current state (rule set default, policy or adjustment), POLICY what changed it
("__manual__" for a rule adjustment). The filters action, disabled and policy see the installed rules: changes are
matched after "/ids/service reload-rules".

  print search=emotet
  print classtype=trojan-activity disabled=no limit=20
  print metadata=signature_severity:Major,affected_product:Windows_XP_Vista_7_8_10_Server_32_64_Bit`,
			Args: []Arg{
				{Name: "search", Help: "only rules whose message, rule set file or sid contains this text", Validate: ids.RuleValidateFilter},
				{Name: "action", Help: "only rules with this action", Values: []string{ids.RuleActionAlert, ids.RuleActionDrop}},
				{Name: "disabled", Type: Bool, Help: "only disabled (yes) or enabled (no) rules"},
				{Name: "ruleset", Help: "only rules of this rule set file, like emerging-scan.rules", Validate: ids.RuleValidateFilter,
					Complete: idsRulesetNames},
				{Name: "classtype", Help: "only rules of this class type, like trojan-activity", Validate: ids.RuleValidateFilter,
					Complete: idsRuleMetadataComplete("classtype")},
				{Name: "policy", Help: `only rules changed by this policy (its description, "__manual__" for adjustments)`,
					Validate: ids.RuleValidateFilter, Complete: idsRuleMetadataComplete("matched_policy")},
				{Name: "metadata", Type: List, Help: "only rules with these metadata values, name:value", Validate: idsRuleValidateMetadata},
				{Name: "limit", Type: Int, Default: "100", Help: "rules per page", Validate: ValidateRange(1, 10000)},
				{Name: "page", Type: Int, Default: "1", Help: "the page to show", Validate: ValidateRange(1, 1<<30)},
				{Name: "detail", Type: Bool, Help: "show all fields of every rule"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			},
			Run: idsRulePrint},
		&Command{Name: "show", Help: "show one rule with all its metadata",
			Args: []Arg{{Name: "sid", Help: idsRuleSidHelp, Positional: true, Required: true, Validate: idsRuleValidateSids},
				{Name: "json", Type: Bool, Help: "print the rule as the API returns it"}},
			Run: idsRuleShow},
		&Command{Name: "enable", Help: "enable rules (keeping their action)", Long: idsApplyHint, Args: []Arg{sids}, Run: idsRuleEnabler(true)},
		&Command{Name: "disable", Help: "disable rules", Long: idsApplyHint, Args: []Arg{sids}, Run: idsRuleEnabler(false)},
		&Command{Name: "reset", Help: "remove the adjustments of rules: back to the rule set default or policy",
			Long: idsApplyHint, Args: []Arg{sids}, Run: idsRuleReset},
		&Command{Name: "set", Help: "change the action and / or state of a rule",
			Long: `Stores a rule adjustment for the rule (see /ids/policy/adjustment), reset removes it again.

  set 2010935 action=drop
  set 2010935 disabled

` + idsApplyHint,
			Args: []Arg{
				{Name: "sid", Help: idsRuleSidHelp, Positional: true, Required: true, Validate: idsRuleValidateSids},
				{Name: "action", Help: "the action when the rule matches (drop only drops in IPS mode)", Values: []string{ids.RuleActionAlert, ids.RuleActionDrop}},
				{Name: "disabled", Type: Bool, Help: "disable (yes) or enable (no) the rule"},
			},
			Check: idsRuleCheckSet, Run: idsRuleSet},
	)

	idsMonitRegister(idsAdjustmentRecords)
}

// --- validation

func idsRuleParseSid(value string) (int64, error) {
	var sid, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || sid <= 0 {
		return 0, fmt.Errorf("must be a sid (a positive number), got %q", value)
	}
	return sid, nil
}

func idsRuleValidateSids(value string) error {
	for _, element := range splitList(value) {
		if _, err := idsRuleParseSid(element); err != nil {
			return err
		}
	}
	return nil
}

func idsRuleSids(args *Args, name string) []int64 {
	var sids []int64
	for _, element := range args.List(name) {
		var sid, _ = idsRuleParseSid(element)
		sids = append(sids, sid)
	}
	return sids
}

func idsRuleValidateMetadata(value string) error {
	for _, element := range splitList(value) {
		var name, metadataValue, found = strings.Cut(element, ":")
		if !found || name == "" || strings.ContainsAny(name, " /\"'") {
			return fmt.Errorf("must be name:value like signature_severity:Major, got %q", element)
		}
		if err := ids.RuleValidateFilter(metadataValue); err != nil {
			return err
		}
	}
	return nil
}

func idsRuleCheckSet(args *Args) error {
	if !args.Has("action") && !args.Has("disabled") {
		return errors.New("nothing to change, give action= and / or disabled=")
	}
	if args.Has("action") && args.String("action") == "" {
		return errors.New("action must not be empty")
	}
	if len(args.List("sid")) != 1 {
		return errors.New("set takes one sid")
	}
	return nil
}

// idsRuleMetadataComplete completes the values of a metadata property from the installed rules
func idsRuleMetadataComplete(property string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = idsApi(c)
		if err != nil {
			return nil
		}
		var metadata, getErr = api.RuleMetadata()
		if getErr != nil {
			return nil
		}
		return metadata[property]
	}
}

// --- print and show

func idsRuleQuery(args *Args) ids.RuleQuery {
	var query = ids.RuleQuery{Search: args.String("search"), Filters: map[string]string{}, Limit: args.Int("limit"), Page: args.Int("page")}
	if args.Has("action") {
		query.Filters["action"] = strings.ToLower(args.String("action"))
	}
	if args.Has("disabled") {
		query.Filters["status"] = map[bool]string{true: "disabled", false: "enabled"}[args.Bool("disabled")]
	}
	for arg, filter := range map[string]string{"ruleset": "source", "classtype": "classtype", "policy": "matched_policy"} {
		if args.Has(arg) && args.String(arg) != "" {
			query.Filters[filter] = args.String(arg)
		}
	}
	for _, element := range args.List("metadata") {
		var name, value, _ = strings.Cut(element, ":")
		query.Filters[name] = value
	}
	return query
}

func idsRuleFields(rule ids.Rule) [][2]string {
	var fields = [][2]string{
		{"sid", strconv.FormatInt(rule.Sid, 10)},
		{"message", rule.Msg},
		{"ruleset", rule.Source},
		{"disabled", YesNo(Flag(!rule.Enabled))},
		{"action", rule.Action},
		{"default-disabled", YesNo(Flag(!rule.EnabledDefault))},
		{"default-action", rule.ActionDefault},
		{"policy", rule.MatchedPolicy},
		{"classtype", rule.Classtype},
		{"revision", rule.Rev},
		{"gid", rule.Gid},
		{"reference", strings.ReplaceAll(rule.Reference, "\n", ", ")},
	}
	var names = make([]string, 0, len(rule.Metadata))
	for name := range rule.Metadata {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fields = append(fields, [2]string{name, strings.ReplaceAll(rule.Metadata[name], "\n", ", ")})
	}
	return fields
}

func idsRulePrint(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var query = idsRuleQuery(args)
	var page, searchErr = api.RuleSearch(query)
	if searchErr != nil {
		return searchErr
	}
	switch {
	case args.Bool("json"):
		for _, row := range page.Raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		for i, rule := range page.Rules {
			if i > 0 {
				c.Println()
			}
			c.Fields(idsRuleFields(rule))
		}
	default:
		var rows = make([][]string, len(page.Rules))
		for i, rule := range page.Rules {
			rows[i] = []string{strconv.FormatInt(rule.Sid, 10), YesNo(Flag(!rule.Enabled)), rule.Action, rule.Source,
				rule.Classtype, rule.MatchedPolicy, rule.Msg}
		}
		c.Table([]string{"SID", "DISABLED", "ACTION", "RULESET", "CLASSTYPE", "POLICY", "MESSAGE"}, rows)
	}
	var first = (query.Page-1)*query.Limit + 1
	var last = first + len(page.Rules) - 1
	switch {
	case page.Total == 0:
		c.Infof("no matching rules (are rule sets downloaded? see /ids/ruleset)")
	case len(page.Rules) == 0:
		c.Infof("page %d is empty, %d matching rules", query.Page, page.Total)
	case last < page.Total:
		c.Infof("rules %d-%d of %d, page=%d shows the next ones", first, last, page.Total, query.Page+1)
	default:
		c.Infof("rules %d-%d of %d", first, last, page.Total)
	}
	return nil
}

func idsRuleShow(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var sids = idsRuleSids(args, "sid")
	if len(sids) != 1 {
		return errors.New("show takes one sid")
	}
	var rule, raw, getErr = api.RuleGet(sids[0])
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return err
		}
		c.Println(compact.String())
		return nil
	}
	c.Fields(idsRuleFields(rule))
	return nil
}

func idsRuleEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.RuleSetEnabled(idsRuleSids(args, "sid"), enabled)
	}
}

func idsRuleReset(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	return api.RuleReset(idsRuleSids(args, "sid"))
}

func idsRuleSet(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var sid = idsRuleSids(args, "sid")[0]
	if !args.Has("action") {
		return api.RuleSetEnabled([]int64{sid}, !args.Bool("disabled"))
	}
	var enabled *bool
	if args.Has("disabled") {
		var value = !args.Bool("disabled")
		enabled = &value
	}
	return api.RuleSetAction(sid, strings.ToLower(args.String("action")), enabled)
}

// --- /ids/policy/adjustment

var idsAdjustmentRecords = &idsMonitRecords[ids.Adjustment, struct{}]{
	what:     "rule adjustment",
	path:     "ids/policy/adjustment",
	help:     "rule adjustments: state and action set for single rules (Policy > Rule adjustments)",
	itemHelp: `the # or uuid of the adjustment ("/ids/rule reset <sid>" removes one by sid)`,
	hint:     idsApplyHint,
	printLong: `Rule adjustments are created by "/ids/rule enable|disable|set", they win over the policies. Removing
one (or "/ids/rule reset <sid>") restores the rule's default (or policy) state and action. MESSAGE and RULESET are empty for rules that are not
installed (any more).`,
	removeLong: "The rule goes back to its default (or policy) state and action.",
	list: func(c *Context, search string) ([]ids.Adjustment, []json.RawMessage, error) {
		var api, err = idsApi(c)
		if err != nil {
			return nil, nil, err
		}
		return api.AdjustmentSearch(search)
	},
	uuid: func(a ids.Adjustment) string { return a.Uuid },
	// sids are numbers, which select by #: "/ids/rule reset <sid>" removes by sid
	names: func(ids.Adjustment) []string { return nil },
	remove: func(c *Context, uuid string) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.AdjustmentRemove(uuid)
	},
	columns: []string{"SID", "DISABLED", "ACTION", "RULESET", "MESSAGE"},
	row: func(a ids.Adjustment) []string {
		return []string{a.Sid, YesNo(Flag(a.Enabled != "1")), a.Action, a.Source, a.Msg}
	},
	fields: []idsMonitField[ids.Adjustment, struct{}]{
		{Arg: Arg{Name: "sid"}, show: func(a ids.Adjustment) string { return a.Sid }},
		{Arg: Arg{Name: "disabled"}, show: func(a ids.Adjustment) string { return YesNo(Flag(a.Enabled != "1")) }},
		{Arg: Arg{Name: "action"}, show: func(a ids.Adjustment) string { return a.Action }},
		{Arg: Arg{Name: "ruleset"}, show: func(a ids.Adjustment) string { return a.Source }},
		{Arg: Arg{Name: "message"}, show: func(a ids.Adjustment) string { return a.Msg }},
	},
}
