package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"opnsense-cli/opnsense/api/ids"
	"regexp"
	"strings"
)

// /ids/policy: rule policies (Policy), /ids/user-rule: user defined rules (Administration > User defined). Items
// are selected by the # of print, the uuid or the description

func init() {
	idsMonitRegister(idsPolicyRecords)
	idsMonitRegister(idsUserRuleRecords)
}

// --- /ids/policy

// idsPolicyMetadataArg turns "classtype.trojan-activity" into the classtype:trojan-activity of the arguments
func idsPolicyMetadataArg(content string) string {
	var keys = splitList(content)
	for i, key := range keys {
		keys[i] = strings.Replace(key, ".", ":", 1)
	}
	return strings.Join(keys, ",")
}

// idsPolicyOptionKeys maps the comma separated value to the keys of the choices of field (matching key or display
// name, case-insensitive)
func idsPolicyOptionKeys(c *Context, field string, what string, value string, mapElement func(string) string) (string, error) {
	var elements = splitList(value)
	if len(elements) == 0 {
		return "", nil
	}
	var api, err = idsApi(c)
	if err != nil {
		return "", err
	}
	var options, optionsErr = api.PolicyOptions()
	if optionsErr != nil {
		return "", optionsErr
	}
	var keys []string
	for _, element := range elements {
		var wanted = mapElement(element)
		var found = ""
		for _, option := range options[field] {
			if strings.EqualFold(option.Key, wanted) || strings.EqualFold(option.Display, wanted) {
				found = option.Key
				break
			}
		}
		if found == "" {
			var valid []string
			for _, option := range options[field] {
				valid = append(valid, option.Display)
			}
			if len(valid) == 0 {
				return "", fmt.Errorf("unknown %s %q, there are none", what, element)
			}
			return "", fmt.Errorf("unknown %s %q, valid are: %s", what, element, strings.Join(valid, ", "))
		}
		keys = append(keys, found)
	}
	return strings.Join(keys, ","), nil
}

func idsPolicyCompleteOptions(field string, mapKey func(ids.SettingsOption) string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = idsApi(c)
		if err != nil {
			return nil
		}
		var options, optionsErr = api.PolicyOptions()
		if optionsErr != nil {
			return nil
		}
		var values []string
		for _, option := range options[field] {
			values = append(values, mapKey(option))
		}
		return values
	}
}

func idsPolicyEnabled(p ids.Policy) bool { return p.Enabled == "1" }

var idsPolicyRecords = &idsMonitRecords[ids.Policy, ids.PolicyFields]{
	what:     "policy",
	path:     "ids/policy",
	help:     "rule policies: change the action of the rules matching criteria (Policy)",
	itemHelp: "the #, uuid or description of the policy",
	hint:     idsApplyHint,
	printLong: `A policy changes the rules that match all its criteria (rule sets, metadata, current action) to
NEW-ACTION. Policies are applied by priority (lower first, later ones win), rule adjustments win over policies.`,
	addLong: `  add description="drop trojans" rulesets=emerging-malware.rules metadata=classtype:trojan-activity new-action=drop`,
	list: func(c *Context, search string) ([]ids.Policy, []json.RawMessage, error) {
		var api, err = idsApi(c)
		if err != nil {
			return nil, nil, err
		}
		return api.PolicySearch(search)
	},
	uuid:  func(p ids.Policy) string { return p.Uuid },
	names: func(p ids.Policy) []string { return []string{p.Description} },
	key:   "description",
	keyOf: func(p ids.Policy) string { return p.Description },
	create: func(c *Context, patch ids.PolicyFields) (string, error) {
		var api, err = idsApi(c)
		if err != nil {
			return "", err
		}
		return api.PolicyCreate(patch)
	},
	update: func(c *Context, uuid string, patch ids.PolicyFields) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.PolicyUpdate(uuid, patch)
	},
	remove: func(c *Context, uuid string) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.PolicyRemove(uuid)
	},
	enabled: idsPolicyEnabled,
	columns: []string{"DISABLED", "PRIORITY", "DESCRIPTION", "RULESETS", "METADATA", "MATCH-ACTION", "NEW-ACTION"},
	row: func(p ids.Policy) []string {
		return []string{YesNo(Flag(!idsPolicyEnabled(p))), p.Prio, p.Description, idsMonitListDisplay(p.RulesetNames, p.Rulesets),
			idsPolicyMetadataArg(p.Content), p.Action, p.NewAction}
	},
	fields: []idsMonitField[ids.Policy, ids.PolicyFields]{
		{Arg: Arg{Name: "description", Help: "the name of the policy, shown as POLICY of the rules", Validate: idsMonitValidateText},
			show: func(p ids.Policy) string { return p.Description }, target: func(f *ids.PolicyFields) **string { return &f.Description }},
		idsMonitDisabledField("keep the policy, but don't apply it", idsPolicyEnabled,
			func(f *ids.PolicyFields) **string { return &f.Enabled }),
		{Arg: Arg{Name: "priority", Type: Int, Default: "0", Help: "the order, lower numbers are applied first (later ones win)",
			Validate: ValidateRange(0, 1<<30)},
			show: func(p ids.Policy) string { return p.Prio }, target: func(f *ids.PolicyFields) **string { return &f.Prio }},
		{Arg: Arg{Name: "rulesets", Type: List, Help: `only rules of these rule set files (enabled ones), "" for all`,
			Complete: idsPolicyCompleteOptions("rulesets", func(o ids.SettingsOption) string { return o.Display })},
			show:   func(p ids.Policy) string { return idsMonitListDisplay(p.RulesetNames, p.Rulesets) },
			target: func(f *ids.PolicyFields) **string { return &f.Rulesets },
			convert: func(c *Context, value string) (string, error) {
				return idsPolicyOptionKeys(c, "rulesets", "enabled rule set", value, func(s string) string { return s })
			}},
		{Arg: Arg{Name: "metadata", Type: List, Help: `only rules with all these metadata values, name:value like classtype:trojan-activity`,
			Complete: idsPolicyCompleteOptions("content", func(o ids.SettingsOption) string { return idsPolicyMetadataArg(o.Key) })},
			show:   func(p ids.Policy) string { return idsPolicyMetadataArg(p.Content) },
			target: func(f *ids.PolicyFields) **string { return &f.Content },
			convert: func(c *Context, value string) (string, error) {
				return idsPolicyOptionKeys(c, "content", "metadata value", value, func(s string) string { return strings.Replace(s, ":", ".", 1) })
			}},
		{Arg: Arg{Name: "match-action", Type: List, Help: `only rules whose current action is one of these, "" for any`,
			Values: []string{ids.PolicyActionDisable, ids.RuleActionAlert, ids.RuleActionDrop}},
			show: func(p ids.Policy) string { return p.Action }, target: func(f *ids.PolicyFields) **string { return &f.Action }},
		{Arg: Arg{Name: "new-action", Default: ids.RuleActionAlert, Help: "what the policy sets: default (the rule set's), alert, drop or disable",
			Values: []string{ids.PolicyNewDefault, ids.RuleActionAlert, ids.RuleActionDrop, ids.PolicyActionDisable}},
			show: func(p ids.Policy) string { return p.NewAction }, target: func(f *ids.PolicyFields) **string { return &f.NewAction },
			convert: func(_ *Context, value string) (string, error) { return strings.ToLower(value), nil }},
	},
}

// --- /ids/user-rule

var idsUserRuleFingerprint = regexp.MustCompile(`^[0-9a-fA-F:]{59}$`)

func idsUserRuleValidateNetwork(value string) error {
	if value == "" || net.ParseIP(value) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return nil
	}
	return fmt.Errorf("must be an IP address or a network like 10.0.0.0/8, got %q", value)
}

func idsUserRuleValidateFingerprint(value string) error {
	if value != "" && !idsUserRuleFingerprint.MatchString(value) {
		return fmt.Errorf("must be a SHA1 fingerprint of 59 characters like 00:11:...:ff, got %q", value)
	}
	return nil
}

func idsUserRuleEnabled(r ids.UserRule) bool { return r.Enabled == "1" }

var idsUserRuleRecords = &idsMonitRecords[ids.UserRule, ids.UserRuleFields]{
	what:     "user rule",
	path:     "ids/user-rule",
	help:     "user defined rules by network or TLS fingerprint (Administration > User defined)",
	itemHelp: "the #, uuid or description of the user rule",
	hint:     idsApplyHint,
	addLong: `  add description="block test net" source=192.0.2.0/24 action=drop
  add description="trusted backup" destination=198.51.100.7 action=pass bypass`,
	list: func(c *Context, search string) ([]ids.UserRule, []json.RawMessage, error) {
		var api, err = idsApi(c)
		if err != nil {
			return nil, nil, err
		}
		return api.UserRuleSearch(search)
	},
	uuid:  func(r ids.UserRule) string { return r.Uuid },
	names: func(r ids.UserRule) []string { return []string{r.Description} },
	key:   "description",
	keyOf: func(r ids.UserRule) string { return r.Description },
	create: func(c *Context, patch ids.UserRuleFields) (string, error) {
		var api, err = idsApi(c)
		if err != nil {
			return "", err
		}
		return api.UserRuleCreate(patch)
	},
	update: func(c *Context, uuid string, patch ids.UserRuleFields) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.UserRuleUpdate(uuid, patch)
	},
	remove: func(c *Context, uuid string) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.UserRuleRemove(uuid)
	},
	enabled: idsUserRuleEnabled,
	columns: []string{"DISABLED", "DESCRIPTION", "SOURCE", "DESTINATION", "FINGERPRINT", "ACTION", "BYPASS"},
	row: func(r ids.UserRule) []string {
		return []string{YesNo(Flag(!idsUserRuleEnabled(r))), r.Description, r.Source, r.Destination, r.Fingerprint, r.Action, YesNo(r.Bypass)}
	},
	fields: []idsMonitField[ids.UserRule, ids.UserRuleFields]{
		{Arg: Arg{Name: "description", Help: "the message of the rule's alerts", Validate: idsMonitValidateText},
			show: func(r ids.UserRule) string { return r.Description }, target: func(f *ids.UserRuleFields) **string { return &f.Description }},
		idsMonitDisabledField("keep the rule, but don't install it", idsUserRuleEnabled,
			func(f *ids.UserRuleFields) **string { return &f.Enabled }),
		{Arg: Arg{Name: "source", Help: `match this source address or network, "" for any`, Validate: idsUserRuleValidateNetwork},
			show: func(r ids.UserRule) string { return r.Source }, target: func(f *ids.UserRuleFields) **string { return &f.Source }},
		{Arg: Arg{Name: "destination", Help: `match this destination address or network, "" for any`, Validate: idsUserRuleValidateNetwork},
			show: func(r ids.UserRule) string { return r.Destination }, target: func(f *ids.UserRuleFields) **string { return &f.Destination }},
		{Arg: Arg{Name: "fingerprint", Help: `match the SHA1 fingerprint of a TLS certificate (59 characters), "" for none`,
			Validate: idsUserRuleValidateFingerprint},
			show: func(r ids.UserRule) string { return r.Fingerprint }, target: func(f *ids.UserRuleFields) **string { return &f.Fingerprint }},
		{Arg: Arg{Name: "action", Default: ids.RuleActionAlert, Help: "alert, drop (only in IPS mode) or pass",
			Values: []string{ids.RuleActionAlert, ids.RuleActionDrop, ids.UserRuleActionPass}},
			show: func(r ids.UserRule) string { return r.Action }, target: func(f *ids.UserRuleFields) **string { return &f.Action },
			convert: func(_ *Context, value string) (string, error) { return strings.ToLower(value), nil }},
		{Arg: Arg{Name: "bypass", Type: Bool, Default: "no", Help: "with action pass: let the traffic bypass the inspection completely"},
			show: func(r ids.UserRule) string { return YesNo(r.Bypass) }, target: func(f *ids.UserRuleFields) **string { return &f.Bypass }},
	},
}
