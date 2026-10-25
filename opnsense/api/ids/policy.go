package ids

import (
	"encoding/json"
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
)

// recordKind describes a model backed list of api/ids/settings (policies, user rules): its endpoints
// (search_<method>, add_<method>, set_<method>, del_<method>) and the container key of add / set bodies
type recordKind struct {
	what      string
	method    string
	container string
}

var (
	policyKind   = recordKind{what: "policy", method: "policy", container: "policy"}
	userRuleKind = recordKind{what: "user rule", method: "user_rule", container: "rule"}
)

func searchRecords[T any](opn *IdsApi, kind recordKind, searchPhrase string) ([]T, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("settings", "search_"+kind.method), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var records = make([]T, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &records[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected %s from OPNsense: %w", kind.what, err)
		}
	}
	return records, rows, nil
}

// getRecord finds the record with this uuid in the search results (get_<method> answers unknown uuids with a default
// record), uuid returns the uuid of a record
func getRecord[T any](opn *IdsApi, kind recordKind, uuid string, uuidOf func(T) string) (T, error) {
	var zero T
	if err := validateUuid(kind.what, uuid); err != nil {
		return zero, err
	}
	var records, _, err = searchRecords[T](opn, kind, "")
	if err != nil {
		return zero, err
	}
	for _, record := range records {
		if uuidOf(record) == uuid {
			return record, nil
		}
	}
	return zero, &coreapi.NotFoundError{Name: kind.what + " " + uuid}
}

func (opn *IdsApi) createRecord(kind recordKind, fields any) (string, error) {
	return opn.Mutate(opn.endpoint("settings", "add_"+kind.method), map[string]any{kind.container: fields})
}

// updateRecord sends set_<method>/<uuid>, exists must have been checked: set on an unknown uuid creates the record
func (opn *IdsApi) updateRecord(kind recordKind, uuid string, fields any) error {
	_, err := opn.Mutate(opn.endpoint("settings", "set_"+kind.method, uuid), map[string]any{kind.container: fields})
	return err
}

func (opn *IdsApi) removeRecord(kind recordKind, uuid string) error {
	if err := validateUuid(kind.what, uuid); err != nil {
		return err
	}
	_, err := opn.Mutate(opn.endpoint("settings", "del_"+kind.method, uuid), nil)
	return notFound(kind.what, uuid, err)
}

// optionsOf returns the choices of the option fields of the default record get_<method> answers
func (opn *IdsApi) optionsOf(kind recordKind) (map[string][]SettingsOption, error) {
	var answer map[string]map[string]json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get_"+kind.method), nil, &answer); err != nil {
		return nil, err
	}
	var options = map[string][]SettingsOption{}
	for field, raw := range answer[kind.container] {
		if choices, ok := optionChoices(raw); ok {
			options[field] = choices
		}
	}
	return options, nil
}

// Policy actions: Action of a policy selects rules by their current action, NewAction is what the policy sets
const (
	PolicyActionDisable = "disable"
	PolicyNewDefault    = "default"
)

// Policy is a rule policy (Services > Intrusion Detection > Policy, api/ids/settings/*_policy): it changes the
// action of the rules that match all its criteria. Policies are applied by priority, rule adjustments win
type Policy struct {
	Uuid    string `json:"uuid"`
	Enabled string `json:"enabled"` // "1" or "0"
	// Prio orders the policies, lower numbers are applied first (later ones win)
	Prio string `json:"prio"`
	// Action matches rules by their current action: comma separated disable, alert, drop ("" for any)
	Action string `json:"action"`
	// Rulesets are the uuids of the rule set files (comma separated, "" for all), RulesetNames their file names
	Rulesets     string `json:"rulesets"`
	RulesetNames string `json:"%rulesets"`
	// Content are rule metadata the rules must have, as "property.value" (like classtype.trojan-activity)
	Content   string `json:"content"`
	NewAction string `json:"new_action"` // default, alert, drop or disable
	// Description is the name of the policy, shown as matched_policy of the rules
	Description string `json:"description"`
}

// PolicyFields are the fields to send on create / update, nil fields are not sent: create uses the OPNsense
// defaults for them, update keeps them
type PolicyFields struct {
	Enabled     *string `json:"enabled,omitempty"`
	Prio        *string `json:"prio,omitempty"`
	Action      *string `json:"action,omitempty"`
	Rulesets    *string `json:"rulesets,omitempty"`
	Content     *string `json:"content,omitempty"`
	NewAction   *string `json:"new_action,omitempty"`
	Description *string `json:"description,omitempty"`
}

func policyUuid(policy Policy) string { return policy.Uuid }

// PolicySearch returns the policies where any column contains searchPhrase ("" for all) sorted by description, and
// the rows as the API returned them
func (opn *IdsApi) PolicySearch(searchPhrase string) ([]Policy, []json.RawMessage, error) {
	return searchRecords[Policy](opn, policyKind, searchPhrase)
}

// PolicyGet returns the policy with this uuid or a *NotFoundError
func (opn *IdsApi) PolicyGet(uuid string) (Policy, error) {
	return getRecord(opn, policyKind, uuid, policyUuid)
}

// PolicyOptions returns the choices of the option fields: action, rulesets (uuid → file name of the enabled rule
// sets), content (the metadata of the installed rules) and new_action
func (opn *IdsApi) PolicyOptions() (map[string][]SettingsOption, error) {
	return opn.optionsOf(policyKind)
}

// PolicyCreate adds a policy and returns its uuid
func (opn *IdsApi) PolicyCreate(fields PolicyFields) (string, error) {
	return opn.createRecord(policyKind, fields)
}

// PolicyUpdate changes the non nil fields of the policy, it returns a *NotFoundError for unknown uuids
func (opn *IdsApi) PolicyUpdate(uuid string, fields PolicyFields) error {
	if fields == (PolicyFields{}) {
		return errNoChanges
	}
	if _, err := opn.PolicyGet(uuid); err != nil {
		return err
	}
	return opn.updateRecord(policyKind, uuid, fields)
}

// PolicyRemove deletes the policy
func (opn *IdsApi) PolicyRemove(uuid string) error {
	return opn.removeRecord(policyKind, uuid)
}

// User rule actions
const UserRuleActionPass = "pass"

// UserRule is a user defined rule (Administration > User defined, api/ids/settings/*_user_rule): it alerts, drops
// or passes traffic by source / destination network or TLS fingerprint
type UserRule struct {
	Uuid        string `json:"uuid"`
	Enabled     string `json:"enabled"` // "1" or "0"
	Source      string `json:"source"`
	Destination string `json:"destination"`
	// Fingerprint is the SHA1 fingerprint of a TLS certificate (59 characters like 00:11:...)
	Fingerprint string `json:"fingerprint"`
	Description string `json:"description"`
	Action      string `json:"action"` // alert, drop or pass
	// Bypass ("1") lets matching pass traffic bypass the inspection (only with action pass)
	Bypass string `json:"bypass"`
}

// UserRuleFields are the fields to send on create / update, nil fields are not sent
type UserRuleFields struct {
	Enabled     *string `json:"enabled,omitempty"`
	Source      *string `json:"source,omitempty"`
	Destination *string `json:"destination,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
	Description *string `json:"description,omitempty"`
	Action      *string `json:"action,omitempty"`
	Bypass      *string `json:"bypass,omitempty"`
}

func userRuleUuid(rule UserRule) string { return rule.Uuid }

// UserRuleSearch returns the user defined rules where any column contains searchPhrase ("" for all) sorted by
// description, and the rows as the API returned them
func (opn *IdsApi) UserRuleSearch(searchPhrase string) ([]UserRule, []json.RawMessage, error) {
	return searchRecords[UserRule](opn, userRuleKind, searchPhrase)
}

// UserRuleGet returns the user defined rule with this uuid or a *NotFoundError
func (opn *IdsApi) UserRuleGet(uuid string) (UserRule, error) {
	return getRecord(opn, userRuleKind, uuid, userRuleUuid)
}

// UserRuleCreate adds a user defined rule and returns its uuid, a description is required
func (opn *IdsApi) UserRuleCreate(fields UserRuleFields) (string, error) {
	return opn.createRecord(userRuleKind, fields)
}

// UserRuleUpdate changes the non nil fields of the rule, it returns a *NotFoundError for unknown uuids
func (opn *IdsApi) UserRuleUpdate(uuid string, fields UserRuleFields) error {
	if fields == (UserRuleFields{}) {
		return errNoChanges
	}
	if _, err := opn.UserRuleGet(uuid); err != nil {
		return err
	}
	return opn.updateRecord(userRuleKind, uuid, fields)
}

// UserRuleRemove deletes the user defined rule
func (opn *IdsApi) UserRuleRemove(uuid string) error {
	return opn.removeRecord(userRuleKind, uuid)
}
