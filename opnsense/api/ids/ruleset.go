package ids

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Ruleset is a downloadable rule set of Services > Intrusion Detection > Administration > Download
// (api/ids/settings/list_rulesets), identified by its file name
type Ruleset struct {
	Filename         string `json:"filename"`
	Description      string `json:"description"`
	DocumentationUrl string `json:"documentation_url"`
	// ModifiedLocal is the time of the last download like "2026/10/25 15:38", "" when never downloaded
	ModifiedLocal string `json:"modified_local"`
	Enabled       bool   `json:"-"`
}

func (r *Ruleset) UnmarshalJSON(data []byte) error {
	type plain Ruleset // modified_local is null when never downloaded, which leaves the string empty
	var raw struct {
		plain
		Enabled string `json:"enabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = Ruleset(raw.plain)
	r.Enabled = raw.Enabled == "1"
	return nil
}

// RulesetSearch returns the rule sets where any column contains searchPhrase ("" for all), sorted by description
func (opn *IdsApi) RulesetSearch(searchPhrase string) ([]Ruleset, error) {
	return coreapi.Search[Ruleset](opn.OPNsense, opn.endpoint("settings", "list_rulesets"), searchPhrase)
}

// RulesetGet returns the rule set with this file name or a *NotFoundError
func (opn *IdsApi) RulesetGet(filename string) (Ruleset, error) {
	var rulesets, err = opn.RulesetSearch("")
	if err != nil {
		return Ruleset{}, err
	}
	for _, ruleset := range rulesets {
		if ruleset.Filename == filename {
			return ruleset, nil
		}
	}
	return Ruleset{}, &coreapi.NotFoundError{Name: "rule set " + filename}
}

// RulesetSetEnabled enables or disables the rule sets with these file names. All names are checked first, OPNsense
// would change the known ones of a list with an unknown one. Enabled rule sets are downloaded by RulesUpdate
func (opn *IdsApi) RulesetSetEnabled(filenames []string, enabled bool) error {
	if len(filenames) == 0 {
		return errors.New("no rule set given")
	}
	var rulesets, err = opn.RulesetSearch("")
	if err != nil {
		return err
	}
	var known = map[string]bool{}
	for _, ruleset := range rulesets {
		known[ruleset.Filename] = true
	}
	var escaped = make([]string, len(filenames))
	for i, filename := range filenames {
		if !known[filename] {
			return &coreapi.NotFoundError{Name: "rule set " + filename}
		}
		escaped[i] = url.PathEscape(filename)
	}

	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("settings", "toggle_ruleset", strings.Join(escaped, ","), flag(enabled)), struct{}{}, &answer); err != nil {
		return err
	}
	if answer.Status != flag(enabled) {
		return fmt.Errorf("toggle_ruleset failed: status %q", answer.Status)
	}
	return nil
}

// RulesetProperties returns the properties of the rule sets (like credentials or options of commercial rule sets,
// api/ids/settings/get_rulesetproperties): name → value. Which exist depends on the installed rule set definitions
func (opn *IdsApi) RulesetProperties() (map[string]string, error) {
	var answer struct {
		Properties json.RawMessage `json:"properties"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get_rulesetproperties"), nil, &answer); err != nil {
		return nil, err
	}
	var properties = map[string]string{}
	if isEmptyAnswer(answer.Properties) {
		return properties, nil
	}
	if err := json.Unmarshal(answer.Properties, &properties); err != nil {
		return nil, fmt.Errorf("unexpected rule set properties: %w", err)
	}
	return properties, nil
}

// RulesetPropertiesSet changes rule set properties. Unknown names are refused (OPNsense ignores them silently)
func (opn *IdsApi) RulesetPropertiesSet(values map[string]string) error {
	if len(values) == 0 {
		return errNoChanges
	}
	var current, err = opn.RulesetProperties()
	if err != nil {
		return err
	}
	var names = make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := current[name]; !ok {
			var known = make([]string, 0, len(current))
			for key := range current {
				known = append(known, key)
			}
			sort.Strings(known)
			if len(known) == 0 {
				return fmt.Errorf("unknown rule set property %q, the installed rule sets have no properties", name)
			}
			return fmt.Errorf("unknown rule set property %q, known are: %s", name, strings.Join(known, ", "))
		}
	}
	_, err = opn.Mutate(opn.endpoint("settings", "set_rulesetproperties"), map[string]any{"properties": values})
	return err
}

// RulesUpdate downloads the enabled rule sets, installs them and makes a running Suricata reload them
// (api/ids/service/update_rules). It waits until the download is done (this can take minutes, cancel ctx to stop
// waiting) unless background is set, then it returns the id of the background job right away
func (opn *IdsApi) RulesUpdate(ctx context.Context, background bool) (string, error) {
	var endpoint = opn.endpoint("service", "update_rules")
	if background {
		endpoint = opn.endpoint("service", "update_rules", "1")
	}
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.postNoTimeout(ctx, endpoint, struct{}{}, &answer); err != nil {
		return "", err
	}
	var status = strings.TrimSpace(answer.Status)
	if background {
		if status == "" || status == "failed" || strings.Contains(status, "error") {
			return "", fmt.Errorf("rule update failed: %s", firstNonEmpty(status, "no status given"))
		}
		return status, nil
	}
	if !strings.HasPrefix(status, "OK") {
		return "", fmt.Errorf("rule update failed: %s", firstNonEmpty(status, "no status given"))
	}
	return status, nil
}
