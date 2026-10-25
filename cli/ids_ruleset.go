package cli

import (
	"encoding/json"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ids"
	"sort"
	"strings"
)

// /ids/ruleset: the downloadable rule sets (Administration > Download). Items are selected by the # of print, the
// file name or the description. Enabled rule sets are downloaded and installed by "update"

const idsRulesetItemHelp = "the #, file name or description of the rule set; enable and disable take several, comma separated"

func init() {
	var menu = Root.Menu("ids/ruleset")
	menu.Help = "rule sets to download (Administration > Download)"
	var items = Arg{Name: "item", Type: List, Help: idsRulesetItemHelp, Positional: true, Required: true, Complete: idsRulesetNames}
	menu.Add(
		&Command{Name: "print", Help: "list the rule sets",
			Long: `DOWNLOADED is the time of the last download, "-" when the rule set was never downloaded.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every rule set", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only rule sets where any field contains this text"},
				{Name: "enabled", Help: "only the enabled rule sets", Type: Bool},
			}, Run: idsRulesetPrint},
		&Command{Name: "show", Help: "show all fields of one rule set",
			Args: []Arg{{Name: "item", Help: "the #, file name or description of the rule set", Positional: true, Required: true,
				Complete: idsRulesetNames}}, Run: idsRulesetShow},
		&Command{Name: "enable", Help: "enable rule sets, update downloads them", Long: idsRulesetUpdateHint,
			Args: []Arg{items}, Run: idsRulesetEnabler(true)},
		&Command{Name: "disable", Help: "disable rule sets", Long: idsApplyHint, Args: []Arg{items}, Run: idsRulesetEnabler(false)},
		&Command{Name: "update", Help: "download the enabled rule sets, install them and reload the rules",
			Long: `Downloads the enabled rule sets (this needs internet access and can take minutes), installs them and
makes a running Suricata reload the rules, like "Download & Update Rules" in the GUI. It waits until the download is
done, Ctrl-C stops waiting (the download goes on). background starts the download and returns at once.`,
			Args: []Arg{{Name: "background", Type: Bool, Help: "do not wait for the download"}}, Run: idsRulesetUpdate},
	)

	var properties = Root.Menu("ids/ruleset/property")
	properties.Help = "properties of the rule sets, like the codes of commercial rule sets"
	properties.Add(
		&Command{Name: "print", Help: "list the rule set properties and whether they are set",
			Long: `Which properties exist depends on the installed rule set definitions, the standard ones have none.
The values are mostly subscription codes and never printed, only "(set)".`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the properties as one JSON object"}}, Run: idsRulesetPropertyPrint},
		&Command{Name: "set", Help: "set a rule set property",
			Long: "  set name=et_pro.oinkcode value=0123456789abcdef\n\n" + idsRulesetUpdateHint,
			Args: []Arg{
				{Name: "name", Help: "the property name, see print", Required: true, Complete: idsRulesetPropertyNames},
				{Name: "value", Help: `the new value, "" clears it`, Required: true, Validate: idsMonitValidateText},
			}, Run: idsRulesetPropertySet},
	)
}

const idsRulesetUpdateHint = `Changes are only saved, run "/ids/ruleset update" to download and install the rule sets.`

func idsRulesetUuid(ruleset ids.Ruleset) string { return ruleset.Filename }

func idsRulesetNamesOf(ruleset ids.Ruleset) []string {
	return []string{ruleset.Filename, ruleset.Description}
}

// idsRulesetSearch returns the matching rule sets in API order with the raw rows for json
func idsRulesetSearch(api *ids.IdsApi, searchPhrase string) ([]ids.Ruleset, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, api.EndpointForPluginControllerMethod("ids", "settings", "list_rulesets"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var rulesets = make([]ids.Ruleset, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &rulesets[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected rule set from OPNsense: %w", err)
		}
	}
	return rulesets, rows, nil
}

func idsRulesetNames(c *Context) []string {
	var api, err = idsApi(c)
	if err != nil {
		return nil
	}
	var rulesets, _, searchErr = idsRulesetSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(rulesets))
	for _, ruleset := range rulesets {
		names = append(names, ruleset.Filename)
	}
	return names
}

func idsRulesetFields(ruleset ids.Ruleset) [][2]string {
	return [][2]string{
		{"filename", ruleset.Filename},
		{"description", ruleset.Description},
		{"disabled", YesNo(Flag(!ruleset.Enabled))},
		{"downloaded", ruleset.ModifiedLocal},
		{"documentation", ruleset.DocumentationUrl},
	}
}

func idsRulesetPrint(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var rulesets, raw, searchErr = idsRulesetSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}
	var shown []ids.Ruleset
	var shownRaw []json.RawMessage
	for i, ruleset := range rulesets {
		if !args.Bool("enabled") || ruleset.Enabled {
			shown = append(shown, ruleset)
			shownRaw = append(shownRaw, raw[i])
		}
	}
	var names = make([]string, len(shown))
	for i, ruleset := range shown {
		names[i] = ruleset.Filename
	}
	switch {
	case args.Bool("json"):
		for _, row := range shownRaw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(shown))
		for i, ruleset := range shown {
			blocks[i] = idsRulesetFields(ruleset)
		}
		c.Details(blocks, names)
	default:
		var rows = make([][]string, len(shown))
		for i, ruleset := range shown {
			rows[i] = []string{YesNo(Flag(!ruleset.Enabled)), ruleset.Filename, ruleset.Description, ruleset.ModifiedLocal}
		}
		c.Items([]string{"DISABLED", "FILENAME", "DESCRIPTION", "DOWNLOADED"}, rows, names)
	}
	return nil
}

// idsRulesetSelect resolves each selector to a rule set
func idsRulesetSelect(c *Context, api *ids.IdsApi, selectors []string) ([]ids.Ruleset, error) {
	var rulesets, _, err = idsRulesetSearch(api, "")
	if err != nil {
		return nil, err
	}
	var selected []ids.Ruleset
	for _, selector := range selectors {
		var ruleset, selectErr = Select(c, selector, rulesets, idsRulesetUuid, idsRulesetNamesOf)
		if selectErr != nil {
			return nil, selectErr
		}
		selected = append(selected, ruleset)
	}
	return selected, nil
}

func idsRulesetShow(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var selected, selectErr = idsRulesetSelect(c, api, []string{args.String("item")})
	if selectErr != nil {
		return selectErr
	}
	c.Fields(idsRulesetFields(selected[0]))
	return nil
}

func idsRulesetEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		var selected, selectErr = idsRulesetSelect(c, api, args.List("item"))
		if selectErr != nil {
			return selectErr
		}
		var filenames []string
		var seen = map[string]bool{}
		for _, ruleset := range selected {
			switch {
			case seen[ruleset.Filename]:
			case ruleset.Enabled == enabled:
				c.Infof("rule set %s is already %s", ruleset.Filename, EnabledWord(enabled))
			default:
				filenames = append(filenames, ruleset.Filename)
			}
			seen[ruleset.Filename] = true
		}
		if len(filenames) == 0 {
			return nil
		}
		return api.RulesetSetEnabled(filenames, enabled)
	}
}

func idsRulesetUpdate(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var background = args.Bool("background")
	if !background {
		c.Infof("downloading the enabled rule sets, this can take a while (Ctrl-C stops waiting)")
	}
	var status, updateErr = api.RulesUpdate(c, background)
	if updateErr != nil {
		if c.Err() != nil {
			c.Infof("stopped waiting, the download goes on on the firewall")
			return nil
		}
		return updateErr
	}
	if background {
		c.Infof("the download runs in the background (job %s), see the DOWNLOADED column of print", status)
	}
	return nil
}

func idsRulesetPropertyPrint(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var properties, getErr = api.RulesetProperties()
	if getErr != nil {
		return getErr
	}
	// the properties are mostly credentials (subscription codes), their values are never printed
	var masked = make(map[string]string, len(properties))
	for name, value := range properties {
		masked[name] = ""
		if value != "" {
			masked[name] = idsMonitSecretShown
		}
	}
	if args.Bool("json") {
		return c.JSON(masked)
	}
	var names = make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	var lines = make([][2]string, len(names))
	for i, name := range names {
		lines[i] = [2]string{name, masked[name]}
	}
	if len(lines) == 0 {
		c.Infof("the installed rule sets have no properties")
		return nil
	}
	c.Fields(lines)
	return nil
}

func idsRulesetPropertyNames(c *Context) []string {
	var api, err = idsApi(c)
	if err != nil {
		return nil
	}
	var properties, getErr = api.RulesetProperties()
	if getErr != nil {
		return nil
	}
	var names []string
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func idsRulesetPropertySet(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var name = strings.TrimSpace(args.String("name"))
	return api.RulesetPropertiesSet(map[string]string{name: args.String("value")})
}
