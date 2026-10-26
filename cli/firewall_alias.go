package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// /firewall/alias: Firewall > Aliases. Items are selected by the # of print, the uuid or the name. The built-in
// aliases (bogons, sshlockout, __lan_network, ...) are listed but can not be changed. Changes reach pf with apply

const (
	firewallAliasItemHelp  = "the #, uuid or name of the alias"
	firewallAliasApplyHint = `Changes are only saved, run "/firewall/alias apply" to load them into pf.`
	// firewallAliasContentShown is the number of content entries print shows
	firewallAliasContentShown = 3
)

// firewallAliasArg maps an argument to its alias field
type firewallAliasArg struct {
	arg   string
	field string
}

// firewallAliasArgs are the field arguments, in the order of show
var firewallAliasArgs = []firewallAliasArg{
	{"name", firewall.AliasFieldName},
	{"type", firewall.AliasFieldType},
	{"content", firewall.AliasFieldContent},
	{"proto", firewall.AliasFieldProto},
	{"interface", firewall.AliasFieldInterface},
	{"updatefreq", firewall.AliasFieldUpdatefreq},
	{"path-expression", firewall.AliasFieldPathExpression},
	{"authtype", firewall.AliasFieldAuthtype},
	{"username", firewall.AliasFieldUsername},
	{"password", firewall.AliasFieldPassword},
	{"expire", firewall.AliasFieldExpire},
	{"counters", firewall.AliasFieldCounters},
	{"categories", firewall.AliasFieldCategories},
	{"description", firewall.AliasFieldDescription},
}

func firewallAliasFieldArgs(add bool) []Arg {
	return []Arg{
		{Name: "name", Required: add, Validate: firewall.AliasValidName,
			Help: "the name used in rules: a letter or underscore first, at most 31 letters, digits and underscores"},
		{Name: "type", Required: add, Values: firewall.AliasTypes,
			Help: "host, network, port, url (IPs of a list), urltable, urljson, geoip, networkgroup, mac, asn, dynipv6host, authgroup (OpenVPN group), external"},
		{Name: "content", Type: List, Help: "the entries, comma separated: addresses/ranges/host names (host), networks (network), " +
			"ports or ranges 80:90 (port), URLs (url*), country codes (geoip, see countries), alias names (networkgroup), " +
			"MAC addresses, AS numbers, partial IPv6 addresses ::1000 (dynipv6host), group names (authgroup)"},
		{Name: "proto", Type: List, Values: []string{"IPv4", "IPv6"}, Help: "address families of geoip and asn aliases"},
		{Name: "interface", Complete: firewallAliasCompleteInterfaces, Help: "interface whose IPv6 prefix a dynipv6host alias tracks"},
		{Name: "updatefreq", Validate: firewallAliasValidateDays, Help: "refresh interval of host, urltable and urljson aliases in days, e.g. 1 or 0.5"},
		{Name: "path-expression", Help: "urljson: the field to select, e.g. container.fieldname (or a jq expression)"},
		{Name: "authtype", Values: []string{"Basic", "Bearer", "Header"}, Help: "authentication for url aliases (empty for none)"},
		{Name: "username", Help: "url alias authentication: user (Basic) or header name (Header)"},
		{Name: "password", Help: "url alias authentication: password (Basic), token (Bearer) or header value (Header)"},
		{Name: "expire", Validate: firewallAliasValidateExpire, Help: "external aliases: seconds after which unused addresses are purged (60-999999999)"},
		{Name: "counters", Type: Bool, Help: "keep packet counters per table entry"},
		{Name: "categories", Type: List, Complete: firewallAliasCompleteCategories, Help: "categories, comma separated names"},
		{Name: "description", Help: "what the alias is for"},
		{Name: "disabled", Type: Bool, Help: "keep the alias, but do not load it"},
	}
}

func init() {
	var menu = Root.Menu("firewall/alias")
	menu.Help = "aliases: named lists of hosts, networks, ports, URLs, countries, ... used in rules (Firewall > Aliases)"
	var item = Arg{Name: "item", Positional: true, Required: true, Help: firewallAliasItemHelp, Complete: firewallAliasCompleteNames}

	menu.Add(
		&Command{
			Name: "print",
			Help: "list the aliases (built-in ones included) with their content and table entries",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every alias"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only aliases where any field contains this text"},
				{Name: "type", Values: append(append([]string{}, firewall.AliasTypes...), firewall.AliasTypeInternal), Help: "only aliases of this type"},
				{Name: "category", Complete: firewallAliasCompleteCategories, Help: "only aliases in this category"},
			},
			Run: firewallAliasPrint,
		},
		&Command{Name: "show", Help: "show all fields of an alias", Args: []Arg{item}, Run: firewallAliasShow},
		&Command{
			Name: "add",
			Help: "add an alias, prints its uuid",
			Long: `An alias with the same name makes add fail unless replace is given, then that alias is replaced
completely (arguments not given are reset to their defaults).
` + firewallAliasApplyHint,
			Args:  append(firewallAliasFieldArgs(true), Arg{Name: "replace", Type: Bool, Help: "replace the alias with the same name"}),
			Check: firewallAliasCheckAdd,
			Run:   firewallAliasAdd,
		},
		&Command{
			Name: "set",
			Help: "change fields of an alias, the others are kept",
			Long: `name= renames the alias, OPNsense also renames it in the rules and aliases using it.
` + firewallAliasApplyHint,
			Args: append([]Arg{item}, firewallAliasFieldArgs(false)...),
			Check: func(args *Args) error {
				for _, spec := range firewallAliasFieldArgs(false) {
					if args.Has(spec.Name) {
						return nil
					}
				}
				return errors.New("nothing to set, give at least one field like content=")
			},
			Run: firewallAliasSet,
		},
		&Command{Name: "remove", Help: "remove an alias (not while rules or aliases use it)", Long: firewallAliasApplyHint,
			Args: []Arg{item}, Run: firewallAliasRemove},
		&Command{Name: "enable", Help: "enable an alias", Long: firewallAliasApplyHint, Args: []Arg{item}, Run: firewallAliasEnabler(true)},
		&Command{Name: "disable", Help: "disable an alias", Long: firewallAliasApplyHint, Args: []Arg{item}, Run: firewallAliasEnabler(false)},
		&Command{
			Name: "apply",
			Help: "load the aliases into pf: reload the filter and refresh the alias tables",
			Long: `Also hands a changed GeoIP URL (/firewall/alias/geoip) to the GeoIP updater.`,
			Run:  firewallAliasApply,
		},
		&Command{
			Name: "export",
			Help: "write the configuration of aliases as JSON (the format of import and the GUI)",
			Long: `Exports all aliases except the built-in ones unless items= names some. The file contains the
passwords of URL aliases; it is written with mode 0600, an existing file is only replaced with overwrite.`,
			Args: []Arg{
				{Name: "items", Type: List, Complete: firewallAliasCompleteNames, Help: "the aliases to export (# of print, uuid or name), comma separated"},
				{Name: "file", Default: "-", Help: "file to write, - for stdout"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: firewallAliasExport,
		},
		&Command{
			Name: "import",
			Help: "add the aliases of an export file",
			Long: `Reads a file written by export (or the GUI). Aliases with a name that exists already are only
changed with replace (the fields in the file overwrite theirs). Built-in aliases in the file are skipped. All
aliases are validated first, nothing is saved when one is invalid.
` + firewallAliasApplyHint,
			Args: []Arg{
				{Name: "file", Required: true, Help: "the export file"},
				{Name: "replace", Type: Bool, Help: "change the existing aliases with the same names"},
			},
			Run: firewallAliasImport,
		},
		&Command{
			Name: "categories",
			Help: "list the firewall categories with the number of aliases using them",
			Args: []Arg{{Name: "json", Type: Bool, Help: "one JSON object per line"}},
			Run:  firewallAliasCategories,
		},
		&Command{
			Name: "countries",
			Help: "list the country codes for geoip aliases",
			Args: []Arg{
				{Name: "json", Type: Bool, Help: "one JSON object per line"},
				{Name: "search", Help: "only countries whose code, name or region contains this text"},
			},
			Run: firewallAliasCountries,
		},
	)
}

// --- validation

func firewallAliasValidateDays(value string) error {
	if value == "" {
		return nil
	}
	if days, err := strconv.ParseFloat(value, 64); err != nil || days < 0 {
		return fmt.Errorf("must be a number of days like 1 or 0.5, got %q", value)
	}
	return nil
}

func firewallAliasValidateExpire(value string) error {
	return ValidateRange(60, 999999999)(value)
}

var (
	firewallAliasMacPattern     = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){1,5}$`)
	firewallAliasCountryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

// firewallAliasCheckContent checks the entries of the types OPNsense validates strictly, the others (host names,
// ranges, nested aliases) are left to OPNsense
func firewallAliasCheckContent(aliasType string, entries []string) error {
	for _, entry := range entries {
		var err error
		switch aliasType {
		case "port":
			if firewall.AliasValidName(entry) == nil {
				continue // an alias
			}
			for _, port := range strings.SplitN(entry, ":", 2) {
				if ValidatePort(port) != nil || port == "" {
					err = errors.New("not a port or port range like 80:90")
				}
			}
		case "mac":
			if !firewallAliasMacPattern.MatchString(entry) {
				err = errors.New("not a (partial) MAC address like 00:11:22")
			}
		case "asn":
			if number, parseErr := strconv.ParseUint(entry, 10, 64); parseErr != nil || number < 1 || number > 4294967296 {
				err = errors.New("not an AS number")
			}
		case "geoip":
			if !firewallAliasCountryPattern.MatchString(entry) {
				err = errors.New("not a country code like NL, see countries")
			}
		case "networkgroup":
			if firewall.AliasValidName(entry) != nil {
				err = errors.New("not an alias name")
			}
		}
		if err != nil {
			return fmt.Errorf("content: %q is %s", entry, err)
		}
	}
	return nil
}

func firewallAliasCheckAdd(args *Args) error {
	switch strings.ToLower(args.String("type")) {
	case "dynipv6host":
		if args.String("interface") == "" {
			return errors.New("a dynipv6host alias needs interface=")
		}
	case "port":
		if len(args.List("content")) == 0 {
			return errors.New("a port alias needs content=")
		}
	}
	if args.String("interface") != "" && !strings.EqualFold(args.String("type"), "dynipv6host") {
		return errors.New("interface= is only used by dynipv6host aliases")
	}
	return nil
}

// --- selection and display

func firewallAliasSelect(c *Context, aliases []firewall.Alias, selector string) (firewall.Alias, error) {
	return Select(c, selector, aliases, func(a firewall.Alias) string { return a.Uuid },
		func(a firewall.Alias) []string { return []string{a.Name} })
}

// firewallAliasCategoryNames maps category uuids to names, only loaded when an alias has categories
func firewallAliasCategoryNames(api *firewall.FirewallApi, aliases []firewall.Alias) (map[string]string, error) {
	var names = map[string]string{}
	for _, alias := range aliases {
		if len(alias.CategoriesUuid) == 0 {
			continue
		}
		var categories, err = api.AliasCategories()
		if err != nil {
			return nil, err
		}
		for _, category := range categories {
			names[category.Uuid] = category.Name
		}
		break
	}
	return names, nil
}

func firewallAliasCategoriesOf(alias firewall.Alias, names map[string]string) []string {
	var result = make([]string, 0, len(alias.CategoriesUuid))
	for _, uuid := range alias.CategoriesUuid {
		if name, ok := names[uuid]; ok {
			result = append(result, name)
		} else {
			result = append(result, uuid)
		}
	}
	return result
}

// firewallAliasContentSummary shows the first entries of content
func firewallAliasContentSummary(alias firewall.Alias) string {
	var entries = alias.ContentList()
	if len(entries) <= firewallAliasContentShown {
		return strings.Join(entries, ",")
	}
	return fmt.Sprintf("%s,... (%d)", strings.Join(entries[:firewallAliasContentShown], ","), len(entries))
}

func firewallAliasFields(alias firewall.Alias, categories map[string]string) [][2]string {
	var password = ""
	if alias.Password != "" {
		password = "********"
	}
	return [][2]string{
		{"name", alias.Name},
		{"uuid", alias.Uuid},
		{"type", alias.Type},
		{"disabled", YesNo(Flag(alias.Enabled != "1"))},
		{"content", strings.Join(alias.ContentList(), ",")},
		{"proto", alias.Proto},
		{"interface", alias.Interface},
		{"updatefreq", alias.Updatefreq},
		{"path-expression", alias.PathExpression},
		{"authtype", alias.Authtype},
		{"username", alias.Username},
		{"password", password},
		{"expire", alias.Expire},
		{"counters", YesNo(alias.Counters)},
		{"categories", strings.Join(firewallAliasCategoriesOf(alias, categories), ",")},
		{"description", alias.Description},
		{"entries", alias.CurrentItems},
		{"last-updated", alias.LastUpdated},
		{"built-in", YesNo(Flag(alias.BuiltIn()))},
	}
}

func firewallAliasPrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	raw, aliases, err := api.AliasListRaw(args.String("search"))
	if err != nil {
		return err
	}
	var keepRaw = make([]json.RawMessage, 0, len(raw))
	var keep = make([]firewall.Alias, 0, len(aliases))
	for i, alias := range aliases {
		if !args.Has("type") || strings.EqualFold(alias.Type, args.String("type")) {
			keepRaw = append(keepRaw, raw[i])
			keep = append(keep, alias)
		}
	}
	categories, err := firewallAliasCategoryNames(api, keep)
	if err != nil {
		return err
	}
	if wantCategory := args.String("category"); wantCategory != "" {
		var filteredRaw = make([]json.RawMessage, 0, len(keep))
		var filtered = make([]firewall.Alias, 0, len(keep))
		for i, alias := range keep {
			if containsFold(firewallAliasCategoriesOf(alias, categories), wantCategory) || containsFold(alias.CategoriesUuid, wantCategory) {
				filteredRaw = append(filteredRaw, keepRaw[i])
				filtered = append(filtered, alias)
			}
		}
		keepRaw, keep = filteredRaw, filtered
	}

	var uuids = make([]string, 0, len(keep))
	for _, alias := range keep {
		uuids = append(uuids, alias.Uuid)
	}
	switch {
	case args.Bool("json"):
		for _, row := range keepRaw {
			if err := c.JSON(row); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(keep))
		for _, alias := range keep {
			items = append(items, firewallAliasFields(alias, categories))
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, 0, len(keep))
		for _, alias := range keep {
			rows = append(rows, []string{
				alias.Name, alias.Type, firewallAliasContentSummary(alias), alias.CurrentItems,
				YesNo(Flag(alias.Enabled != "1")), strings.Join(firewallAliasCategoriesOf(alias, categories), ","), alias.Description,
			})
		}
		c.Items([]string{"NAME", "TYPE", "CONTENT", "ENTRIES", "DISABLED", "CATEGORIES", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func firewallAliasShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	aliases, err := api.AliasList("")
	if err != nil {
		return err
	}
	alias, err := firewallAliasSelect(c, aliases, args.String("item"))
	if err != nil {
		return err
	}
	categories, err := firewallAliasCategoryNames(api, []firewall.Alias{alias})
	if err != nil {
		return err
	}
	c.Fields(firewallAliasFields(alias, categories))
	return nil
}

// --- add / set

// firewallAliasCollect turns the given field arguments into alias fields. aliasType is the type the alias will
// have (for the content conversion of authgroup aliases)
func firewallAliasCollect(api *firewall.FirewallApi, args *Args, aliasType string) (firewall.AliasFields, error) {
	var fields = firewall.AliasFields{}
	for _, spec := range firewallAliasArgs {
		if !args.Has(spec.arg) {
			continue
		}
		var value = args.String(spec.arg)
		switch spec.field {
		case firewall.AliasFieldType:
			value = strings.ToLower(value)
		case firewall.AliasFieldCounters:
			value = Flag(args.Bool(spec.arg))
		case firewall.AliasFieldProto:
			value = strings.Join(firewallAliasCanonical(args.List(spec.arg), []string{"IPv4", "IPv6"}), ",")
		case firewall.AliasFieldAuthtype:
			if canonical := firewallAliasCanonical([]string{value}, []string{"Basic", "Bearer", "Header"}); value != "" {
				value = canonical[0]
			}
		case firewall.AliasFieldContent:
			var entries = args.List(spec.arg)
			if err := firewallAliasCheckContent(aliasType, entries); err != nil {
				return nil, err
			}
			if aliasType == "authgroup" {
				var gids, err = firewallAliasGroupIds(api, entries)
				if err != nil {
					return nil, err
				}
				entries = gids
			}
			value = strings.Join(entries, firewall.AliasContentSeparator)
		case firewall.AliasFieldCategories:
			var uuids, err = firewallAliasCategoryUuids(api, args.List(spec.arg))
			if err != nil {
				return nil, err
			}
			value = strings.Join(uuids, ",")
		}
		fields[spec.field] = value
	}
	if args.Has("disabled") {
		fields[firewall.AliasFieldEnabled] = Flag(!args.Bool("disabled"))
	}
	return fields, nil
}

// firewallAliasCanonical spells values like known does (the arguments are matched case-insensitively)
func firewallAliasCanonical(values []string, known []string) []string {
	var result = make([]string, 0, len(values))
	for _, value := range values {
		for _, candidate := range known {
			if strings.EqualFold(candidate, value) {
				value = candidate
			}
		}
		result = append(result, value)
	}
	return result
}

// firewallAliasGroupIds maps group names (or gids) to the gids authgroup aliases store
func firewallAliasGroupIds(api *firewall.FirewallApi, entries []string) ([]string, error) {
	var groups, err = api.AliasUserGroups()
	if err != nil {
		return nil, err
	}
	var gids = make([]string, 0, len(entries))
	for _, entry := range entries {
		var gid string
		for _, group := range groups {
			if group.Gid == entry || strings.EqualFold(group.Name, entry) {
				gid = group.Gid
			}
		}
		if gid == "" {
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("user group %q", entry)}
		}
		gids = append(gids, gid)
	}
	return gids, nil
}

// firewallAliasCategoryUuids maps category names (or uuids) to uuids
func firewallAliasCategoryUuids(api *firewall.FirewallApi, names []string) ([]string, error) {
	if len(names) == 0 {
		return []string{}, nil
	}
	var categories, err = api.AliasCategories()
	if err != nil {
		return nil, err
	}
	var uuids = make([]string, 0, len(names))
	for _, name := range names {
		var uuid string
		for _, category := range categories {
			if strings.EqualFold(category.Name, name) || strings.EqualFold(category.Uuid, name) {
				uuid = category.Uuid
			}
		}
		if uuid == "" {
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("category %q, see categories", name)}
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

// firewallAliasError renames the fields of a validation error to the argument names
func firewallAliasError(err error) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var renamed = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		renamed[firewallAliasArgOf(field)] = message
	}
	return &coreapi.ValidationError{Validations: renamed}
}

func firewallAliasArgOf(field string) string {
	for _, spec := range firewallAliasArgs {
		if spec.field == field {
			return spec.arg
		}
	}
	return field
}

func firewallAliasAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	fields, err := firewallAliasCollect(api, args, strings.ToLower(args.String("type")))
	if err != nil {
		return err
	}
	if !args.Has("disabled") {
		fields[firewall.AliasFieldEnabled] = "1"
	}

	var name = args.String("name")
	existing, err := api.AliasGetByName(name)
	switch {
	case err == nil && existing.BuiltIn():
		return fmt.Errorf("%s is a built-in alias, it can not be replaced", name)
	case err == nil && !args.Bool("replace"):
		return fmt.Errorf("an alias named %s exists already (%s), add replace to replace it", name, existing.Uuid)
	case err == nil:
		if err := api.AliasReplace(existing.Uuid, fields); err != nil {
			return firewallAliasError(err)
		}
		c.Infof("replaced the existing alias %s", name)
		c.Println(existing.Uuid)
		return nil
	case !coreapi.IsNotFound(err):
		return err
	}

	uuid, err := api.AliasCreate(fields)
	if err != nil {
		return firewallAliasError(err)
	}
	c.Println(uuid)
	return nil
}

func firewallAliasSet(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	aliases, err := api.AliasList("")
	if err != nil {
		return err
	}
	alias, err := firewallAliasSelect(c, aliases, args.String("item"))
	if err != nil {
		return err
	}
	if alias.BuiltIn() {
		return fmt.Errorf("%s is a built-in alias, it can not be changed", alias.Name)
	}
	var aliasType = alias.Type
	if args.Has("type") {
		aliasType = strings.ToLower(args.String("type"))
	}
	if aliasType == "dynipv6host" && args.Has("interface") && args.String("interface") == "" {
		return errors.New("a dynipv6host alias needs interface=")
	}
	if args.String("interface") != "" && aliasType != "dynipv6host" {
		return errors.New("interface= is only used by dynipv6host aliases")
	}
	fields, err := firewallAliasCollect(api, args, aliasType)
	if err != nil {
		return err
	}
	return firewallAliasError(api.AliasUpdate(alias.Uuid, fields))
}

// --- remove / enable / disable / apply

func firewallAliasRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	aliases, err := api.AliasList("")
	if err != nil {
		return err
	}
	alias, err := firewallAliasSelect(c, aliases, args.String("item"))
	if err != nil {
		return err
	}
	return api.AliasRemove(alias.Uuid)
}

func firewallAliasEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = firewallApi(c)
		if err != nil {
			return err
		}
		aliases, err := api.AliasList("")
		if err != nil {
			return err
		}
		alias, err := firewallAliasSelect(c, aliases, args.String("item"))
		if err != nil {
			return err
		}
		changed, err := api.AliasSetEnabled(alias.Uuid, enabled)
		if err != nil {
			return err
		}
		if !changed {
			c.Infof("alias %s is already %s", alias.Name, EnabledWord(enabled))
		}
		return nil
	}
}

func firewallAliasApply(c *Context, _ *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasReconfigure()
}

// --- export / import

func firewallAliasExport(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	aliases, err := api.AliasList("")
	if err != nil {
		return err
	}
	var uuids []string
	if args.Has("items") {
		for _, selector := range args.List("items") {
			var alias, selectErr = firewallAliasSelect(c, aliases, selector)
			if selectErr != nil {
				return selectErr
			}
			uuids = append(uuids, alias.Uuid)
		}
	} else {
		for _, alias := range aliases {
			if !alias.BuiltIn() {
				uuids = append(uuids, alias.Uuid)
			}
		}
	}

	var content = []byte("{\n    \"aliases\": {\n        \"alias\": {}\n    }\n}")
	if len(uuids) > 0 { // without ids OPNsense exports everything
		var raw, exportErr = api.AliasExport(uuids)
		if exportErr != nil {
			return exportErr
		}
		content = raw
	} else {
		c.Infof("no aliases to export")
	}
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}

	var file = args.String("file")
	if file == "-" {
		_, err = c.Out.Write(content)
		return err
	}
	if err := firewallAliasWriteFile(file, content, args.Bool("overwrite")); err != nil {
		return err
	}
	c.Infof("saved %d aliases to %s", len(uuids), file)
	return nil
}

// firewallAliasWriteFile writes content with mode 0600, an existing file only with overwrite
func firewallAliasWriteFile(name string, content []byte, overwrite bool) error {
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	var file, err = os.OpenFile(name, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", name)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func firewallAliasImport(c *Context, args *Args) error {
	var data, err = os.ReadFile(args.String("file"))
	if err != nil {
		return err
	}
	imported, err := firewall.AliasParseExport(data)
	if err != nil {
		return fmt.Errorf("%s: %w", args.String("file"), err)
	}
	api, err := firewallApi(c)
	if err != nil {
		return err
	}
	aliases, err := api.AliasList("")
	if err != nil {
		return err
	}
	var existing = map[string]firewall.Alias{}
	for _, alias := range aliases {
		existing[alias.Name] = alias
	}

	var ids = make([]string, 0, len(imported))
	for id := range imported {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var names = map[string]string{} // id -> name, for the validation messages
	var replaced []string
	for _, id := range ids {
		var fields = imported[id]
		var name = fields[firewall.AliasFieldName]
		if name == "" {
			return fmt.Errorf("%s: alias %s has no name", args.String("file"), id)
		}
		var current, exists = existing[name]
		if fields[firewall.AliasFieldType] == firewall.AliasTypeInternal || (exists && current.BuiltIn()) {
			c.Infof("skipped the built-in alias %s", name)
			delete(imported, id)
			continue
		}
		if exists {
			replaced = append(replaced, name)
		}
		names[id] = name
	}
	if len(replaced) > 0 && !args.Bool("replace") {
		return fmt.Errorf("aliases with these names exist already: %s, add replace to change them", strings.Join(replaced, ", "))
	}
	if len(imported) == 0 {
		return errors.New("no aliases to import")
	}

	result, err := api.AliasImport(imported)
	if err != nil {
		var validation *coreapi.ValidationError
		if errors.As(err, &validation) {
			var renamed = map[string]string{}
			for field, message := range validation.Validations {
				var id, name, found = strings.Cut(field, ".")
				if alias, ok := names[id]; ok && found {
					field = alias + "." + firewallAliasArgOf(name)
				}
				renamed[field] = message
			}
			return &coreapi.ValidationError{Validations: renamed}
		}
		return err
	}
	c.Infof("imported %d new and %d changed aliases", result.New, result.Existing)
	return nil
}

// --- lookups

func firewallAliasCategories(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	categories, err := api.AliasCategories()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, category := range categories {
			if err := c.JSON(category); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(categories))
	for _, category := range categories {
		rows = append(rows, []string{category.Name, category.Color, strconv.Itoa(category.Used)})
	}
	c.Table([]string{"NAME", "COLOR", "ALIASES"}, rows)
	return nil
}

func firewallAliasCountries(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	countries, err := api.AliasCountries()
	if err != nil {
		return err
	}
	if search := strings.ToLower(args.String("search")); search != "" {
		countries = coreapi.Filter(countries, func(country firewall.AliasCountry) bool {
			return strings.Contains(strings.ToLower(country.Code+"\x00"+country.Name+"\x00"+country.Region), search)
		})
	}
	if args.Bool("json") {
		for _, country := range countries {
			if err := c.JSON(country); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(countries))
	for _, country := range countries {
		rows = append(rows, []string{country.Code, country.Name, country.Region})
	}
	c.Table([]string{"CODE", "NAME", "REGION"}, rows)
	return nil
}

// --- completion, errors are ignored

func firewallAliasCompleteNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var aliases, listErr = api.AliasList("")
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(aliases))
	for _, alias := range aliases {
		names = append(names, alias.Name)
	}
	return names
}

func firewallAliasCompleteCategories(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var categories, listErr = api.AliasCategories()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(categories))
	for _, category := range categories {
		names = append(names, category.Name)
	}
	return names
}

func firewallAliasCompleteInterfaces(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var options, optionsErr = api.AliasFieldOptions(firewall.AliasFieldInterface)
	if optionsErr != nil {
		return nil
	}
	return options
}
