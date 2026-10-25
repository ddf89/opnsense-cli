package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"regexp"
	"sort"
	"strings"
)

// Firewall > Aliases (api/firewall/alias). Behaviour of OPNsense 26.7 this wrapper relies on:
//   - the built-in aliases (bogons, bogonsv6, sshlockout, virusprot of type external and the __<if>_network aliases of
//     type internal) are generated, their "uuid" is their name. set_item answers "saved" for them without changing
//     anything, del_item and toggle_item answer "not found"/"failed": the library refuses to change them
//   - get_item answers defaults for unknown uuids, existence is checked via search_item
//   - content is one entry per line ("\n"), a comma is not a separator
//   - add_item accepts type internal, which only OPNsense itself should create: refused here
//   - set_item with a new name renames the alias in every reference (rules, other aliases)
//   - del_item of an alias in use is an HTTP 500 {"errorMessage":"Cannot delete alias x. Currently in use by ..."}
//   - nothing reaches pf until reconfigure (AliasReconfigure)

// AliasField* are the API names of the alias fields
const (
	AliasFieldEnabled        = "enabled"
	AliasFieldName           = "name"
	AliasFieldType           = "type"
	AliasFieldPathExpression = "path_expression"
	AliasFieldProto          = "proto"
	AliasFieldInterface      = "interface"
	AliasFieldCounters       = "counters"
	AliasFieldUpdatefreq     = "updatefreq"
	AliasFieldContent        = "content"
	AliasFieldPassword       = "password"
	AliasFieldUsername       = "username"
	AliasFieldAuthtype       = "authtype"
	AliasFieldExpire         = "expire"
	AliasFieldCategories     = "categories"
	AliasFieldDescription    = "description"
)

// AliasFieldNames are the writable fields, in the order of the GUI
var AliasFieldNames = []string{
	AliasFieldEnabled, AliasFieldName, AliasFieldType, AliasFieldProto, AliasFieldInterface, AliasFieldContent,
	AliasFieldUpdatefreq, AliasFieldPathExpression, AliasFieldAuthtype, AliasFieldUsername, AliasFieldPassword,
	AliasFieldExpire, AliasFieldCounters, AliasFieldCategories, AliasFieldDescription,
}

// AliasFieldDefaults are the values of a new alias (and of the fields not given when an alias is replaced)
var AliasFieldDefaults = AliasFields{
	AliasFieldEnabled: "1", AliasFieldProto: "", AliasFieldInterface: "", AliasFieldContent: "", AliasFieldUpdatefreq: "",
	AliasFieldPathExpression: "", AliasFieldAuthtype: "", AliasFieldUsername: "", AliasFieldPassword: "",
	AliasFieldExpire: "", AliasFieldCounters: "0", AliasFieldCategories: "", AliasFieldDescription: "",
}

// AliasVolatileFields are statistics OPNsense adds to every alias (search, export), they are not stored
var AliasVolatileFields = []string{
	"current_items", "last_updated", "eval_nomatch", "eval_match", "in_block_p", "in_block_b", "in_pass_p",
	"in_pass_b", "out_block_p", "out_block_b", "out_pass_p", "out_pass_b",
}

// AliasTypes are the alias types that can be created ("internal" is reserved for the aliases OPNsense generates)
var AliasTypes = []string{
	"host", "network", "port", "url", "urltable", "urljson", "geoip", "networkgroup", "mac", "asn", "dynipv6host",
	"authgroup", "external",
}

// AliasTypeInternal is the type of the generated interface network aliases
const AliasTypeInternal = "internal"

// AliasContentSeparator separates the entries of content
const AliasContentSeparator = "\n"

// aliasNamePattern is the rule of AliasNameField: a letter or single underscore first, at most 31 characters
var aliasNamePattern = regexp.MustCompile(`^([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))$`)

// AliasValidName checks a name like OPNsense does, except the reserved pf keywords and service names (which only
// OPNsense knows)
func AliasValidName(name string) error {
	if !aliasNamePattern.MatchString(name) {
		return fmt.Errorf("%q: an alias name starts with a letter or single underscore and has at most 31 letters, digits or underscores", name)
	}
	return nil
}

// aliasUuidPattern tells a stored alias (uuid) from a built-in one (the uuid is the name)
var aliasUuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Alias is an alias as search_item returns it
type Alias struct {
	Uuid           string `json:"uuid"`
	Enabled        string `json:"enabled"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	PathExpression string `json:"path_expression"`
	Proto          string `json:"proto"`
	Interface      string `json:"interface"`
	Counters       string `json:"counters"`
	Updatefreq     string `json:"updatefreq"`
	// Content has one entry per line; for authgroup aliases search_item answers group names instead of the gids
	Content     string `json:"content"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	Authtype    string `json:"authtype"`
	Expire      string `json:"expire"`
	Categories  string `json:"categories"`
	Description string `json:"description"`
	// CurrentItems is the number of entries of the pf table, "" when it is not loaded
	CurrentItems   string   `json:"current_items"`
	LastUpdated    string   `json:"last_updated"`
	CategoriesUuid []string `json:"categories_uuid"`
}

// BuiltIn tells whether OPNsense generates the alias (bogons, __lan_network, ...), it can not be changed
func (a Alias) BuiltIn() bool {
	return !aliasUuidPattern.MatchString(a.Uuid)
}

// ContentList returns the entries of content
func (a Alias) ContentList() []string {
	if a.Content == "" {
		return []string{}
	}
	return strings.Split(a.Content, AliasContentSeparator)
}

// AliasFields maps API field names (AliasField*) to values: booleans "1"/"0", lists (content) one entry per line,
// proto and categories comma separated
type AliasFields map[string]string

func (opn *FirewallApi) aliasEndpoint(method string, args ...string) string {
	var endpoint = opn.endpoint("firewall", "alias", method)
	for _, arg := range args {
		endpoint += "/" + url.PathEscape(arg)
	}
	return endpoint
}

// AliasList lists the aliases (built-in ones included) sorted by name as OPNsense does, filtered by searchPhrase
// (substring of any field, "" for all)
func (opn *FirewallApi) AliasList(searchPhrase string) ([]Alias, error) {
	var _, aliases, err = opn.AliasListRaw(searchPhrase)
	return aliases, err
}

// AliasListRaw is AliasList with the rows as OPNsense sent them
func (opn *FirewallApi) AliasListRaw(searchPhrase string) ([]json.RawMessage, []Alias, error) {
	var raw, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.aliasEndpoint("search_item"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var aliases = make([]Alias, 0, len(raw))
	for _, row := range raw {
		var alias Alias
		if err := json.Unmarshal(row, &alias); err != nil {
			return nil, nil, fmt.Errorf("could not decode alias %s: %w", row, err)
		}
		if alias.CategoriesUuid == nil {
			alias.CategoriesUuid = []string{}
		}
		aliases = append(aliases, alias)
	}
	return raw, aliases, nil
}

func aliasNotFound(name string) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("alias %s", name)}
}

// AliasGet returns the alias with this uuid (or, for built-in aliases, name), *NotFoundError when there is none
func (opn *FirewallApi) AliasGet(uuid string) (Alias, error) {
	var aliases, err = opn.AliasList("")
	if err != nil {
		return Alias{}, err
	}
	for _, alias := range aliases {
		if strings.EqualFold(alias.Uuid, uuid) {
			return alias, nil
		}
	}
	return Alias{}, aliasNotFound(uuid)
}

// AliasGetByName returns the alias with exactly this name, *NotFoundError when there is none
func (opn *FirewallApi) AliasGetByName(name string) (Alias, error) {
	var aliases, err = opn.AliasList(name)
	if err != nil {
		return Alias{}, err
	}
	for _, alias := range aliases {
		if alias.Name == name {
			return alias, nil
		}
	}
	return Alias{}, aliasNotFound(name)
}

func aliasCheckFields(fields AliasFields) error {
	for name, value := range fields {
		var known = false
		for _, field := range AliasFieldNames {
			known = known || field == name
		}
		if !known {
			return fmt.Errorf("unknown alias field %q", name)
		}
		if name == AliasFieldType && value == AliasTypeInternal {
			return errors.New("aliases of type internal are generated by OPNsense and can not be created")
		}
	}
	return nil
}

// aliasChangeable returns the alias uuid, *NotFoundError when it does not exist, an error for built-in aliases
func (opn *FirewallApi) aliasChangeable(uuid string) (Alias, error) {
	var alias, err = opn.AliasGet(uuid)
	if err != nil {
		return alias, err
	}
	if alias.BuiltIn() {
		return alias, fmt.Errorf("%s is a built-in alias, it can not be changed", alias.Name)
	}
	return alias, nil
}

// AliasCreate adds an alias with fields (missing fields get the OPNsense defaults) and returns its uuid. A
// rejected field (e.g. a name in use) is a *ValidationError keyed by the field name
func (opn *FirewallApi) AliasCreate(fields AliasFields) (string, error) {
	if err := aliasCheckFields(fields); err != nil {
		return "", err
	}
	var uuid, err = opn.Mutate(opn.aliasEndpoint("add_item"), map[string]AliasFields{"alias": fields})
	return uuid, aliasValidationError(err)
}

// AliasUpdate changes the given fields of the alias uuid, the others are kept. A new name is replaced in every
// reference by OPNsense. *NotFoundError when it does not exist (checked first, OPNsense would create it), an error
// for built-in aliases
func (opn *FirewallApi) AliasUpdate(uuid string, fields AliasFields) error {
	if err := aliasCheckFields(fields); err != nil {
		return err
	}
	var alias, err = opn.aliasChangeable(uuid)
	if err != nil {
		return err
	}
	_, err = opn.Mutate(opn.aliasEndpoint("set_item", alias.Uuid), map[string]AliasFields{"alias": fields})
	return aliasValidationError(err)
}

// AliasReplace overwrites all fields of the alias uuid: fields not given get their defaults (AliasFieldDefaults)
func (opn *FirewallApi) AliasReplace(uuid string, fields AliasFields) error {
	var all = AliasFields{}
	for name, value := range AliasFieldDefaults {
		all[name] = value
	}
	for name, value := range fields {
		all[name] = value
	}
	return opn.AliasUpdate(uuid, all)
}

// aliasValidationError strips the "alias." prefix of validation fields
func aliasValidationError(err error) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var stripped = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		stripped[strings.TrimPrefix(field, "alias.")] = message
	}
	return &coreapi.ValidationError{Validations: stripped}
}

// AliasRemove deletes the alias uuid. *NotFoundError when it does not exist, an *HttpError ("Cannot delete alias
// x. Currently in use by ...") when a rule or another alias uses it, an error for built-in aliases
func (opn *FirewallApi) AliasRemove(uuid string) error {
	var alias, err = opn.aliasChangeable(uuid)
	if err != nil {
		return err
	}
	_, err = opn.Mutate(opn.aliasEndpoint("del_item", alias.Uuid), nil)
	if coreapi.IsNotFound(err) {
		return aliasNotFound(alias.Name)
	}
	return err
}

// AliasSetEnabled enables or disables the alias uuid, changed is false when it already was
func (opn *FirewallApi) AliasSetEnabled(uuid string, enabled bool) (changed bool, err error) {
	var alias, aliasErr = opn.aliasChangeable(uuid)
	if aliasErr != nil {
		return false, aliasErr
	}
	if (alias.Enabled == "1") == enabled {
		return false, nil
	}
	var flag = "0"
	if enabled {
		flag = "1"
	}
	var result struct {
		Result string `json:"result"`
	}
	if err := opn.DoJSON("POST", opn.aliasEndpoint("toggle_item", alias.Uuid, flag), struct{}{}, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return true, nil
	case "failed", "not found":
		return false, aliasNotFound(alias.Name)
	default:
		return false, fmt.Errorf("unexpected answer from toggle_item: result %q", result.Result)
	}
}

// AliasReconfigure applies the aliases: reloads the filter and refreshes the pf tables (and URL tables)
func (opn *FirewallApi) AliasReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.aliasEndpoint("reconfigure"), struct{}{}, &result); err != nil {
		return err
	}
	if result.Status != "ok" {
		return fmt.Errorf("alias reconfigure failed: status %q", result.Status)
	}
	return nil
}

// AliasUpdateTables downloads the source of the bogons or geoip aliases and reloads them
func (opn *FirewallApi) AliasUpdateTables(kind string) error {
	if kind != "bogons" && kind != "geoip" {
		return fmt.Errorf("unknown alias update %q, use bogons or geoip", kind)
	}
	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", opn.aliasEndpoint("update", kind), struct{}{}, &result); err != nil {
		return err
	}
	if result.Status != "ok" {
		return fmt.Errorf("updating %s failed: %s", kind, result.Message)
	}
	return nil
}

// AliasCategory is a firewall category with the number of aliases using it
type AliasCategory struct {
	Uuid  string `json:"uuid"`
	Name  string `json:"name"`
	Color string `json:"color"`
	Used  int    `json:"used"`
}

// AliasCategories lists the firewall categories sorted by name, with their use by aliases
func (opn *FirewallApi) AliasCategories() ([]AliasCategory, error) {
	var container struct {
		Rows []AliasCategory `json:"rows"`
	}
	if err := opn.DoJSON("GET", opn.aliasEndpoint("list_categories"), nil, &container); err != nil {
		return nil, err
	}
	if container.Rows == nil {
		container.Rows = []AliasCategory{}
	}
	return container.Rows, nil
}

// AliasCountry is a country code usable in geoip aliases
type AliasCountry struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Region string `json:"region"`
}

// AliasCountries lists the country codes for geoip aliases, sorted by code
func (opn *FirewallApi) AliasCountries() ([]AliasCountry, error) {
	var container map[string]struct {
		Name   string  `json:"name"`
		Region *string `json:"region"`
	}
	if err := opn.DoJSON("GET", opn.aliasEndpoint("list_countries"), nil, &container); err != nil {
		return nil, err
	}
	var countries = make([]AliasCountry, 0, len(container))
	for code, country := range container {
		var region string
		if country.Region != nil {
			region = *country.Region
		}
		countries = append(countries, AliasCountry{Code: code, Name: country.Name, Region: region})
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Code < countries[j].Code })
	return countries, nil
}

// AliasUserGroup is a user group usable in authgroup (OpenVPN group) aliases, the content holds the gids
type AliasUserGroup struct {
	Gid  string `json:"gid"`
	Name string `json:"name"`
}

// AliasUserGroups lists the user groups (without "all") sorted by gid
func (opn *FirewallApi) AliasUserGroups() ([]AliasUserGroup, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.aliasEndpoint("list_user_groups"), nil, &raw); err != nil {
		return nil, err
	}
	var groups = []AliasUserGroup{}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("[]")) {
		return groups, nil // PHP sends an empty array as []
	}
	var container map[string]AliasUserGroup
	if err := json.Unmarshal(raw, &container); err != nil {
		return nil, fmt.Errorf("could not decode the user groups: %w", err)
	}
	for _, group := range container {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].Gid) != len(groups[j].Gid) {
			return len(groups[i].Gid) < len(groups[j].Gid)
		}
		return groups[i].Gid < groups[j].Gid
	})
	return groups, nil
}

// AliasFieldOptions returns the values an option field (e.g. interface, authtype) offers, from the defaults of a
// new alias; "" (none) is left out
func (opn *FirewallApi) AliasFieldOptions(field string) ([]string, error) {
	var container struct {
		Alias map[string]json.RawMessage `json:"alias"`
	}
	if err := opn.DoJSON("GET", opn.aliasEndpoint("get_item"), nil, &container); err != nil {
		return nil, err
	}
	var options map[string]json.RawMessage
	if err := json.Unmarshal(container.Alias[field], &options); err != nil {
		return nil, fmt.Errorf("alias field %s has no options", field)
	}
	var keys = make([]string, 0, len(options))
	for key := range options {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// AliasExport returns the configuration of the aliases uuids as JSON {"aliases":{"alias":{"<uuid>":{...}}}}, the
// format AliasImport reads. Without uuids the whole model is exported (built-in aliases and the geoip settings
// included). The values contain the URL passwords
func (opn *FirewallApi) AliasExport(uuids []string) (json.RawMessage, error) {
	var endpoint = opn.aliasEndpoint("export")
	if len(uuids) > 0 {
		endpoint += "?" + url.Values{"ids": {strings.Join(uuids, ",")}}.Encode()
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// AliasImportResult tells how many aliases an import added and changed
type AliasImportResult struct {
	New      int `json:"new"`
	Existing int `json:"existing"`
}

// AliasImport adds the aliases (keyed by any id, e.g. the uuid of an export) or, when an alias with the same name
// exists, changes the given fields of it. Everything is validated first and only saved when all aliases are valid:
// a *ValidationError keyed "<id>.<field>". OPNsense skips type internal; volatile fields (AliasVolatileFields)
// are left out here
func (opn *FirewallApi) AliasImport(aliases map[string]AliasFields) (AliasImportResult, error) {
	if len(aliases) == 0 {
		return AliasImportResult{}, errors.New("no aliases to import")
	}
	var cleaned = make(map[string]AliasFields, len(aliases))
	for id, fields := range aliases {
		if fields[AliasFieldName] == "" {
			return AliasImportResult{}, fmt.Errorf("alias %s has no name", id)
		}
		var copied = AliasFields{}
		for name, value := range fields {
			var volatile = false
			for _, field := range AliasVolatileFields {
				volatile = volatile || field == name
			}
			if !volatile {
				copied[name] = value
			}
		}
		cleaned[id] = copied
	}

	var body = map[string]any{"data": map[string]any{"aliases": map[string]any{"alias": cleaned}}}
	var result struct {
		AliasImportResult
		Status      string                     `json:"status"`
		Validations coreapi.ValidationMessages `json:"validations"`
	}
	if err := opn.DoJSON("POST", opn.aliasEndpoint("import"), body, &result); err != nil {
		return AliasImportResult{}, err
	}
	switch {
	case result.Status == "ok":
		return result.AliasImportResult, nil
	case len(result.Validations) > 0:
		return AliasImportResult{}, &coreapi.ValidationError{Validations: result.Validations}
	default:
		return AliasImportResult{}, fmt.Errorf("import failed: status %q", result.Status)
	}
}

// AliasParseExport reads an export (AliasExport, also a full one or a file saved by the GUI) into the aliases
// keyed by their id. Values are returned as strings like the API sends them
func AliasParseExport(data []byte) (map[string]AliasFields, error) {
	var export struct {
		Aliases *struct {
			Alias json.RawMessage `json:"alias"`
		} `json:"aliases"`
	}
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("not an alias export: %w", err)
	}
	if export.Aliases == nil {
		return nil, errors.New(`not an alias export: no "aliases" object`)
	}
	var aliases = map[string]AliasFields{}
	var trimmed = bytes.TrimSpace(export.Aliases.Alias)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("null")) {
		return aliases, nil
	}
	var raw map[string]map[string]any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fmt.Errorf(`not an alias export: "aliases.alias" is not an object of aliases: %w`, err)
	}
	for id, fields := range raw {
		var alias = AliasFields{}
		for name, value := range fields {
			switch typed := value.(type) {
			case nil:
				alias[name] = ""
			case string:
				alias[name] = typed
			case bool:
				alias[name] = map[bool]string{true: "1", false: "0"}[typed]
			case float64:
				alias[name] = fmt.Sprint(typed)
			default:
				return nil, fmt.Errorf("alias %s: field %s is not a value", id, name)
			}
		}
		aliases[id] = alias
	}
	return aliases, nil
}
