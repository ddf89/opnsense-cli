package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ipsec"
)

// Shared parts of the /vpn/ipsec menus (VPN > IPsec): a small engine for the configuration lists (connection,
// local, remote, child, pool, vti, manual-spd, pre-shared-key, key-pair) and the settings. A list is described by
// a vpnIpsecItems value (its field arguments, columns, natural key, API functions), vpnIpsecRegister adds the
// print, show, add, set, remove, enable and disable commands. Secrets (pre-shared keys, private keys) are never
// shown, not even in json

func init() {
	Root.Menu("vpn/ipsec").Help = "IPsec connections, keys, tunnel interfaces, settings and status (VPN > IPsec)"
}

const (
	vpnIpsecApplyHint = `Changes are only saved, run "/vpn/ipsec/service reconfigure" to apply them.`
	vpnIpsecMasked    = "********"
)

// vpnIpsecApi returns the IPsec API on the session's connection
func vpnIpsecApi(c *Context) (*ipsec.IPsecApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &ipsec.IPsecApi{OPNsense: opn}, nil
}

// --- field arguments

// vpnIpsecKind says how an argument value maps to the API value
type vpnIpsecKind int

const (
	vpnIpsecPlain      vpnIpsecKind = iota
	vpnIpsecFlag                    // yes/no as 1/0
	vpnIpsecDisabled                // the disabled argument for the enabled field
	vpnIpsecList                    // comma separated
	vpnIpsecMapped                  // one of a fixed set of words, mapped to the API values (version=ikev2 is "2")
	vpnIpsecRef                     // an option key, given by key or option description (certificates, groups, ...)
	vpnIpsecRefList                 // several option keys, like vpnIpsecRef
	vpnIpsecConnection              // the uuid of a connection, given by uuid or description
	vpnIpsecSecret                  // plain, never shown
	vpnIpsecFile                    // the content of a local file, never shown (key pairs)
	vpnIpsecPresent                 // only shown: yes when the field is set (a private key)
)

type vpnIpsecField struct {
	Arg
	field   string
	kind    vpnIpsecKind
	mapping [][2]string // vpnIpsecMapped: {argument value, API value}
	keys    bool        // vpnIpsecRefList: the option keys are the names (proposals), shown as they are
}

// vpnIpsecMap returns a mapped field, the argument values are the first elements of mapping
func vpnIpsecMap(arg Arg, field string, mapping ...[2]string) vpnIpsecField {
	for _, pair := range mapping {
		arg.Values = append(arg.Values, pair[0])
	}
	return vpnIpsecField{Arg: arg, field: field, kind: vpnIpsecMapped, mapping: mapping}
}

func vpnIpsecArgs(fields []vpnIpsecField) []Arg {
	var args = make([]Arg, len(fields))
	for i, field := range fields {
		args[i] = field.Arg
	}
	return args
}

// vpnIpsecRequired marks an argument as required for add
func vpnIpsecRequired(add bool, arg Arg) Arg {
	arg.Required = add
	return arg
}

// --- validation

func vpnIpsecValidateText(value string) error {
	for _, char := range value {
		if char < ' ' || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func vpnIpsecNotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty")
	}
	return vpnIpsecValidateText(value)
}

// vpnIpsecValidateNetworks accepts comma separated networks in CIDR notation or addresses
func vpnIpsecValidateNetworks(value string) error {
	for _, element := range splitList(value) {
		if err := vpnIpsecValidateNetwork(element); err != nil {
			return err
		}
	}
	return nil
}

// vpnIpsecValidateNetwork accepts a network in CIDR notation or an address, "" clears
func vpnIpsecValidateNetwork(value string) error {
	if value == "" {
		return nil
	}
	if ValidateIP(value) == nil {
		return nil
	}
	if _, err := vpnIpsecParseCIDR(value); err != nil {
		return fmt.Errorf("must be a network in CIDR notation like 192.0.2.0/24 or an address, got %q", value)
	}
	return nil
}

// vpnIpsecParseCIDR parses a network in CIDR notation
func vpnIpsecParseCIDR(value string) (*net.IPNet, error) {
	var _, network, err = net.ParseCIDR(value)
	return network, err
}

// vpnIpsecValidateCIDR accepts exactly one network in CIDR notation
func vpnIpsecValidateCIDR(value string) error {
	if _, err := vpnIpsecParseCIDR(value); err != nil {
		return fmt.Errorf("must be a network in CIDR notation like 192.0.2.0/24, got %q", value)
	}
	return nil
}

// --- lookups

// vpnIpsecCanonical returns value in the spelling of values (the API keys are case-sensitive)
func vpnIpsecCanonical(values []string, value string) string {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return candidate
		}
	}
	return value
}

// vpnIpsecOptionNames returns the option descriptions of a form field (or the keys), for completion
func vpnIpsecOptionNames(form ipsec.Form, field string, keys bool) []string {
	var names []string
	for _, option := range form.Options(field) {
		if keys {
			names = append(names, option.Key)
		} else if text := strings.TrimSpace(option.Description); text != "" {
			names = append(names, text)
		}
	}
	return names
}

// vpnIpsecCompleteRef completes a reference argument with the option names of a form
func vpnIpsecCompleteRef(form func(api *ipsec.IPsecApi) (ipsec.Form, error), field string, keys bool) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = vpnIpsecApi(c)
		if err != nil {
			return nil
		}
		var values, formErr = form(api)
		if formErr != nil {
			return nil
		}
		return vpnIpsecOptionNames(values, field, keys)
	}
}

// vpnIpsecResolveRef maps a reference given by key or option description to the option key
func vpnIpsecResolveRef(form ipsec.Form, field string, argName string, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	var options = form.Options(field)
	for _, option := range options {
		if strings.EqualFold(option.Key, value) {
			return option.Key, nil
		}
	}
	var matches []ipsec.Option
	for _, option := range options {
		if strings.EqualFold(strings.TrimSpace(option.Description), value) {
			matches = append(matches, option)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Key, nil
	case 0:
		var names []string
		for _, option := range options {
			names = append(names, fmt.Sprintf("%q", strings.TrimSpace(option.Description)))
		}
		switch {
		case len(names) == 0:
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, there is nothing to choose from", argName, value)}
		case len(names) > 20:
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q (TAB completes the %d choices)", argName, value, len(names))}
		}
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, valid are: %s", argName, value, strings.Join(names, ", "))}
	default:
		var keys = make([]string, len(matches))
		for i, match := range matches {
			keys[i] = match.Key
		}
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, give the key instead", argName, value, strings.Join(keys, ", "))}
	}
}

// vpnIpsecRefText renders option keys by their description
func vpnIpsecRefText(form ipsec.Form, field string, value string) string {
	if value == "" {
		return ""
	}
	var texts []string
	for _, key := range strings.Split(value, ",") {
		var text = key
		for _, option := range form[field].Options {
			if option.Key == key && strings.TrimSpace(option.Description) != "" {
				text = strings.TrimSpace(option.Description)
				break
			}
		}
		texts = append(texts, text)
	}
	return strings.Join(texts, ",")
}

// vpnIpsecConnectionResolve returns the uuid of the connection given by uuid or description
func vpnIpsecConnectionResolve(api *ipsec.IPsecApi, value string) (string, error) {
	var connections, err = api.ConnectionList("")
	if err != nil {
		return "", err
	}
	for _, connection := range connections {
		if strings.EqualFold(connection.Uuid(), value) {
			return connection.Uuid(), nil
		}
	}
	var matches = coreapi.Filter(connections, func(connection ipsec.Record) bool {
		return strings.EqualFold(connection.Value("description"), value)
	})
	switch len(matches) {
	case 0:
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("connection %q, give the uuid or description of a connection", value)}
	case 1:
		return matches[0].Uuid(), nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid()
		}
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("connection %q matches %s, give the uuid", value, strings.Join(uuids, ", "))}
	}
}

// vpnIpsecConnectionNames completes connection arguments with the descriptions
func vpnIpsecConnectionNames(c *Context) []string {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return nil
	}
	var connections, listErr = api.ConnectionList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, connection := range connections {
		if description := connection.Value("description"); description != "" {
			names = append(names, description)
		}
	}
	return names
}

// vpnIpsecFieldsOf returns the given field arguments as API fields, references resolved. form is fetched on
// first use of a reference
func vpnIpsecFieldsOf(api *ipsec.IPsecApi, args *Args, specs []vpnIpsecField, form func(api *ipsec.IPsecApi) (ipsec.Form, error)) (ipsec.Fields, error) {
	var fields = ipsec.Fields{}
	var values ipsec.Form
	for _, spec := range specs {
		if !args.Has(spec.Name) {
			continue
		}
		var value = strings.TrimSpace(args.String(spec.Name))
		switch spec.kind {
		case vpnIpsecFlag:
			fields[spec.field] = Flag(args.Bool(spec.Name))
		case vpnIpsecDisabled:
			fields[spec.field] = Flag(!args.Bool(spec.Name))
		case vpnIpsecList:
			var elements = args.List(spec.Name)
			for i := range elements {
				elements[i] = vpnIpsecCanonical(spec.Values, elements[i])
			}
			fields[spec.field] = strings.Join(elements, ",")
		case vpnIpsecMapped:
			for _, pair := range spec.mapping {
				if strings.EqualFold(pair[0], value) {
					fields[spec.field] = pair[1]
				}
			}
		case vpnIpsecConnection:
			var uuid, err = vpnIpsecConnectionResolve(api, value)
			if err != nil {
				return nil, err
			}
			fields[spec.field] = uuid
		case vpnIpsecRef, vpnIpsecRefList:
			if values == nil && value != "" {
				var err error
				if values, err = form(api); err != nil {
					return nil, err
				}
			}
			var elements = []string{value}
			if spec.kind == vpnIpsecRefList {
				elements = args.List(spec.Name)
			}
			var keys []string
			for _, element := range elements {
				var key, err = vpnIpsecResolveRef(values, spec.field, spec.Name, element)
				if err != nil {
					return nil, err
				}
				if key != "" {
					keys = append(keys, key)
				}
			}
			fields[spec.field] = strings.Join(keys, ",")
		case vpnIpsecSecret:
			fields[spec.field] = args.String(spec.Name)
		case vpnIpsecFile:
			if value == "" {
				fields[spec.field] = ""
				continue
			}
			var content, err = os.ReadFile(value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", spec.Name, err)
			}
			fields[spec.field] = string(content)
		default:
			fields[spec.field] = vpnIpsecCanonical(spec.Values, value)
		}
	}
	return fields, nil
}

// vpnIpsecMask returns the mask for a non-empty secret
func vpnIpsecMask(value string) string {
	if value == "" {
		return ""
	}
	return vpnIpsecMasked
}

// vpnIpsecDetail renders values (API field names) as name: value lines named like the arguments. display
// returns the display text of a field (the "%field" of search rows), form holds the options of references
func vpnIpsecDetail(values map[string]string, display func(field string) string, form ipsec.Form, specs []vpnIpsecField) [][2]string {
	var fields [][2]string
	if uuid, found := values["uuid"]; found {
		fields = append(fields, [2]string{"uuid", uuid})
	}
	for _, spec := range specs {
		var value = values[spec.field]
		switch spec.kind {
		case vpnIpsecFlag:
			value = YesNo(value)
		case vpnIpsecDisabled:
			value = YesNo(Flag(value == "0"))
		case vpnIpsecMapped:
			for _, pair := range spec.mapping {
				if pair[1] == value {
					value = pair[0]
					break
				}
			}
		case vpnIpsecConnection:
			value = display(spec.field)
		case vpnIpsecRef, vpnIpsecRefList:
			if !spec.keys {
				value = vpnIpsecRefText(form, spec.field, value)
			}
		case vpnIpsecSecret, vpnIpsecFile:
			value = vpnIpsecMask(value)
		case vpnIpsecPresent:
			value = YesNo(Flag(value != ""))
		}
		fields = append(fields, [2]string{spec.Name, value})
	}
	return fields
}

// vpnIpsecValidationArgs renames the fields of a validation error of OPNsense ("connection.remote_addrs") to the
// argument names ("remote-addresses"), so the message names what was typed
func vpnIpsecValidationArgs(err error, prefix string, specs []vpnIpsecField) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var renamed = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		var name = field
		if rest, found := strings.CutPrefix(field, prefix); found {
			for _, spec := range specs {
				if spec.field == rest {
					name = spec.Name
					break
				}
			}
		}
		if previous, exists := renamed[name]; exists {
			message = previous + "; " + message
		}
		renamed[name] = message
	}
	return &coreapi.ValidationError{Validations: renamed}
}

// --- item lists

// vpnIpsecColumn is one column of a print table
type vpnIpsecColumn struct {
	header string
	value  func(r ipsec.Record) string
}

// vpnIpsecItems describes a configuration list for vpnIpsecRegister
type vpnIpsecItems struct {
	menu       string // e.g. "vpn/ipsec/connection"
	help       string // menu help
	noun       string // e.g. "connection"
	plural     string // when not noun+"s"
	itemHelp   string // help of the item argument
	addLong    string // Long help of add (the apply hint is appended)
	setLong    string // Long help of set
	removeLong string // Long help of remove
	prefix     string // the prefix of validation fields, e.g. "connection."
	// fields are the field arguments of add (true) and set, in the order of show
	fields func(add bool) []vpnIpsecField
	// shown are the fields of show and print detail when they differ from the field arguments
	shown func() []vpnIpsecField
	// fieldNames are the writable API fields (replace starts from the defaults of these)
	fieldNames []string
	list       func(api *ipsec.IPsecApi) ([]ipsec.Record, error)
	form       func(api *ipsec.IPsecApi) (ipsec.Form, error)
	create     func(api *ipsec.IPsecApi, fields ipsec.Fields) (string, error)
	update     func(api *ipsec.IPsecApi, uuid string, fields ipsec.Fields) error
	remove     func(api *ipsec.IPsecApi, uuid string) error
	setEnabled func(api *ipsec.IPsecApi, uuid string, enabled bool) (bool, error) // nil: no enable/disable
	// names are the names an item can be selected by (besides # and uuid), label names it in messages
	names func(r ipsec.Record) []string
	label func(r ipsec.Record) string
	// key is the natural key of add: whether r has the key of values (the API fields of the new item merged over
	// the defaults); nil when items have no natural key. keyText names it in messages
	key     func(r ipsec.Record, values map[string]string) bool
	keyText string
	columns []vpnIpsecColumn
	// printArgs are additional arguments of print, filter applies them
	printArgs []Arg
	filter    func(api *ipsec.IPsecApi, args *Args, records []ipsec.Record) ([]ipsec.Record, error)
	secrets   []string // fields masked in json
	check     func(args *Args) error
	// beforeRemove refuses to remove items that are still used
	beforeRemove func(api *ipsec.IPsecApi, r ipsec.Record) error
	// extra are additional commands of the menu
	extra []*Command
}

func (items *vpnIpsecItems) itemArg() Arg {
	return Arg{Name: "item", Help: items.itemHelp, Positional: true, Required: true, Complete: items.complete}
}

func (items *vpnIpsecItems) complete(c *Context) []string {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return nil
	}
	var records, listErr = items.list(api)
	if listErr != nil {
		return nil
	}
	var names []string
	for _, record := range records {
		for _, name := range items.names(record) {
			if name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// vpnIpsecRegister adds the commands of an item list to its menu
func vpnIpsecRegister(items *vpnIpsecItems) *Menu {
	var menu = Root.Menu(items.menu)
	menu.Help = items.help
	var item = items.itemArg()
	var plural = items.plural
	if plural == "" {
		plural = items.noun + "s"
	}
	var printArgs = append([]Arg{
		{Name: "detail", Type: Bool, Help: "show all fields of every " + items.noun},
		{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (secrets masked)"},
		{Name: "search", Help: "only " + plural + " where any field contains this text"},
	}, items.printArgs...)
	var hint = vpnIpsecApplyHint
	var addArgs = vpnIpsecArgs(items.fields(true))
	if items.key != nil { // without a natural key there is nothing to replace
		addArgs = append(addArgs, Arg{Name: "replace", Type: Bool, Help: "replace the " + items.noun + " with the same " + items.keyText})
	}
	menu.Add(
		&Command{Name: "print", Help: "list the " + plural, Args: printArgs, Run: items.print},
		&Command{Name: "show", Help: "show all fields of one " + items.noun, Args: []Arg{item}, Run: items.show},
		&Command{Name: "add", Help: "add a " + items.noun + ", prints its uuid", Long: strings.TrimSpace(items.addLong + "\n" + hint),
			Args: addArgs, Check: items.check, Run: items.add},
		&Command{Name: "set", Help: "change fields of a " + items.noun + ", the others are kept",
			Long: strings.TrimSpace(items.setLong + "\nAn empty value clears a field.\n" + hint),
			Args: append([]Arg{item}, vpnIpsecArgs(items.fields(false))...), Check: items.check, Run: items.set},
		&Command{Name: "remove", Help: "remove a " + items.noun, Long: strings.TrimSpace(items.removeLong + "\n" + hint),
			Args: []Arg{item}, Run: items.removeItem},
	)
	if items.setEnabled != nil {
		menu.Add(
			&Command{Name: "enable", Help: "enable a " + items.noun, Long: hint, Args: []Arg{item}, Run: items.enabler(true)},
			&Command{Name: "disable", Help: "disable a " + items.noun, Long: hint, Args: []Arg{item}, Run: items.enabler(false)},
		)
	}
	menu.Add(items.extra...)
	return menu
}

// vpnIpsecSearch keeps the records where any value contains phrase (case-insensitive), like OPNsense's searchPhrase
func vpnIpsecSearch(records []ipsec.Record, phrase string) []ipsec.Record {
	if phrase == "" {
		return records
	}
	phrase = strings.ToLower(phrase)
	return coreapi.Filter(records, func(record ipsec.Record) bool {
		for _, value := range record.Values() {
			if strings.Contains(strings.ToLower(value), phrase) {
				return true
			}
		}
		return false
	})
}

// vpnIpsecMaskedRow returns a raw row with the secret fields masked
func vpnIpsecMaskedRow(record ipsec.Record, secrets []string) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(record.Raw(), &object); err != nil {
		return nil, err
	}
	for _, field := range secrets {
		if value, isString := object[field].(string); isString && value != "" {
			object[field] = vpnIpsecMasked
		}
	}
	return object, nil
}

// vpnIpsecPrintJSON prints records as ndjson with secrets masked
func vpnIpsecPrintJSON(c *Context, records []ipsec.Record, secrets []string) error {
	for _, record := range records {
		var masked, err = vpnIpsecMaskedRow(record, secrets)
		if err != nil {
			return err
		}
		if err := c.JSON(masked); err != nil {
			return err
		}
	}
	return nil
}

func vpnIpsecUuids(records []ipsec.Record) []string {
	var uuids = make([]string, len(records))
	for i, record := range records {
		uuids[i] = record.Uuid()
	}
	return uuids
}

func (items *vpnIpsecItems) shownFields() []vpnIpsecField {
	if items.shown != nil {
		return items.shown()
	}
	return items.fields(false)
}

func (items *vpnIpsecItems) detail(record ipsec.Record, form ipsec.Form) [][2]string {
	return vpnIpsecDetail(record.Values(), record.Display, form, items.shownFields())
}

// detailForm fetches the form when a field is a reference
func (items *vpnIpsecItems) detailForm(api *ipsec.IPsecApi) (ipsec.Form, error) {
	for _, spec := range items.shownFields() {
		if (spec.kind == vpnIpsecRef || spec.kind == vpnIpsecRefList) && !spec.keys {
			return items.form(api)
		}
	}
	return ipsec.Form{}, nil
}

func (items *vpnIpsecItems) print(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var records, listErr = items.list(api)
	if listErr != nil {
		return listErr
	}
	records = vpnIpsecSearch(records, args.String("search"))
	if items.filter != nil {
		if records, err = items.filter(api, args, records); err != nil {
			return err
		}
	}

	switch {
	case args.Bool("json"):
		return vpnIpsecPrintJSON(c, records, items.secrets)
	case args.Bool("detail"):
		var form, formErr = items.detailForm(api)
		if formErr != nil {
			return formErr
		}
		var details = make([][][2]string, len(records))
		for i, record := range records {
			details[i] = items.detail(record, form)
		}
		c.Details(details, vpnIpsecUuids(records))
	default:
		var headers = make([]string, len(items.columns))
		for i, column := range items.columns {
			headers[i] = column.header
		}
		var rows = make([][]string, len(records))
		for i, record := range records {
			rows[i] = make([]string, len(items.columns))
			for j, column := range items.columns {
				rows[i][j] = column.value(record)
			}
		}
		c.Items(headers, rows, vpnIpsecUuids(records))
	}
	return nil
}

// selectItem resolves the item argument, it also returns all records
func (items *vpnIpsecItems) selectItem(c *Context, api *ipsec.IPsecApi, selector string) (ipsec.Record, []ipsec.Record, error) {
	var records, err = items.list(api)
	if err != nil {
		return ipsec.Record{}, nil, err
	}
	var record, selectErr = Select(c, selector, records, ipsec.Record.Uuid, items.names)
	return record, records, selectErr
}

func (items *vpnIpsecItems) show(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var record, _, selectErr = items.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var form, formErr = items.detailForm(api)
	if formErr != nil {
		return formErr
	}
	c.Fields(items.detail(record, form))
	return nil
}

func (items *vpnIpsecItems) error(err error) error {
	return vpnIpsecValidationArgs(err, items.prefix, items.fields(false))
}

// writable returns the defaults of a new item restricted to the writable fields
func (items *vpnIpsecItems) defaults(api *ipsec.IPsecApi) (map[string]string, error) {
	var form, err = items.form(api)
	if err != nil {
		return nil, err
	}
	var defaults = map[string]string{}
	for name, value := range form.Values() {
		if slices.Contains(items.fieldNames, name) {
			defaults[name] = value
		}
	}
	return defaults, nil
}

func (items *vpnIpsecItems) add(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = vpnIpsecFieldsOf(api, args, items.fields(true), items.form)
	if fieldsErr != nil {
		return fieldsErr
	}
	if items.key == nil {
		var uuid, createErr = items.create(api, fields)
		if createErr != nil {
			return items.error(createErr)
		}
		c.Println(uuid)
		return nil
	}

	var defaults, defaultsErr = items.defaults(api)
	if defaultsErr != nil {
		return defaultsErr
	}
	var merged = map[string]string{}
	for name, value := range defaults {
		merged[name] = value
	}
	for name, value := range fields {
		merged[name] = value
	}
	var records, listErr = items.list(api)
	if listErr != nil {
		return listErr
	}
	var existing = coreapi.Filter(records, func(record ipsec.Record) bool { return items.key(record, merged) })
	switch {
	case len(existing) == 0:
		var uuid, createErr = items.create(api, fields)
		if createErr != nil {
			return items.error(createErr)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d %ss with this %s (%s), change or remove them with set or remove",
			len(existing), items.noun, items.keyText, strings.Join(vpnIpsecUuids(existing), ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a %s with this %s exists already (%s %s), change it with set or replace it with add ... replace",
			items.noun, items.keyText, items.label(existing[0]), existing[0].Uuid())
	}
	// replace: the defaults of a new item, overwritten by the given fields
	if err := items.update(api, existing[0].Uuid(), merged); err != nil {
		return items.error(err)
	}
	c.Infof("replaced the existing %s %s", items.noun, items.label(existing[0]))
	c.Println(existing[0].Uuid())
	return nil
}

func (items *vpnIpsecItems) set(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = vpnIpsecFieldsOf(api, args, items.fields(false), items.form)
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field (type \"set ?\" for help)")
	}
	var record, records, selectErr = items.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if items.key != nil {
		var merged = record.Values()
		for name, value := range fields {
			merged[name] = value
		}
		for _, other := range records {
			if other.Uuid() != record.Uuid() && items.key(other, merged) {
				return fmt.Errorf("another %s with this %s exists already (%s %s)", items.noun, items.keyText, items.label(other), other.Uuid())
			}
		}
	}
	return items.error(items.update(api, record.Uuid(), fields))
}

func (items *vpnIpsecItems) removeItem(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var record, _, selectErr = items.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if items.beforeRemove != nil {
		if err := items.beforeRemove(api, record); err != nil {
			return err
		}
	}
	return items.remove(api, record.Uuid())
}

func (items *vpnIpsecItems) enabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = vpnIpsecApi(c)
		if err != nil {
			return err
		}
		var record, _, selectErr = items.selectItem(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = items.setEnabled(api, record.Uuid(), enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("%s %s is already %s", items.noun, items.label(record), EnabledWord(enabled))
		}
		return nil
	}
}

// vpnIpsecDisabledText renders the DISABLED column
func vpnIpsecDisabledText(r ipsec.Record) string {
	return YesNo(Flag(r.Value("enabled") == "0"))
}

// vpnIpsecQuoted names an item by a field for messages, e.g. "web" (or its uuid when the field is empty)
func vpnIpsecQuoted(field string) func(r ipsec.Record) string {
	return func(r ipsec.Record) string {
		if value := r.Value(field); value != "" {
			return fmt.Sprintf("%q", value)
		}
		return r.Uuid()
	}
}

// vpnIpsecUsers returns a message naming the records of a list whose field (a comma separated list) contains uuid
func vpnIpsecUsers(records []ipsec.Record, field string, uuid string, label func(r ipsec.Record) string) []string {
	var users []string
	for _, record := range records {
		if slices.Contains(strings.Split(record.Value(field), ","), uuid) {
			users = append(users, fmt.Sprintf("%s (%s)", label(record), record.Uuid()))
		}
	}
	return users
}

// vpnIpsecWriteFile writes content with mode 0600, an existing file only with overwrite; "-" writes to stdout
func vpnIpsecWriteFile(c *Context, name string, content []byte, overwrite bool) error {
	if name == "-" {
		var _, err = c.Out.Write(content)
		return err
	}
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
