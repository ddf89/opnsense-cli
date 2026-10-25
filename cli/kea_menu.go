package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dhcp"
)

// The menu engine of the DHCP services (/kea, /dhcrelay, /radvd): their records all follow the same OPNsense MVC
// pattern (opnsense/api/dhcp Collection), so an item menu is declared as a keaItems table of field arguments and
// print columns and gets print / show / add / set / remove (+ enable / disable) from keaRegisterItems. Settings
// menus (print / set) come from keaRegisterSettings, service menus from keaRegisterService

// keaFieldKind says how an argument value maps to the API value
type keaFieldKind int

const (
	keaPlain    keaFieldKind = iota
	keaFlag                  // yes/no as 1/0
	keaDisabled              // the RouterOS style disabled argument for the enabled field
	keaList                  // comma separated in both
	keaLines                 // comma separated argument, newline separated API value (Kea pools)
	keaRef                   // uuid of another record, given by its name (keaRef.names) or uuid
	keaRefList               // several uuids, like keaRef
	keaSecret                // plain, never shown
)

const keaMasked = "********"

// keaField is a field argument of add / set (and a field of show)
type keaField struct {
	Arg
	api  string
	kind keaFieldKind
	ref  *keaRefSpec
	// options completes the argument with the choices of the option field api in get_<item> (interfaces, ...)
	options bool
}

// keaRefSpec is a relation to records of another menu: the related records and the names they are given by
type keaRefSpec struct {
	what  string
	rows  func(c *Context) ([]dhcp.Row, error)
	names func(row dhcp.Row) []string
}

// keaColumn is a column of print
type keaColumn struct {
	header string
	value  func(row dhcp.Row) string
}

// keaRecords is what an item menu needs of a dhcp.Collection
type keaRecords interface {
	Rows(searchPhrase string) ([]dhcp.Row, []json.RawMessage, error)
	Form(uuid string) (dhcp.Form, error)
	Defaults() (dhcp.Fields, error)
	Create(fields dhcp.Fields) (string, error)
	Update(uuid string, fields dhcp.Fields) error
	Remove(uuid string) error
	SetEnabled(uuid string, enabled bool) (bool, error)
	CanToggle() bool
	What() string
	Container() string
}

// keaItems declares an item menu
type keaItems struct {
	path     string // e.g. "kea/dhcp4/subnet"
	help     string
	noun     string // "subnet"
	itemHelp string // help of the item argument: "the #, uuid, network or description of the subnet"
	addLong  string
	setLong  string
	hint     string // how changes take effect, appended to the help of the changing commands
	records  func(c *Context) (keaRecords, error)
	fields   func(add bool) []keaField
	columns  []keaColumn
	// names are the natural names an item is selected by (and completed with), the first one names related records
	names func(row dhcp.Row) []string
	// same tells whether an existing row has the natural key of a new record (add fails or replaces), key names it
	same func(row dhcp.Row, fields dhcp.Fields) bool
	key  string
	// check validates argument combinations of add (add=true) and set before anything is sent
	check func(add bool, args *Args) error
	// prepare may complete the fields of add (before the duplicate check) and set, e.g. find the subnet of an address
	prepare func(c *Context, add bool, fields dhcp.Fields) error
}

func keaFieldArgs(fields []keaField) []Arg {
	var args = make([]Arg, len(fields))
	for i, field := range fields {
		args[i] = field.Arg
	}
	return args
}

// keaRegisterItems adds the menu of spec with print, show, add, set, remove and, for records with an enabled
// flag, enable and disable
func keaRegisterItems(spec *keaItems) {
	var menu = Root.Menu(spec.path)
	menu.Help = spec.help
	var item = Arg{Name: "item", Help: spec.itemHelp, Positional: true, Required: true, Complete: spec.itemNames}
	var hint = ""
	if spec.hint != "" {
		hint = "\n" + spec.hint
	}
	var argsOf = func(add bool) []Arg {
		var args = keaFieldArgs(spec.fields(add))
		for i := range args {
			if fields := spec.fields(add); fields[i].options && args[i].Complete == nil && args[i].Values == nil {
				args[i].Complete = spec.optionNames(fields[i].api)
			}
		}
		return args
	}
	var check = func(add bool) func(args *Args) error {
		if spec.check == nil {
			return nil
		}
		return func(args *Args) error { return spec.check(add, args) }
	}
	var toggles = keaToggles(spec)
	var addArgs = append(argsOf(true), Arg{Name: "replace", Type: Bool, Help: "replace the " + spec.noun + " with the same " + spec.key})
	menu.Add(
		&Command{Name: "print", Help: "list the " + spec.noun + "s", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every " + spec.noun},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (secrets masked)"},
			{Name: "search", Help: "only " + spec.noun + "s where any field contains this text"},
		}, Run: spec.print},
		&Command{Name: "show", Help: "show all fields of one " + spec.noun, Args: []Arg{item}, Run: spec.show},
		&Command{Name: "add", Help: "add a " + spec.noun + ", prints its uuid",
			Long: strings.TrimSpace(spec.addLong+"\n") + "\nIf a " + spec.noun + " with the same " + spec.key + " exists, add fails unless replace is given,\n" +
				"then that " + spec.noun + " is replaced completely (fields not given get the defaults)." + hint,
			Args: addArgs, Check: check(true), Run: spec.add},
		&Command{Name: "set", Help: "change fields of a " + spec.noun + ", the others are kept",
			Long: strings.TrimSpace(spec.setLong+"\n") + "\nAn empty value clears a field (e.g. description=)." + hint,
			Args: append([]Arg{item}, argsOf(false)...), Check: check(false), Run: spec.set},
		&Command{Name: "remove", Help: "remove a " + spec.noun, Long: strings.TrimSpace(hint), Args: []Arg{item}, Run: spec.remove},
	)
	if toggles {
		menu.Add(
			&Command{Name: "enable", Help: "enable a " + spec.noun, Long: strings.TrimSpace(hint), Args: []Arg{item}, Run: spec.enabler(true)},
			&Command{Name: "disable", Help: "disable a " + spec.noun, Long: strings.TrimSpace(hint), Args: []Arg{item}, Run: spec.enabler(false)},
		)
	}
}

// keaToggles tells whether the records of spec have the disabled argument
func keaToggles(spec *keaItems) bool {
	for _, field := range spec.fields(false) {
		if field.kind == keaDisabled {
			return true
		}
	}
	return false
}

// --- lookups

func (spec *keaItems) selectRow(c *Context, records keaRecords, selector string) (dhcp.Row, []dhcp.Row, error) {
	var rows, _, err = records.Rows("")
	if err != nil {
		return nil, nil, err
	}
	var row, selectErr = Select(c, selector, rows, dhcp.Row.Uuid, spec.names)
	return row, rows, selectErr
}

func (spec *keaItems) itemNames(c *Context) []string {
	var records, err = spec.records(c)
	if err != nil {
		return nil
	}
	var rows, _, rowsErr = records.Rows("")
	if rowsErr != nil {
		return nil
	}
	var names []string
	var seen = map[string]bool{}
	for _, row := range rows {
		for _, name := range spec.names(row) {
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// optionNames completes an argument with the option keys of the field api of a new record
func (spec *keaItems) optionNames(api string) func(c *Context) []string {
	return func(c *Context) []string {
		var records, err = spec.records(c)
		if err != nil {
			return nil
		}
		var form, formErr = records.Form("")
		if formErr != nil {
			return nil
		}
		return keaOptionKeys(form[api])
	}
}

func keaOptionKeys(field dhcp.FormField) []string {
	var keys []string
	for _, option := range field.Options {
		if option.Key != "" {
			keys = append(keys, option.Key)
		}
	}
	return keys
}

// keaResolveRef maps a related record given by uuid or name to its uuid
func keaResolveRef(rows []dhcp.Row, ref *keaRefSpec, argName string, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	for _, row := range rows {
		if strings.EqualFold(row.Uuid(), value) {
			return row.Uuid(), nil
		}
	}
	var matches []dhcp.Row
	for _, row := range rows {
		for _, name := range ref.names(row) {
			if name != "" && strings.EqualFold(name, value) {
				matches = append(matches, row)
				break
			}
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Uuid(), nil
	case 0:
		var names []string
		for _, row := range rows {
			if found := ref.names(row); len(found) > 0 && found[0] != "" {
				names = append(names, fmt.Sprintf("%q", found[0]))
			}
		}
		if len(names) == 0 {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, there is no %s yet", argName, value, ref.what)}
		}
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, valid are: %s", argName, value, strings.Join(names, ", "))}
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid()
		}
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches the %ss %s, give the uuid instead", argName, value, ref.what, strings.Join(uuids, ", "))}
	}
}

// keaRefNames completes a reference argument with the first name of every related record
func keaRefNames(ref *keaRefSpec) func(c *Context) []string {
	return func(c *Context) []string {
		var rows, err = ref.rows(c)
		if err != nil {
			return nil
		}
		var names []string
		for _, row := range rows {
			if found := ref.names(row); len(found) > 0 && found[0] != "" {
				names = append(names, found[0])
			}
		}
		return names
	}
}

// keaFieldsOf returns the given field arguments as API fields, references resolved
func keaFieldsOf(c *Context, args *Args, specs []keaField) (dhcp.Fields, error) {
	var fields = dhcp.Fields{}
	var refRows = map[*keaRefSpec][]dhcp.Row{}
	for _, spec := range specs {
		if !args.Has(spec.Name) {
			continue
		}
		var value = args.String(spec.Name)
		switch spec.kind {
		case keaFlag:
			fields[spec.api] = Flag(args.Bool(spec.Name))
		case keaDisabled:
			fields[spec.api] = Flag(!args.Bool(spec.Name))
		case keaList, keaLines:
			var elements = args.List(spec.Name)
			for i := range elements {
				elements[i] = keaCanonical(spec.Values, elements[i])
			}
			fields[spec.api] = strings.Join(elements, map[bool]string{true: "\n", false: ","}[spec.kind == keaLines])
		case keaRef, keaRefList:
			var rows, loaded = refRows[spec.ref]
			if !loaded && strings.TrimSpace(value) != "" {
				var err error
				if rows, err = spec.ref.rows(c); err != nil {
					return nil, err
				}
				refRows[spec.ref] = rows
			}
			var elements = []string{value}
			if spec.kind == keaRefList {
				elements = args.List(spec.Name)
			}
			var uuids []string
			for _, element := range elements {
				var uuid, err = keaResolveRef(rows, spec.ref, spec.Name, element)
				if err != nil {
					return nil, err
				}
				if uuid != "" {
					uuids = append(uuids, uuid)
				}
			}
			fields[spec.api] = strings.Join(uuids, ",")
		case keaSecret:
			fields[spec.api] = value
		default:
			fields[spec.api] = keaCanonical(spec.Values, strings.TrimSpace(value))
		}
	}
	return fields, nil
}

// keaCanonical returns value in the spelling of values (the API keys are case-sensitive)
func keaCanonical(values []string, value string) string {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return candidate
		}
	}
	return value
}

// keaValidationArgs renames the fields of an OPNsense validation error ("subnet4.option_data.routers") to the
// argument names ("routers"), so the message names what was typed
func keaValidationArgs(err error, container string, specs []keaField) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var renamed = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		var name = field
		if rest, found := strings.CutPrefix(field, container+"."); found {
			name = rest
			for _, spec := range specs {
				if spec.api == rest {
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

// --- output

func keaDisabledText(row dhcp.Row) string {
	if row["enabled"] == "0" {
		return "yes"
	}
	return "no"
}

func keaMask(value string) string {
	if value == "" {
		return ""
	}
	return keaMasked
}

// keaLinesText renders a newline separated API value comma separated
func keaLinesText(value string) string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, ",")
}

// keaFieldText renders one field of a row for show: references by the name of the related record
func keaFieldText(c *Context, row dhcp.Row, spec keaField, refRows map[*keaRefSpec][]dhcp.Row) string {
	var value = row[spec.api]
	switch spec.kind {
	case keaFlag:
		return YesNo(value)
	case keaDisabled:
		return keaDisabledText(row)
	case keaLines:
		return keaLinesText(value)
	case keaSecret:
		return keaMask(value)
	case keaRef, keaRefList:
		if value == "" {
			return ""
		}
		var rows, loaded = refRows[spec.ref]
		if !loaded {
			rows, _ = spec.ref.rows(c) // on errors the uuids are shown
			refRows[spec.ref] = rows
		}
		var texts []string
		for _, uuid := range strings.Split(value, ",") {
			var text = uuid
			for _, related := range rows {
				if related.Uuid() == uuid {
					if names := spec.ref.names(related); len(names) > 0 && names[0] != "" {
						text = names[0]
					}
					break
				}
			}
			texts = append(texts, text)
		}
		return strings.Join(texts, ",")
	}
	return value
}

func (spec *keaItems) detail(c *Context, row dhcp.Row, refRows map[*keaRefSpec][]dhcp.Row) [][2]string {
	var fields = [][2]string{{"uuid", row.Uuid()}}
	for _, field := range spec.fields(false) {
		fields = append(fields, [2]string{field.Name, keaFieldText(c, row, field, refRows)})
	}
	return fields
}

// maskedRow returns a raw search row with the secret fields masked
func (spec *keaItems) maskedRow(raw json.RawMessage) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	for _, field := range spec.fields(false) {
		if value, isString := object[field.api].(string); field.kind == keaSecret && isString && value != "" {
			object[field.api] = keaMasked
		}
	}
	return object, nil
}

func (spec *keaItems) print(c *Context, args *Args) error {
	var records, err = spec.records(c)
	if err != nil {
		return err
	}
	var rows, raws, rowsErr = records.Rows(args.String("search"))
	if rowsErr != nil {
		return rowsErr
	}
	var uuids = make([]string, len(rows))
	for i, row := range rows {
		uuids[i] = row.Uuid()
	}
	switch {
	case args.Bool("json"):
		for _, raw := range raws {
			var masked, maskErr = spec.maskedRow(raw)
			if maskErr != nil {
				return maskErr
			}
			if err := c.JSON(masked); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var refRows = map[*keaRefSpec][]dhcp.Row{}
		var items = make([][][2]string, len(rows))
		for i, row := range rows {
			items[i] = spec.detail(c, row, refRows)
		}
		c.Details(items, uuids)
	default:
		var headers []string
		var toggles = keaToggles(spec)
		if toggles {
			headers = append(headers, "DISABLED")
		}
		for _, column := range spec.columns {
			headers = append(headers, column.header)
		}
		var table = make([][]string, len(rows))
		for i, row := range rows {
			if toggles {
				table[i] = append(table[i], keaDisabledText(row))
			}
			for _, column := range spec.columns {
				table[i] = append(table[i], column.value(row))
			}
		}
		c.Items(headers, table, uuids)
	}
	return nil
}

func (spec *keaItems) show(c *Context, args *Args) error {
	var records, err = spec.records(c)
	if err != nil {
		return err
	}
	var row, _, selectErr = spec.selectRow(c, records, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(spec.detail(c, row, map[*keaRefSpec][]dhcp.Row{}))
	return nil
}

// --- changes

func (spec *keaItems) add(c *Context, args *Args) error {
	var records, err = spec.records(c)
	if err != nil {
		return err
	}
	var specs = spec.fields(true)
	var fields, fieldsErr = keaFieldsOf(c, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	// items are enabled unless disabled is given, whatever the OPNsense default is
	for _, field := range specs {
		if field.kind == keaDisabled && !args.Has(field.Name) {
			fields[field.api] = "1"
		}
	}
	if spec.prepare != nil {
		if err := spec.prepare(c, true, fields); err != nil {
			return err
		}
	}

	var rows, _, rowsErr = records.Rows("")
	if rowsErr != nil {
		return rowsErr
	}
	var existing = coreapi.Filter(rows, func(row dhcp.Row) bool { return spec.same(row, fields) })
	switch {
	case len(existing) == 0:
		var uuid, createErr = records.Create(fields)
		if createErr != nil {
			return keaValidationArgs(createErr, records.Container(), specs)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, row := range existing {
			uuids[i] = row.Uuid()
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d %ss with this %s (%s), change or remove them with set or remove",
			len(existing), spec.noun, spec.key, strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a %s with this %s exists already (%s), change it with set or replace it with add ... replace",
			spec.noun, spec.key, existing[0].Uuid())
	}

	// replace: the defaults of a new record, overwritten by the given fields
	var replacement, defaultsErr = records.Defaults()
	if defaultsErr != nil {
		return defaultsErr
	}
	for name, value := range fields {
		replacement[name] = value
	}
	if err := records.Update(existing[0].Uuid(), replacement); err != nil {
		return keaValidationArgs(err, records.Container(), specs)
	}
	c.Infof("replaced the existing %s %s", spec.noun, existing[0].Uuid())
	c.Println(existing[0].Uuid())
	return nil
}

func (spec *keaItems) set(c *Context, args *Args) error {
	var records, err = spec.records(c)
	if err != nil {
		return err
	}
	var specs = spec.fields(false)
	var fields, fieldsErr = keaFieldsOf(c, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field (type \"set ?\" for help)")
	}
	if spec.prepare != nil {
		if err := spec.prepare(c, false, fields); err != nil {
			return err
		}
	}
	var row, _, selectErr = spec.selectRow(c, records, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return keaValidationArgs(records.Update(row.Uuid(), fields), records.Container(), specs)
}

func (spec *keaItems) remove(c *Context, args *Args) error {
	var records, err = spec.records(c)
	if err != nil {
		return err
	}
	var row, _, selectErr = spec.selectRow(c, records, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return records.Remove(row.Uuid())
}

func (spec *keaItems) enabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var records, err = spec.records(c)
		if err != nil {
			return err
		}
		var row, _, selectErr = spec.selectRow(c, records, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = records.SetEnabled(row.Uuid(), enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("the %s %s is already %s", spec.noun, row.Uuid(), EnabledWord(enabled))
		}
		return nil
	}
}

// --- settings menus

// keaSettings declares a settings menu with print and set; the fields are named by section ("general.enabled")
type keaSettings struct {
	path   string
	help   string
	long   string
	hint   string
	spec   dhcp.SettingsSpec
	fields []keaField
}

func keaRegisterSettings(settings *keaSettings) {
	var menu = Root.Menu(settings.path)
	menu.Help = settings.help
	var args = keaFieldArgs(settings.fields)
	for i, field := range settings.fields {
		if field.options && args[i].Complete == nil && args[i].Values == nil {
			args[i].Complete = settings.optionNames(field.api)
		}
	}
	menu.Add(
		&Command{Name: "print", Help: "show the settings",
			Long: "json prints the settings as one object with the API field names (sections joined with a dot).",
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings as one JSON object"}},
			Run:  settings.print},
		&Command{Name: "set", Help: "change settings, the others are kept",
			Long: strings.TrimSpace(settings.long+"\n") + "\n" + settings.hint,
			Args: args, Run: settings.set},
	)
}

func (settings *keaSettings) optionNames(api string) func(c *Context) []string {
	return func(c *Context) []string {
		var dhcpApi, err = keaApi(c)
		if err != nil {
			return nil
		}
		var form, formErr = dhcpApi.SettingsGet(settings.spec)
		if formErr != nil {
			return nil
		}
		return keaOptionKeys(form[api])
	}
}

func (settings *keaSettings) print(c *Context, args *Args) error {
	var dhcpApi, err = keaApi(c)
	if err != nil {
		return err
	}
	var form, formErr = dhcpApi.SettingsGet(settings.spec)
	if formErr != nil {
		return formErr
	}
	if args.Bool("json") {
		return c.JSON(form.Fields())
	}
	var row = dhcp.Row(form.Fields())
	var fields [][2]string
	for _, field := range settings.fields {
		fields = append(fields, [2]string{field.Name, keaFieldText(c, row, field, nil)})
	}
	c.Fields(fields)
	return nil
}

func (settings *keaSettings) set(c *Context, args *Args) error {
	var fields, err = keaFieldsOf(c, args, settings.fields)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one setting (type \"set ?\" for help)")
	}
	var dhcpApi, apiErr = keaApi(c)
	if apiErr != nil {
		return apiErr
	}
	return keaValidationArgs(dhcpApi.SettingsSet(settings.spec, fields), settings.spec.Container(), settings.fields)
}

// --- service menus

// keaRegisterService adds a service menu with status, start, stop, restart and reconfigure. stop and restart ask
// for confirmation with the consequence
func keaRegisterService(path string, help string, service dhcp.Service, reconfigureHelp string, stopConfirm string, restartConfirm string) {
	var menu = Root.Menu(path)
	menu.Help = help
	var run = func(action func(api *dhcp.DhcpApi) error) func(c *Context, _ *Args) error {
		return func(c *Context, _ *Args) error {
			var dhcpApi, err = keaApi(c)
			if err != nil {
				return err
			}
			return action(dhcpApi)
		}
	}
	menu.Add(
		&Command{Name: "status", Help: "show whether the service is running", Run: func(c *Context, _ *Args) error {
			var dhcpApi, err = keaApi(c)
			if err != nil {
				return err
			}
			var status, statusErr = dhcpApi.ServiceStatus(service)
			if statusErr != nil {
				return statusErr
			}
			c.Fields([][2]string{{"status", status}})
			return nil
		}},
		&Command{Name: "start", Help: "start the service", Run: run(func(api *dhcp.DhcpApi) error { return api.ServiceStart(service) })},
		&Command{Name: "stop", Help: "stop the service (until the next reconfigure or boot)", Confirm: stopConfirm,
			Run: run(func(api *dhcp.DhcpApi) error { return api.ServiceStop(service) })},
		&Command{Name: "restart", Help: "restart the service", Confirm: restartConfirm,
			Run: run(func(api *dhcp.DhcpApi) error { return api.ServiceRestart(service) })},
		&Command{Name: "reconfigure", Aliases: []string{"apply"}, Help: reconfigureHelp,
			Run: run(func(api *dhcp.DhcpApi) error { return api.ServiceReconfigure(service) })},
	)
}

// keaApi returns the DHCP services API on the session's connection
func keaApi(c *Context) (*dhcp.DhcpApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &dhcp.DhcpApi{OPNsense: opn}, nil
}
