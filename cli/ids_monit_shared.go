package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strings"
)

// Helpers shared by the /ids and /monit menus: settings forms (print / set of the general settings) and the item
// menus of model backed lists (print / show / add / set / remove / enable / disable)

// --- settings forms

// idsMonitSettingsField is one setting as both APIs return it: the API value and, for option fields, the choices
type idsMonitSettingsField struct {
	Value   string
	Options []idsMonitSettingsOption
}

type idsMonitSettingsOption struct {
	Key      string
	Display  string
	Selected bool
}

// idsMonitSetting maps a kebab-case argument to a setting
type idsMonitSetting struct {
	Arg
	// path is the API name of the setting, like "detect.Profile"
	path string
	// option: the value(s) must be keys of the setting's choices, checked against the live choices
	option bool
	// secret settings are never printed, only whether they are set
	secret bool
	// aliases map argument values to API keys (like weekly → W0D23), printing maps them back
	aliases map[string]string
	// render changes the printed value, e.g. to hide credentials in a URL
	render func(string) string
}

// idsMonitSettingsForm is a settings menu: its settings and how to read and write them
type idsMonitSettingsForm struct {
	settings []idsMonitSetting
	get      func(c *Context) (map[string]idsMonitSettingsField, error)
	set      func(c *Context, values map[string]string) error
}

// idsMonitSecretShown is printed instead of a secret that is set
const idsMonitSecretShown = "(set)"

func (form *idsMonitSettingsForm) byArg(name string) *idsMonitSetting {
	for i := range form.settings {
		if form.settings[i].Name == name {
			return &form.settings[i]
		}
	}
	return nil
}

func (form *idsMonitSettingsForm) optionArgs() []string {
	var names []string
	for _, setting := range form.settings {
		if setting.option {
			names = append(names, setting.Name)
		}
	}
	return names
}

// display renders the API value of a setting for print
func (setting idsMonitSetting) display(field idsMonitSettingsField) string {
	switch {
	case setting.secret:
		if field.Value != "" {
			return idsMonitSecretShown
		}
		return ""
	case setting.Type == Bool:
		return YesNo(field.Value)
	case setting.render != nil:
		return setting.render(field.Value)
	}
	var values = splitList(field.Value)
	for i, value := range values {
		for alias, key := range setting.aliases {
			if key == value {
				values[i] = alias
			}
		}
	}
	if len(values) == 0 {
		for alias, key := range setting.aliases {
			if key == "" {
				return alias
			}
		}
	}
	return strings.Join(values, ",")
}

// printArgs are the arguments of print
func (form *idsMonitSettingsForm) printArgs() []Arg {
	return []Arg{
		{Name: "options", Help: "list the choices of this option field instead", Values: form.optionArgs()},
		{Name: "json", Type: Bool, Help: "print the settings as one JSON object with the API names (secrets masked)"},
	}
}

// setArgs are the arguments of set: the settings, with their choices completed from the API
func (form *idsMonitSettingsForm) setArgs() []Arg {
	var args = make([]Arg, len(form.settings))
	for i, setting := range form.settings {
		args[i] = setting.Arg
		if setting.option && args[i].Complete == nil && len(args[i].Values) == 0 {
			args[i].Complete = form.completeOptions(setting)
		}
	}
	return args
}

func (form *idsMonitSettingsForm) completeOptions(setting idsMonitSetting) func(c *Context) []string {
	return func(c *Context) []string {
		var fields, err = form.get(c)
		if err != nil {
			return nil
		}
		var keys []string
		for _, option := range fields[setting.path].Options {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

func (form *idsMonitSettingsForm) print(c *Context, args *Args) error {
	var fields, err = form.get(c)
	if err != nil {
		return err
	}
	if args.Has("options") {
		var setting = form.byArg(strings.ToLower(args.String("options")))
		if setting == nil || !setting.option {
			return fmt.Errorf("options: must be one of %s", strings.Join(form.optionArgs(), ", "))
		}
		var options = fields[setting.path].Options
		if args.Bool("json") {
			for _, option := range options {
				if err := c.JSON(map[string]any{"key": option.Key, "value": option.Display, "selected": option.Selected}); err != nil {
					return err
				}
			}
			return nil
		}
		var rows [][]string
		for _, option := range options {
			var key = option.Key
			if key == "" {
				key = `""`
			}
			rows = append(rows, []string{key, option.Display, YesNo(Flag(option.Selected))})
		}
		c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		return nil
	}

	if args.Bool("json") {
		var values = map[string]string{}
		for path, field := range fields {
			values[path] = field.Value
		}
		for _, setting := range form.settings {
			switch {
			case setting.secret && values[setting.path] != "":
				values[setting.path] = "********"
			case setting.render != nil:
				values[setting.path] = setting.render(values[setting.path])
			}
		}
		return c.JSON(values)
	}
	var lines = make([][2]string, 0, len(form.settings))
	for _, setting := range form.settings {
		lines = append(lines, [2]string{setting.Name, setting.display(fields[setting.path])})
	}
	c.Fields(lines)
	return nil
}

// optionValue checks the comma separated value against the choices (case-insensitive, aliases first) and returns
// the API keys
func (setting idsMonitSetting) optionValue(choices []idsMonitSettingsOption, value string) (string, error) {
	var elements = splitList(value)
	if setting.Type != List && len(elements) > 1 {
		return "", fmt.Errorf("%s takes one value, got %q", setting.Name, value)
	}
	var keys = make([]string, 0, len(elements))
	for _, element := range elements {
		if key, ok := setting.aliases[strings.ToLower(element)]; ok {
			keys = append(keys, key)
			continue
		}
		var found = false
		for _, choice := range choices {
			if choice.Key != "" && strings.EqualFold(choice.Key, element) {
				keys = append(keys, choice.Key)
				found = true
				break
			}
		}
		if !found {
			var valid []string
			for _, choice := range choices {
				if choice.Key != "" {
					valid = append(valid, choice.Key)
				}
			}
			if len(valid) == 0 {
				return "", fmt.Errorf("%s: unknown value %q, there are no choices", setting.Name, element)
			}
			return "", fmt.Errorf("%s: unknown value %q, must be one of %s", setting.Name, element, strings.Join(valid, ", "))
		}
	}
	return strings.Join(keys, ","), nil
}

func (form *idsMonitSettingsForm) setValues(c *Context, args *Args) (map[string]string, error) {
	var given []idsMonitSetting
	var needChoices = false
	for _, setting := range form.settings {
		if args.Has(setting.Name) {
			given = append(given, setting)
			needChoices = needChoices || setting.option
		}
	}
	if len(given) == 0 {
		return nil, errors.New("set: nothing to change, give at least one setting (type \"set ?\" for help)")
	}
	var current map[string]idsMonitSettingsField
	if needChoices {
		var err error
		if current, err = form.get(c); err != nil {
			return nil, err
		}
	}
	var values = map[string]string{}
	for _, setting := range given {
		var raw = args.String(setting.Name)
		switch {
		case setting.option:
			var value, err = setting.optionValue(current[setting.path].Options, raw)
			if err != nil {
				return nil, err
			}
			values[setting.path] = value
		case setting.Type == Bool:
			values[setting.path] = Flag(args.Bool(setting.Name))
		case setting.Type == List:
			values[setting.path] = strings.Join(args.List(setting.Name), ",")
		default:
			if key, ok := setting.aliases[strings.ToLower(raw)]; ok {
				raw = key
			}
			values[setting.path] = raw
		}
	}
	return values, nil
}

func (form *idsMonitSettingsForm) runSet(c *Context, args *Args) error {
	var values, err = form.setValues(c, args)
	if err != nil {
		return err
	}
	return form.set(c, values)
}

// --- item menus of model backed lists

// idsMonitField is a field of an item: an argument of add / set and a line of show
type idsMonitField[R any, P any] struct {
	Arg
	// show renders the field of an item for show and print detail
	show func(R) string
	// target is the field of the patch, nil for fields only shown
	target func(*P) **string
	// convert turns the argument value into the API value; nil: a Bool becomes "1"/"0" (inverted for disabled),
	// a List is joined by commas, everything else is sent as given
	convert func(c *Context, value string) (string, error)
}

// idsMonitRecords describes an item menu
type idsMonitRecords[R any, P any] struct {
	what     string // like "policy"
	path     string // the menu, like ids/policy
	help     string
	itemHelp string
	// hint ends the help of the changing commands, e.g. how to apply
	hint string
	// list returns the items where any column contains search, with the raw rows for json
	list  func(c *Context, search string) ([]R, []json.RawMessage, error)
	uuid  func(R) string
	names func(R) []string
	// key is the argument that must be unique for add ("" for none), keyOf its value of an item
	key   string
	keyOf func(R) string
	// create, update and remove are nil for read only lists
	create func(c *Context, patch P) (string, error)
	update func(c *Context, uuid string, patch P) error
	remove func(c *Context, uuid string) error
	// enabled tells the state of an item; nil when the items have none
	enabled func(R) bool
	columns []string
	row     func(R) []string
	fields  []idsMonitField[R, P]
	// check validates the arguments of add and set together
	check              func(args *Args) error
	printLong, addLong string
	setLong            string
	removeLong         string
}

// idsMonitDisabledField is the RouterOS style disabled flag for an "enabled" API field
func idsMonitDisabledField[R any, P any](help string, enabled func(R) bool, target func(*P) **string) idsMonitField[R, P] {
	return idsMonitField[R, P]{
		Arg:    Arg{Name: "disabled", Type: Bool, Help: help},
		show:   func(r R) string { return YesNo(Flag(!enabled(r))) },
		target: target,
	}
}

func (spec *idsMonitRecords[R, P]) fieldArgs(add bool) []Arg {
	var args []Arg
	for _, field := range spec.fields {
		if field.target == nil {
			continue
		}
		var arg = field.Arg
		if add {
			arg.Required = arg.Name == spec.key || arg.Required
			if arg.Name == "disabled" && arg.Default == "" {
				arg.Default = "no"
			}
		} else {
			arg.Required = false
			arg.Default = ""
		}
		args = append(args, arg)
	}
	return args
}

// idsMonitRegister adds the item menu of spec
func idsMonitRegister[R any, P any](spec *idsMonitRecords[R, P]) {
	var menu = Root.Menu(spec.path)
	menu.Help = spec.help
	var item = Arg{Name: "item", Help: spec.itemHelp, Positional: true, Required: true, Complete: spec.completeItems}
	var withHint = func(text string) string {
		if spec.hint == "" {
			return text
		}
		if text == "" {
			return spec.hint
		}
		return text + "\n\n" + spec.hint
	}
	menu.Add(
		&Command{Name: "print", Help: "list the " + spec.what + " items", Long: spec.printLong,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every item", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only items where any field contains this text"},
			}, Run: spec.print},
		&Command{Name: "show", Help: "show all fields of one " + spec.what, Args: []Arg{item}, Run: spec.show},
	)
	if spec.create != nil {
		var long = spec.addLong
		if spec.key != "" {
			long = strings.TrimSpace(long + fmt.Sprintf(`

If a %s with this %s exists already, add fails unless replace is given, then that %s is replaced completely
(arguments not given are reset to their defaults).`, spec.what, spec.key, spec.what))
		}
		var args = spec.fieldArgs(true)
		if spec.key != "" {
			args = append(args, Arg{Name: "replace", Type: Bool, Help: "replace the " + spec.what + " with the same " + spec.key})
		}
		menu.Add(&Command{Name: "add", Help: "add a " + spec.what + ", prints its uuid", Long: withHint(long),
			Args: args, Check: spec.check, Run: spec.add})
	}
	if spec.update != nil {
		menu.Add(&Command{Name: "set", Help: "change fields of a " + spec.what + ", the others are kept", Long: withHint(spec.setLong),
			Args: append([]Arg{item}, spec.fieldArgs(false)...), Check: spec.checkSet, Run: spec.set})
	}
	if spec.remove != nil {
		menu.Add(&Command{Name: "remove", Help: "remove a " + spec.what, Long: withHint(spec.removeLong), Args: []Arg{item}, Run: spec.runRemove})
	}
	if spec.enabled != nil && spec.update != nil {
		menu.Add(
			&Command{Name: "enable", Help: "enable a " + spec.what, Long: withHint(""), Args: []Arg{item}, Run: spec.enabler(true)},
			&Command{Name: "disable", Help: "disable a " + spec.what, Long: withHint(""), Args: []Arg{item}, Run: spec.enabler(false)},
		)
	}
}

func (spec *idsMonitRecords[R, P]) completeItems(c *Context) []string {
	var items, _, err = spec.list(c, "")
	if err != nil {
		return nil
	}
	var names []string
	for _, item := range items {
		for _, name := range spec.names(item) {
			if name != "" {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func (spec *idsMonitRecords[R, P]) selectItem(c *Context, selector string) (R, error) {
	var items, _, err = spec.list(c, "")
	if err != nil {
		var zero R
		return zero, err
	}
	return Select(c, selector, items, spec.uuid, spec.names)
}

func (spec *idsMonitRecords[R, P]) fieldLines(item R) [][2]string {
	var lines = [][2]string{{"uuid", spec.uuid(item)}}
	for _, field := range spec.fields {
		lines = append(lines, [2]string{field.Name, field.show(item)})
	}
	return lines
}

func (spec *idsMonitRecords[R, P]) print(c *Context, args *Args) error {
	var items, raw, err = spec.list(c, args.String("search"))
	if err != nil {
		return err
	}
	var uuids = make([]string, len(items))
	for i, item := range items {
		uuids[i] = spec.uuid(item)
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(items))
		for i, item := range items {
			blocks[i] = spec.fieldLines(item)
		}
		c.Details(blocks, uuids)
	default:
		var rows = make([][]string, len(items))
		for i, item := range items {
			rows[i] = spec.row(item)
		}
		c.Items(spec.columns, rows, uuids)
	}
	return nil
}

func (spec *idsMonitRecords[R, P]) show(c *Context, args *Args) error {
	var item, err = spec.selectItem(c, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(spec.fieldLines(item))
	return nil
}

// patch builds the patch from the given arguments, all is set for add: every field is sent (with its default)
func (spec *idsMonitRecords[R, P]) patch(c *Context, args *Args, all bool) (P, error) {
	var patch P
	for _, field := range spec.fields {
		if field.target == nil || !all && !args.Has(field.Name) {
			continue
		}
		var value string
		switch {
		case field.convert != nil:
			var converted, err = field.convert(c, args.String(field.Name))
			if err != nil {
				return patch, fmt.Errorf("%s: %w", field.Name, err)
			}
			value = converted
		case field.Type == Bool && field.Name == "disabled":
			value = Flag(!args.Bool(field.Name))
		case field.Type == Bool:
			value = Flag(args.Bool(field.Name))
		case field.Type == List:
			value = strings.Join(args.List(field.Name), ",")
		default:
			value = args.String(field.Name)
		}
		*field.target(&patch) = &value
	}
	return patch, nil
}

func (spec *idsMonitRecords[R, P]) add(c *Context, args *Args) error {
	var patch, err = spec.patch(c, args, true)
	if err != nil {
		return err
	}
	if spec.key == "" {
		var uuid, createErr = spec.create(c, patch)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	}

	var items, _, listErr = spec.list(c, "")
	if listErr != nil {
		return listErr
	}
	var key = args.String(spec.key)
	for _, item := range items {
		if spec.keyOf(item) != key {
			continue
		}
		if !args.Bool("replace") {
			return fmt.Errorf("a %s with %s %q exists already (%s), change it with set or replace it with add ... replace",
				spec.what, spec.key, key, spec.uuid(item))
		}
		if err := spec.update(c, spec.uuid(item), patch); err != nil {
			return err
		}
		c.Infof("replaced the existing %s %q", spec.what, key)
		c.Println(spec.uuid(item))
		return nil
	}
	var uuid, createErr = spec.create(c, patch)
	if createErr != nil {
		return createErr
	}
	c.Println(uuid)
	return nil
}

func (spec *idsMonitRecords[R, P]) checkSet(args *Args) error {
	var given = false
	for _, field := range spec.fields {
		if field.target != nil && args.Has(field.Name) {
			given = true
		}
	}
	if !given {
		return errors.New("nothing to change, give at least one field (type \"set ?\" for help)")
	}
	if spec.check != nil {
		return spec.check(args)
	}
	return nil
}

func (spec *idsMonitRecords[R, P]) set(c *Context, args *Args) error {
	var item, err = spec.selectItem(c, args.String("item"))
	if err != nil {
		return err
	}
	var patch, patchErr = spec.patch(c, args, false)
	if patchErr != nil {
		return patchErr
	}
	return spec.update(c, spec.uuid(item), patch)
}

func (spec *idsMonitRecords[R, P]) runRemove(c *Context, args *Args) error {
	var item, err = spec.selectItem(c, args.String("item"))
	if err != nil {
		return err
	}
	return spec.remove(c, spec.uuid(item))
}

func (spec *idsMonitRecords[R, P]) enabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var item, err = spec.selectItem(c, args.String("item"))
		if err != nil {
			return err
		}
		if spec.enabled(item) == enabled {
			c.Infof("%s %q is already %s", spec.what, idsMonitFirstName(spec.names(item), spec.uuid(item)), EnabledWord(enabled))
			return nil
		}
		var patch P
		for _, field := range spec.fields {
			if field.Name == "disabled" && field.target != nil {
				var value = Flag(enabled)
				*field.target(&patch) = &value
			}
		}
		return spec.update(c, spec.uuid(item), patch)
	}
}

// idsMonitFirstName returns the first non empty name, fallback when there is none
func idsMonitFirstName(names []string, fallback string) string {
	for _, name := range names {
		if name != "" {
			return name
		}
	}
	return fallback
}

// idsMonitNamesToUuids resolves comma separated names (or uuids) of items to their uuids, in the given order
func idsMonitNamesToUuids[T any](what string, value string, items []T, uuid func(T) string, name func(T) string) (string, error) {
	var uuids []string
	for _, element := range splitList(value) {
		var matches []string
		for _, item := range items {
			if uuid(item) == element || name(item) == element {
				matches = append(matches, uuid(item))
			}
		}
		if len(matches) == 0 {
			for _, item := range items {
				if strings.EqualFold(name(item), element) {
					matches = append(matches, uuid(item))
				}
			}
		}
		switch len(matches) {
		case 0:
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q", what, element)}
		case 1:
			uuids = append(uuids, matches[0])
		default:
			return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %d items (%s), use the uuid", what, element,
				len(matches), strings.Join(matches, ", "))}
		}
	}
	return strings.Join(uuids, ","), nil
}

// idsMonitValidateText refuses control characters like newlines
func idsMonitValidateText(value string) error {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

// idsMonitValidateNoSpaces refuses spaces and control characters (OPNsense StrictTextFields)
func idsMonitValidateNoSpaces(value string) error {
	if strings.ContainsAny(value, " \t") {
		return fmt.Errorf("must not contain spaces, got %q", value)
	}
	return idsMonitValidateText(value)
}

// idsMonitListDisplay renders the ", " separated display names OPNsense sends in %fields as a comma list
func idsMonitListDisplay(display string, keys string) string {
	if display == "" {
		return keys
	}
	var names = strings.Split(display, ",")
	for i := range names {
		names[i] = strings.TrimSpace(names[i])
	}
	return strings.Join(names, ",")
}

// idsMonitRawFields renders a JSON object as "name: value" lines in document order, nested objects as
// "parent.child", arrays as compact JSON
func idsMonitRawFields(raw json.RawMessage) [][2]string {
	var lines [][2]string
	var walk func(prefix string, decoder *json.Decoder) error
	walk = func(prefix string, decoder *json.Decoder) error {
		for decoder.More() {
			var keyToken, err = decoder.Token()
			if err != nil {
				return err
			}
			var value json.RawMessage
			if err := decoder.Decode(&value); err != nil {
				return err
			}
			var name = prefix + fmt.Sprint(keyToken)
			var trimmed = bytes.TrimSpace(value)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				var inner = json.NewDecoder(bytes.NewReader(trimmed))
				if _, err := inner.Token(); err != nil {
					return err
				}
				if err := walk(name+".", inner); err != nil {
					return err
				}
				continue
			}
			var text string
			if json.Unmarshal(trimmed, &text) != nil {
				var compact bytes.Buffer
				if json.Compact(&compact, trimmed) == nil {
					text = compact.String()
				}
				if text == "null" {
					text = ""
				}
			}
			lines = append(lines, [2]string{name, strings.ReplaceAll(text, "\n", `\n`)})
		}
		return nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return [][2]string{{"value", string(raw)}}
	}
	_ = walk("", decoder)
	return lines
}
