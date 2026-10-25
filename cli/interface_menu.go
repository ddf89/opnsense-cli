package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/interfaces"
)

// The item menus below /interface (vlan, lagg, bridge, gif, gre, loopback, vxlan, vip, neighbor) are built from an
// interfaceSpec: Interfaces > Devices, Virtual IPs and Neighbors of OPNsense (api/interfaces/*_settings) all have
// the same search/get/add/set/del/reconfigure endpoints. Changes are only saved, every menu has an apply command

func init() {
	// interface.go registers the menu with the traffic commands, its help is extended here (init runs after it)
	Root.Menu("interface").Help = "network interfaces: devices, virtual IPs, neighbors, settings, overview, traffic"
}

// interfaceApi returns the Interfaces API of the connection
func interfaceApi(c *Context) (*interfaces.InterfacesApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &interfaces.InterfacesApi{OPNsense: opn}, nil
}

// interfaceMasked replaces secrets in the output
const interfaceMasked = "********"

// interfaceFieldKind is how an argument value maps to the API value
type interfaceFieldKind int

const (
	interfaceText   interfaceFieldKind = iota // as given (lists comma separated)
	interfaceFlag                             // yes/no as 1/0
	interfaceMapped                           // one of the mapping's argument values, sent as its API value
	interfaceSecret                           // as given, never shown
)

// interfaceField is a field argument of add and set, mapped to the API field api
type interfaceField struct {
	Arg
	api  string
	kind interfaceFieldKind
	// mapping pairs {argument value, API value} for interfaceMapped, the first is the default shown
	mapping [][2]string
	// optional fields exist only in some releases, show skips them when the record has no such field
	optional bool
	// device marks the field holding the device name, show lists it as device
	device bool
	// display renders the field when the search rows hold it differently (the network of virtual IPs), nil for
	// the API value
	display func(item interfaces.Item) string
}

// interfaceColumn is a column of print
type interfaceColumn struct {
	header string
	value  func(item interfaces.Item) string
}

// interfaceApplySpec describes the apply command of a menu
type interfaceApplySpec struct {
	help    string
	long    string
	confirm string
}

// interfaceSpec describes an item menu
type interfaceSpec struct {
	path     string
	help     string
	kind     interfaces.Kind
	itemHelp string
	// printLong is the long help of print (meaning of the columns)
	printLong string
	fields    []interfaceField
	columns   []interfaceColumn
	// names are the natural names an item can be selected by (besides # and uuid)
	names func(item interfaces.Item) []string
	// keyArgs identify an existing item for add (add fails unless replace), nil: add always creates an item
	keyArgs []string
	// keyMatch tells whether item has the natural key given by the API field values of add
	keyMatch func(item interfaces.Item, fields map[string]string) bool
	addLong  string
	setLong  string
	// check validates the field arguments of add and set together (add tells which), nil for none
	check func(args *Args, add bool) error
	// convert adjusts the API fields built from the arguments (e.g. address -> network), nil for none
	convert func(args *Args, fields map[string]string)
	apply   interfaceApplySpec
}

func (spec *interfaceSpec) what() string {
	return spec.kind.Name
}

func (spec *interfaceSpec) applyHint() string {
	return fmt.Sprintf(`Changes are only saved, run "/%s apply" to apply them.`, spec.path)
}

// interfaceRegister builds the menu of spec
func interfaceRegister(spec *interfaceSpec) {
	var menu = Root.Menu(spec.path)
	menu.Help = spec.help
	var item = Arg{Name: "item", Help: spec.itemHelp, Positional: true, Required: true, Complete: spec.completeItems}
	var replace []Arg
	if spec.keyArgs != nil {
		replace = []Arg{{Name: "replace", Type: Bool, Help: fmt.Sprintf("replace the %s with the same %s", spec.what(), strings.Join(spec.keyArgs, " and "))}}
	}
	menu.Add(
		&Command{Name: "print", Help: fmt.Sprintf("list the %ss", spec.what()), Long: spec.printLong,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every item"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them" + spec.maskedNote()},
				{Name: "search", Help: "only items where any field contains this text"},
			}, Run: spec.print},
		&Command{Name: "show", Help: fmt.Sprintf("show all fields of one %s", spec.what()), Args: []Arg{item}, Run: spec.show},
		&Command{Name: "add", Help: fmt.Sprintf("add a %s, prints its uuid", spec.what()),
			Long: strings.TrimSpace(spec.addLong + "\n" + spec.applyHint()),
			Args: append(spec.fieldArgs(true), replace...), Check: spec.checker(true), Run: spec.add},
		&Command{Name: "set", Help: fmt.Sprintf("change fields of a %s, the others are kept", spec.what()),
			Long: strings.TrimSpace(spec.setLong + "\n" + spec.applyHint()),
			Args: append([]Arg{item}, spec.fieldArgs(false)...), Check: spec.checker(false), Run: spec.set},
		&Command{Name: "remove", Help: fmt.Sprintf("remove a %s", spec.what()),
			Long: spec.applyHint(), Args: []Arg{item}, Run: spec.remove},
		&Command{Name: "apply", Aliases: []string{"reconfigure"}, Help: spec.apply.help, Long: spec.apply.long,
			Confirm: spec.apply.confirm, Run: spec.reconfigure},
	)
}

func (spec *interfaceSpec) maskedNote() string {
	for _, field := range spec.fields {
		if field.kind == interfaceSecret {
			return " (secrets masked)"
		}
	}
	return ""
}

// fieldArgs are the field arguments, required ones only for add
func (spec *interfaceSpec) fieldArgs(add bool) []Arg {
	var args = make([]Arg, 0, len(spec.fields))
	for _, field := range spec.fields {
		var arg = field.Arg
		arg.Required = add && arg.Required
		if field.kind == interfaceMapped && arg.Values == nil {
			for _, pair := range field.mapping {
				arg.Values = append(arg.Values, pair[0])
			}
		}
		args = append(args, arg)
	}
	return args
}

func (spec *interfaceSpec) checker(add bool) func(args *Args) error {
	return func(args *Args) error {
		if !add {
			var given = false
			for _, field := range spec.fields {
				given = given || args.Has(field.Name)
			}
			if !given {
				return errors.New("set: nothing to change, give at least one field (type \"set ?\" for help)")
			}
		}
		if spec.check != nil {
			return spec.check(args, add)
		}
		return nil
	}
}

// --- values

// apiValue converts the value of a given field argument to the API value
func (field interfaceField) apiValue(args *Args) string {
	switch field.kind {
	case interfaceFlag:
		return Flag(args.Bool(field.Name))
	case interfaceMapped:
		var value = args.String(field.Name)
		for _, pair := range field.mapping {
			if strings.EqualFold(pair[0], value) {
				return pair[1]
			}
		}
		return value
	}
	if field.Type == List {
		return strings.Join(args.List(field.Name), ",")
	}
	return strings.TrimSpace(args.String(field.Name))
}

// text renders the API value of the field like the arguments take it
func (field interfaceField) text(item interfaces.Item) string {
	if field.display != nil {
		return field.display(item)
	}
	var value = item.Get(field.api)
	switch field.kind {
	case interfaceFlag:
		return YesNo(value)
	case interfaceSecret:
		if value == "" {
			return ""
		}
		return interfaceMasked
	case interfaceMapped:
		for _, pair := range field.mapping {
			if pair[1] == value {
				return pair[0]
			}
		}
	}
	return value
}

// apiFields builds the API fields of the given field arguments
func (spec *interfaceSpec) apiFields(args *Args) map[string]string {
	var fields = map[string]string{}
	for _, field := range spec.fields {
		if args.Has(field.Name) {
			fields[field.api] = field.apiValue(args)
		}
	}
	if spec.convert != nil {
		spec.convert(args, fields)
	}
	return fields
}

// translate renames the fields of an OPNsense validation error ("vlan.tag") to the arguments ("tag")
func (spec *interfaceSpec) translate(err error) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var translated = map[string]string{}
	for key, message := range validation.Validations {
		var name = key
		if _, apiName, found := strings.Cut(key, "."); found {
			name = apiName
			for _, field := range spec.fields {
				if field.api == apiName || (field.api == "network" && (apiName == "subnet" || apiName == "subnet_bits")) {
					name = field.Name
					break
				}
			}
		}
		if previous, duplicate := translated[name]; duplicate && previous != message {
			message = previous + "; " + message
		}
		translated[name] = message
	}
	return &coreapi.ValidationError{Validations: translated}
}

// --- lookups

func (spec *interfaceSpec) itemUuid(item interfaces.Item) string {
	return item.Uuid
}

func (spec *interfaceSpec) itemNames(item interfaces.Item) []string {
	var names []string
	if device := spec.kind.Device(item); device != "" {
		names = append(names, device)
	}
	if spec.names != nil {
		names = append(names, spec.names(item)...)
	}
	return names
}

func (spec *interfaceSpec) selectItem(c *Context, api *interfaces.InterfacesApi, selector string) (interfaces.Item, error) {
	var items, err = api.List(spec.kind)
	if err != nil {
		return interfaces.Item{}, err
	}
	return Select(c, selector, items, spec.itemUuid, spec.itemNames)
}

func (spec *interfaceSpec) completeItems(c *Context) []string {
	var api, err = interfaceApi(c)
	if err != nil {
		return nil
	}
	var items, listErr = api.List(spec.kind)
	if listErr != nil {
		return nil
	}
	var names []string
	for _, item := range items {
		if found := spec.itemNames(item); len(found) > 0 && found[0] != "" {
			names = append(names, found[0])
		}
	}
	return names
}

// interfaceCompleteOptions completes the choices of an option field from the form of a new item
func interfaceCompleteOptions(kind interfaces.Kind, field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = interfaceApi(c)
		if err != nil {
			return nil
		}
		var form, formErr = api.Form(kind)
		if formErr != nil {
			return nil
		}
		var keys []string
		for _, option := range form.Options[field] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

// interfaceAssignedDevices maps devices to their interface identifier (vlan01 -> opt1), empty when the
// assignments can not be read
func interfaceAssignedDevices(api *interfaces.InterfacesApi) map[string]string {
	var assigned = map[string]string{}
	var assignments, err = api.Assignments()
	if err != nil {
		return assigned
	}
	for _, assignment := range assignments {
		assigned[assignment.Device] = assignment.Identifier
	}
	return assigned
}

// --- output

func (spec *interfaceSpec) detail(item interfaces.Item, assigned map[string]string) [][2]string {
	var fields = [][2]string{{"uuid", item.Uuid}}
	if spec.kind.HasDevice() {
		var device = spec.kind.Device(item)
		fields = append(fields, [2]string{"device", device}, [2]string{"assigned", assigned[device]})
	}
	for _, field := range spec.fields {
		if field.device || field.optional && field.display == nil && !item.Has(field.api) {
			continue
		}
		fields = append(fields, [2]string{field.Name, field.text(item)})
	}
	if origin := item.Get("origin"); origin != "" {
		fields = append(fields, [2]string{"origin", origin})
	}
	return fields
}

// rawRow returns the row as OPNsense sent it, secrets masked
func (spec *interfaceSpec) rawRow(item interfaces.Item) (any, error) {
	if spec.maskedNote() == "" {
		return item.Raw, nil
	}
	var object map[string]any
	if err := json.Unmarshal(item.Raw, &object); err != nil {
		return nil, err
	}
	for _, field := range spec.fields {
		if value, isString := object[field.api].(string); field.kind == interfaceSecret && isString && value != "" {
			object[field.api] = interfaceMasked
		}
	}
	return object, nil
}

func (spec *interfaceSpec) print(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var items, searchErr = api.Search(spec.kind, args.String("search"))
	if searchErr != nil {
		return searchErr
	}
	var uuids = make([]string, len(items))
	for i, item := range items {
		uuids[i] = item.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, item := range items {
			var row, rowErr = spec.rawRow(item)
			if rowErr != nil {
				return rowErr
			}
			if err := c.JSON(row); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var assigned = map[string]string{}
		if spec.kind.HasDevice() {
			assigned = interfaceAssignedDevices(api)
		}
		var blocks = make([][][2]string, len(items))
		for i, item := range items {
			blocks[i] = spec.detail(item, assigned)
		}
		c.Details(blocks, uuids)
	default:
		var headers []string
		if spec.kind.HasDevice() {
			headers = append(headers, "DEVICE")
		}
		for _, column := range spec.columns {
			headers = append(headers, column.header)
		}
		var rows = make([][]string, len(items))
		for i, item := range items {
			var row []string
			if spec.kind.HasDevice() {
				row = append(row, spec.kind.Device(item))
			}
			for _, column := range spec.columns {
				row = append(row, column.value(item))
			}
			rows[i] = row
		}
		c.Items(headers, rows, uuids)
	}
	return nil
}

func (spec *interfaceSpec) show(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var item, selectErr = spec.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var assigned = map[string]string{}
	if spec.kind.HasDevice() {
		assigned = interfaceAssignedDevices(api)
	}
	c.Fields(spec.detail(item, assigned))
	return nil
}

// --- changes

func (spec *interfaceSpec) add(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var fields = spec.apiFields(args)

	if spec.keyArgs != nil {
		var items, listErr = api.List(spec.kind)
		if listErr != nil {
			return listErr
		}
		var index = slices.IndexFunc(items, func(item interfaces.Item) bool { return spec.keyMatch(item, fields) })
		if index >= 0 {
			var existing = items[index]
			if !args.Bool("replace") {
				return fmt.Errorf("a %s with this %s exists already (%s), change it with set or replace it with add ... replace",
					spec.what(), strings.Join(spec.keyArgs, " and "), existing.Uuid)
			}
			// replace: the fields not given get their defaults
			var form, formErr = api.Form(spec.kind)
			if formErr != nil {
				return formErr
			}
			var replaced = map[string]string{}
			for _, field := range spec.fields {
				if value, known := form.Defaults[field.api]; known && !field.device {
					replaced[field.api] = value
				}
			}
			for field, value := range fields {
				replaced[field] = value
			}
			if err := api.Update(spec.kind, existing.Uuid, replaced); err != nil {
				return spec.translate(err)
			}
			c.Infof("replaced the existing %s %s", spec.what(), existing.Uuid)
			c.Println(existing.Uuid)
			return nil
		}
	}

	var uuid, createErr = api.Create(spec.kind, fields)
	if createErr != nil {
		return spec.translate(createErr)
	}
	c.Println(uuid)
	if spec.kind.HasDevice() {
		if created, getErr := api.Get(spec.kind, uuid); getErr == nil && spec.kind.Device(created) != "" {
			c.Infof("device %s", spec.kind.Device(created))
		}
	}
	return nil
}

func (spec *interfaceSpec) set(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var item, selectErr = spec.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return spec.translate(api.Update(spec.kind, item.Uuid, spec.apiFields(args)))
}

func (spec *interfaceSpec) remove(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var item, selectErr = spec.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.Remove(spec.kind, item.Uuid)
}

func (spec *interfaceSpec) reconfigure(c *Context, _ *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	return api.Reconfigure(spec.kind)
}

// --- shared validation and columns

// interfaceValidateText rejects control characters like newlines
func interfaceValidateText(value string) error {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]*$`)

// interfaceValidateName accepts a device or interface name like vtnet0, lan, opt1, vlan01 or vlan0.10
func interfaceValidateName(value string) error {
	if !interfaceNamePattern.MatchString(value) {
		return fmt.Errorf("must be a name like vtnet0, lan or opt1, got %q", value)
	}
	return nil
}

// interfaceValidateNames accepts comma separated names (see interfaceValidateName)
func interfaceValidateNames(value string) error {
	for _, element := range splitList(value) {
		if err := interfaceValidateName(element); err != nil {
			return err
		}
	}
	return nil
}

// interfaceChoices maps values sent as they are (case-insensitive arguments, sent as OPNsense spells them)
func interfaceChoices(values ...string) [][2]string {
	var mapping = make([][2]string, len(values))
	for i, value := range values {
		mapping[i] = [2]string{value, value}
	}
	return mapping
}

// interfaceValidateIPOrName accepts an IP address or an interface name like wan, opt1 or wan_vip1
func interfaceValidateIPOrName(value string) error {
	if ValidateIP(value) == nil {
		return nil
	}
	if err := interfaceValidateName(value); err != nil {
		return fmt.Errorf("must be an IP address or an interface like wan, opt1 or wan_vip1, got %q", value)
	}
	return nil
}

// interfaceCompleteIdentifiers completes the assigned interfaces (lan, wan, opt1)
func interfaceCompleteIdentifiers(c *Context) []string {
	var api, err = interfaceApi(c)
	if err != nil {
		return nil
	}
	var assignments, listErr = api.Assignments()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		names = append(names, assignment.Identifier)
	}
	return names
}

// interfaceDescription is the description field argument for the API field api
func interfaceDescription(api string) interfaceField {
	return interfaceField{Arg: Arg{Name: "description", Help: "any text", Validate: interfaceValidateText}, api: api}
}

// interfaceFieldColumn is a print column showing a field like show does
func interfaceFieldColumn(header string, spec *interfaceSpec, arg string) interfaceColumn {
	return interfaceColumn{header: header, value: func(item interfaces.Item) string {
		for _, field := range spec.fields {
			if field.Name == arg {
				return field.text(item)
			}
		}
		return ""
	}}
}
