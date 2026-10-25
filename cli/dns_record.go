package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strings"
)

// A declarative item menu (print, show, add, set, remove, enable, disable) for the record lists of the Dnsmasq and
// Unbound settings controllers. Each menu describes its fields once (argument, API name, how values map); rows are
// handled as the raw API values (search rows carry option keys and relation uuids, not display names)

// dnsFieldKind tells how an argument value maps to the API value
type dnsFieldKind int

const (
	dnsText     dnsFieldKind = iota // as given (option values normalized to their spelling in Arg.Values)
	dnsBool                         // yes/no <-> 1/0
	dnsDisabled                     // the RouterOS disabled flag <-> the API's enabled field, inverted
	dnsList                         // comma separated, blanks dropped
)

// dnsField is one writable field of a record
type dnsField struct {
	// Arg is the add / set argument; Required and Default only apply to add
	Arg  Arg
	Api  string
	Kind dnsFieldKind
	// Ref: the values are names of other records (# not allowed), the API stores their uuids
	Ref *dnsRef
	// Reset is the OPNsense default, sent by "add ... replace" for arguments not given
	Reset string
	// ToApi converts a given value after Kind and Ref (e.g. a DHCP option name to its code)
	ToApi func(c *Context, value string) (string, error)
	// Describe shows the API's description of the value (the "%<api>" column of the search rows) in print
	Describe bool
}

// dnsRef resolves names of other records to uuids and back
type dnsRef struct {
	What string
	Load func(c *Context) ([]dnsRefItem, error)
}

type dnsRefItem struct {
	Uuid  string
	Names []string // the first is the display name
}

// dnsRecordMenu describes a record menu
type dnsRecordMenu struct {
	Path     string
	Help     string
	What     string // e.g. "DHCP range", used in messages and help
	ItemHelp string // help of the item argument, e.g. "the #, uuid or name of the tag"
	// AddLong / SetLong / RemoveLong are put before ApplyHint in the help of add / set / remove
	AddLong, SetLong, RemoveLong string
	ApplyHint                    string
	Fields                       []dnsField
	// Columns are the argument names print shows (headers in upper case)
	Columns []string
	// Names returns the natural names an item can be selected by
	Names func(row dnsRow) []string
	// Key returns the natural key: add fails for an existing key unless replace, set refuses duplicates.
	// nil: no key, add always creates and has no replace flag
	Key     func(row dnsRow) string
	KeyHelp string // e.g. "the same name", for the replace help
	// Prepare checks / completes a patch before it is sent; row is nil for add
	Prepare func(c *Context, row dnsRow, patch map[string]string) error

	Search func(c *Context, searchPhrase string) ([]json.RawMessage, error)
	Create func(c *Context, patch map[string]string) (string, error)
	Update func(c *Context, row dnsRow, patch map[string]string) error
	Remove func(c *Context, uuid string) error
}

// dnsRow is a record as API name -> raw value
type dnsRow map[string]string

func (row dnsRow) uuid() string {
	return row["uuid"]
}

// dnsDecodeRow turns a search row into a dnsRow: strings as they are, numbers and booleans as JSON text,
// nested values (like _children) are left out
func dnsDecodeRow(raw json.RawMessage) (dnsRow, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("unexpected row from OPNsense: %w", err)
	}
	var row = dnsRow{}
	for name, value := range fields {
		var text string
		if json.Unmarshal(value, &text) == nil {
			row[name] = text
			continue
		}
		var trimmed = strings.TrimSpace(string(value))
		if trimmed != "" && trimmed != "null" && trimmed[0] != '{' && trimmed[0] != '[' {
			row[name] = trimmed
		}
	}
	return row, nil
}

// --- registration

func (m *dnsRecordMenu) field(arg string) *dnsField {
	for i := range m.Fields {
		if m.Fields[i].Arg.Name == arg {
			return &m.Fields[i]
		}
	}
	panic(fmt.Sprintf("%s: no field %q", m.Path, arg))
}

func (m *dnsRecordMenu) disabledField() *dnsField {
	for i := range m.Fields {
		if m.Fields[i].Kind == dnsDisabled {
			return &m.Fields[i]
		}
	}
	return nil
}

// fieldArgs are the field arguments of add (required, defaults) or set (all optional)
func (m *dnsRecordMenu) fieldArgs(add bool) []Arg {
	var args = make([]Arg, 0, len(m.Fields))
	for _, field := range m.Fields {
		var arg = field.Arg
		if field.Ref != nil && arg.Complete == nil {
			arg.Complete = dnsRefComplete(field.Ref)
		}
		if !add {
			arg.Required = false
			arg.Default = ""
		}
		args = append(args, arg)
	}
	return args
}

func (m *dnsRecordMenu) hint(text string) string {
	return strings.TrimSpace(strings.TrimSpace(text) + "\n" + m.ApplyHint)
}

// register adds the menu with print, show, add, set, remove (and enable / disable when there is a disabled field)
// plus extra commands
func (m *dnsRecordMenu) register(extra ...*Command) *Menu {
	var menu = Root.Menu(m.Path)
	menu.Help = m.Help
	var item = Arg{Name: "item", Help: m.ItemHelp, Positional: true, Required: true, Complete: m.complete}

	var addArgs = m.fieldArgs(true)
	var addLong = m.AddLong
	if m.Key != nil {
		addArgs = append(addArgs, Arg{Name: "replace", Type: Bool, Help: "replace the " + m.What + " with " + m.KeyHelp})
		addLong = strings.TrimSpace(addLong + fmt.Sprintf(`
If a %s with %s exists already, add fails unless replace is given, then that entry is replaced
completely (arguments not given are reset to their defaults).`, m.What, m.KeyHelp))
	}

	menu.Add(
		&Command{Name: "print", Help: "list the " + m.What + "s", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every " + m.What},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "search", Help: "only entries where any field contains this text"},
		}, Run: m.print},
		&Command{Name: "show", Help: "show all fields of one " + m.What, Args: []Arg{item}, Run: m.show},
		&Command{Name: "add", Help: "add a " + m.What + ", prints its uuid", Long: m.hint(addLong), Args: addArgs, Run: m.add},
		&Command{Name: "set", Help: "change fields of a " + m.What + ", the others are kept",
			Long: m.hint(m.SetLong + "\nAn empty value clears a field (like description=)."),
			Args: append([]Arg{item}, m.fieldArgs(false)...), Check: m.checkSet, Run: m.set},
		&Command{Name: "remove", Help: "remove a " + m.What, Long: m.hint(m.RemoveLong), Args: []Arg{item}, Run: m.remove},
	)
	if m.disabledField() != nil {
		menu.Add(
			&Command{Name: "enable", Help: "enable a " + m.What, Long: m.ApplyHint, Args: []Arg{item}, Run: m.enabler(true)},
			&Command{Name: "disable", Help: "disable a " + m.What, Long: m.ApplyHint, Args: []Arg{item}, Run: m.enabler(false)},
		)
	}
	menu.Add(extra...)
	return menu
}

func (m *dnsRecordMenu) checkSet(args *Args) error {
	for _, field := range m.Fields {
		if args.Has(field.Arg.Name) {
			return nil
		}
	}
	return fmt.Errorf("set: nothing to change, give at least one field like %s= (type \"set ?\" for help)", m.Fields[0].Arg.Name)
}

// --- loading

// dnsRecordRun caches what one command loads: the rows and the referenced records
type dnsRecordRun struct {
	c    *Context
	m    *dnsRecordMenu
	refs map[*dnsRef][]dnsRefItem
}

func (m *dnsRecordMenu) run(c *Context) *dnsRecordRun {
	return &dnsRecordRun{c: c, m: m, refs: map[*dnsRef][]dnsRefItem{}}
}

func (r *dnsRecordRun) rows(searchPhrase string) ([]dnsRow, []json.RawMessage, error) {
	var raws, err = r.m.Search(r.c, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var rows = make([]dnsRow, len(raws))
	for i, raw := range raws {
		if rows[i], err = dnsDecodeRow(raw); err != nil {
			return nil, nil, err
		}
	}
	return rows, raws, nil
}

func (r *dnsRecordRun) names(row dnsRow) []string {
	if r.m.Names == nil {
		return nil
	}
	return r.m.Names(row)
}

// selectRow loads all rows and returns the one selector refers to, with all rows
func (r *dnsRecordRun) selectRow(selector string) (dnsRow, []dnsRow, error) {
	var rows, _, err = r.rows("")
	if err != nil {
		return nil, nil, err
	}
	var row, selectErr = Select(r.c, selector, rows, dnsRow.uuid, r.names)
	return row, rows, selectErr
}

func (m *dnsRecordMenu) complete(c *Context) []string {
	var rows, _, err = m.run(c).rows("")
	if err != nil || m.Names == nil {
		return nil
	}
	var names []string
	for _, row := range rows {
		for _, name := range m.Names(row) {
			if name != "" {
				names = append(names, name)
				break
			}
		}
	}
	return names
}

func (r *dnsRecordRun) refItems(ref *dnsRef) ([]dnsRefItem, error) {
	if items, loaded := r.refs[ref]; loaded {
		return items, nil
	}
	var items, err = ref.Load(r.c)
	if err != nil {
		return nil, err
	}
	r.refs[ref] = items
	return items, nil
}

func dnsRefComplete(ref *dnsRef) func(c *Context) []string {
	return func(c *Context) []string {
		var items, err = ref.Load(c)
		if err != nil {
			return nil
		}
		var names []string
		for _, item := range items {
			if len(item.Names) > 0 {
				names = append(names, item.Names[0])
			}
		}
		return names
	}
}

// dnsRefResolve finds the uuid of a referenced record by uuid or name (case-insensitive)
func dnsRefResolve(ref *dnsRef, items []dnsRefItem, value string) (string, error) {
	for _, item := range items {
		if strings.EqualFold(item.Uuid, value) {
			return item.Uuid, nil
		}
	}
	var matches []string
	for _, item := range items {
		for _, name := range item.Names {
			if strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(value, ".")) {
				matches = append(matches, item.Uuid)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q", ref.What, value)}
	case 1:
		return matches[0], nil
	}
	return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, use the uuid", ref.What, value, strings.Join(matches, ", "))}
}

// --- values

// toApi converts the given argument of field to its API value
func (r *dnsRecordRun) toApi(field dnsField, args *Args) (string, error) {
	var value = strings.TrimSpace(args.String(field.Arg.Name))
	var err error
	switch field.Kind {
	case dnsBool:
		value = Flag(args.Bool(field.Arg.Name))
	case dnsDisabled:
		value = Flag(!args.Bool(field.Arg.Name))
	case dnsList:
		var elements = args.List(field.Arg.Name)
		for i := range elements {
			elements[i] = dnsCanonicalValue(field.Arg.Values, elements[i])
		}
		value = strings.Join(elements, ",")
	default:
		value = dnsCanonicalValue(field.Arg.Values, value)
	}

	if field.Ref != nil && value != "" {
		var items, loadErr = r.refItems(field.Ref)
		if loadErr != nil {
			return "", loadErr
		}
		var uuids []string
		for _, name := range splitList(value) {
			var uuid, resolveErr = dnsRefResolve(field.Ref, items, name)
			if resolveErr != nil {
				return "", fmt.Errorf("%s: %w", field.Arg.Name, resolveErr)
			}
			uuids = append(uuids, uuid)
		}
		value = strings.Join(uuids, ",")
	}
	if field.ToApi != nil && value != "" {
		if value, err = field.ToApi(r.c, value); err != nil {
			return "", fmt.Errorf("%s: %w", field.Arg.Name, err)
		}
	}
	return value, nil
}

// dnsCanonicalValue returns value as spelled in values (they are matched case-insensitively)
func dnsCanonicalValue(values []string, value string) string {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return candidate
		}
	}
	return value
}

// patch converts the given field arguments; with all (add ... replace) the others get their Reset value
func (r *dnsRecordRun) patch(args *Args, all bool) (map[string]string, error) {
	var patch = map[string]string{}
	for _, field := range r.m.Fields {
		if !args.Has(field.Arg.Name) {
			if all {
				patch[field.Api] = field.Reset
			}
			continue
		}
		var value, err = r.toApi(field, args)
		if err != nil {
			return nil, err
		}
		patch[field.Api] = value
	}
	return patch, nil
}

// display renders the API value of field for output: yes/no, names of referenced records, lists in table cells
func (r *dnsRecordRun) display(field dnsField, row dnsRow, cell bool) string {
	var value = row[field.Api]
	switch field.Kind {
	case dnsBool:
		return YesNo(value)
	case dnsDisabled:
		if value == "0" {
			return "yes"
		}
		return "no"
	}
	if cell && field.Describe && row["%"+field.Api] != "" {
		return row["%"+field.Api]
	} else if field.Ref != nil && value != "" {
		var items, err = r.refItems(field.Ref)
		if err == nil {
			var names []string
			for _, uuid := range splitList(value) {
				var name = uuid
				for _, item := range items {
					if item.Uuid == uuid && len(item.Names) > 0 {
						name = item.Names[0]
					}
				}
				names = append(names, name)
			}
			value = strings.Join(names, ",")
		}
	}
	if cell {
		return dnsmasqListCell(value)
	}
	return value
}

func (r *dnsRecordRun) fields(row dnsRow) [][2]string {
	var fields = [][2]string{{"uuid", row.uuid()}}
	for _, field := range r.m.Fields {
		fields = append(fields, [2]string{field.Arg.Name, r.display(field, row, false)})
	}
	return fields
}

// merged returns row with patch applied
func dnsMerged(row dnsRow, patch map[string]string) dnsRow {
	var merged = dnsRow{}
	for name, value := range row {
		merged[name] = value
	}
	for name, value := range patch {
		merged[name] = value
	}
	return merged
}

// --- commands

func (m *dnsRecordMenu) print(c *Context, args *Args) error {
	var r = m.run(c)
	var rows, raws, err = r.rows(args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, raw := range raws {
			if err := c.JSON(raw); err != nil {
				return err
			}
		}
		return nil
	}
	var uuids = make([]string, len(rows))
	for i, row := range rows {
		uuids[i] = row.uuid()
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(rows))
		for i, row := range rows {
			details[i] = r.fields(row)
		}
		c.Details(details, uuids)
		return nil
	}
	var headers = make([]string, len(m.Columns))
	for i, column := range m.Columns {
		headers[i] = strings.ToUpper(column)
	}
	var cells = make([][]string, len(rows))
	for i, row := range rows {
		for _, column := range m.Columns {
			cells[i] = append(cells[i], r.display(*m.field(column), row, true))
		}
	}
	c.Items(headers, cells, uuids)
	return nil
}

func (m *dnsRecordMenu) show(c *Context, args *Args) error {
	var r = m.run(c)
	var row, _, err = r.selectRow(args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(r.fields(row))
	return nil
}

// duplicate returns the row (other than self) with the same natural key as candidate
func (m *dnsRecordMenu) duplicate(rows []dnsRow, candidate dnsRow, self string) dnsRow {
	if m.Key == nil {
		return nil
	}
	var key = strings.ToLower(m.Key(candidate))
	for _, row := range rows {
		if row.uuid() != self && strings.ToLower(m.Key(row)) == key {
			return row
		}
	}
	return nil
}

func (m *dnsRecordMenu) add(c *Context, args *Args) error {
	var r = m.run(c)
	var replace = m.Key != nil && args.Bool("replace")
	var patch, err = r.patch(args, false)
	if err != nil {
		return err
	}
	if m.Prepare != nil {
		if err := m.Prepare(c, nil, patch); err != nil {
			return err
		}
	}

	if m.Key != nil {
		var rows, _, loadErr = r.rows("")
		if loadErr != nil {
			return loadErr
		}
		if existing := m.duplicate(rows, dnsRow(patch), ""); existing != nil {
			if !replace {
				return fmt.Errorf("a %s with %s exists already (%s), change it with set or replace it with add ... replace",
					m.What, m.KeyHelp, existing.uuid())
			}
			var full, fullErr = r.patch(args, true)
			if fullErr != nil {
				return fullErr
			}
			if m.Prepare != nil {
				if err := m.Prepare(c, existing, full); err != nil {
					return err
				}
			}
			if err := m.Update(c, existing, full); err != nil {
				return err
			}
			c.Infof("replaced the existing %s %s", m.What, existing.uuid())
			c.Println(existing.uuid())
			return nil
		}
	}

	var uuid, createErr = m.Create(c, patch)
	if createErr != nil {
		return createErr
	}
	c.Println(uuid)
	return nil
}

func (m *dnsRecordMenu) set(c *Context, args *Args) error {
	var r = m.run(c)
	var row, rows, err = r.selectRow(args.String("item"))
	if err != nil {
		return err
	}
	patch, err := r.patch(args, false)
	if err != nil {
		return err
	}
	if m.Prepare != nil {
		if err := m.Prepare(c, row, patch); err != nil {
			return err
		}
	}
	if existing := m.duplicate(rows, dnsMerged(row, patch), row.uuid()); existing != nil {
		return fmt.Errorf("a %s with %s exists already (%s)", m.What, m.KeyHelp, existing.uuid())
	}
	return m.Update(c, row, patch)
}

func (m *dnsRecordMenu) remove(c *Context, args *Args) error {
	var row, _, err = m.run(c).selectRow(args.String("item"))
	if err != nil {
		return err
	}
	return m.Remove(c, row.uuid())
}

func (m *dnsRecordMenu) enabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var field = m.disabledField()
		var row, _, err = m.run(c).selectRow(args.String("item"))
		if err != nil {
			return err
		}
		if (row[field.Api] != "0") == enabled {
			c.Infof("%s %s is already %s", m.What, row.uuid(), EnabledWord(enabled))
			return nil
		}
		return m.Update(c, row, map[string]string{field.Api: Flag(enabled)})
	}
}

// --- shared helpers of the dnsmasq and unbound menus

// dnsSearchRaw returns the raw rows of api/<module>/<controller>/<method>
func dnsSearchRaw(c *Context, module string, controller string, method string, searchPhrase string) ([]json.RawMessage, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return coreapi.Search[json.RawMessage](opn, opn.EndpointForPluginControllerMethod(module, controller, method), searchPhrase)
}

// dnsDecodeStrict converts a patch to a record struct, failing on API names the struct does not have
func dnsDecodeStrict(patch map[string]string, record any) error {
	var data, err = json.Marshal(patch)
	if err != nil {
		return err
	}
	var decoder = json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(record)
}

// dnsNotEmpty rejects an empty value of a required field (like name=)
func dnsNotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty")
	}
	return nil
}

// dnsSortedKeys returns the keys of a map sorted
func dnsSortedKeys[V any](values map[string]V) []string {
	var keys = make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// dnsValidateNetworks accepts a comma separated list of networks in CIDR notation
func dnsValidateNetworks(value string) error {
	for _, element := range splitList(value) {
		if _, _, err := net.ParseCIDR(element); err != nil {
			return fmt.Errorf("must be networks in CIDR notation like 192.0.2.0/24, got %q", element)
		}
	}
	return nil
}
