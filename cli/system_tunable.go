package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"sort"
	"strings"
)

// /system/tunable: System > Settings > Tunables (sysctl / loader.conf values). Items are selected by the # of
// print, the uuid or the tunable name. Built-in OPNsense defaults are listed even when they are not configured:
// their uuid is a 32 character md5 key and their value is the current runtime value. Setting one stores an
// override, removing the override brings back the built-in default

const systemTunableItemHelp = "the #, uuid or name of the tunable (like kern.ipc.maxsockbuf)"

const systemTunableApplyHint = `Changes are only saved, run "/system/tunable apply" to apply them.`

func init() {
	var menu = Root.Menu("system/tunable")
	menu.Help = "tunables: sysctl and loader.conf values (System > Settings > Tunables)"
	var item = Arg{Name: "item", Help: systemTunableItemHelp, Positional: true, Required: true, Complete: systemTunableItemNames}
	var value = Arg{Name: "value", Help: `the value, "" uses the built-in default`, Validate: systemTunableValidateValue}
	var description = Arg{Name: "description", Help: "any text"}
	menu.Add(
		&Command{Name: "print", Help: "list the configured tunables and the built-in defaults",
			Long: `SOURCE is "built-in" for defaults which are not configured (VALUE is then the current runtime value),
"override" for a configured built-in and "custom" for other configured tunables. An empty VALUE ("-") of a
configured tunable means the DEFAULT is used.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every tunable", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only tunables where any field contains this text"},
				{Name: "changed", Help: "only configured tunables whose value differs from the default", Type: Bool},
			}, Run: systemTunablePrint},
		&Command{Name: "show", Help: "show all fields of one tunable", Args: []Arg{item}, Run: systemTunableShow},
		&Command{Name: "add", Help: "add a tunable, prints its uuid",
			Long: `Adding the name of a built-in default overrides it. If the name is configured already, add fails unless
replace is given, then that entry is replaced completely (a description not given is cleared).
` + systemTunableApplyHint,
			Args: []Arg{
				{Name: "name", Help: "the sysctl or loader variable, like kern.ipc.maxsockbuf", Required: true, Validate: systemTunableValidateName},
				systemTunableRequired(value),
				description,
				{Name: "replace", Help: "replace the configured entry with the same name", Type: Bool},
			}, Run: systemTunableAdd},
		&Command{Name: "set", Help: "change fields of a tunable, the others are kept",
			Long: `Setting a built-in default which is not configured yet stores an override with the given value.
` + systemTunableApplyHint,
			Args: []Arg{
				item,
				{Name: "name", Help: "rename the configured entry", Validate: systemTunableValidateName},
				value,
				description,
			}, Run: systemTunableSet},
		&Command{Name: "remove", Help: "remove a configured tunable",
			Long: `Removing an override brings back the built-in default, built-in defaults themselves can not be removed.
` + systemTunableApplyHint,
			Args: []Arg{item}, Run: systemTunableRemove},
		&Command{Name: "apply", Help: "apply the tunables (sets runtime sysctls, regenerates loader.conf)",
			Long: `Runtime sysctls which differ from the configuration are set and /boot/loader.conf is regenerated,
boot-time tunables take effect after a reboot.`,
			Run: systemTunableApply},
	)
}

func systemTunableRequired(arg Arg) Arg {
	arg.Required = true
	return arg
}

// --- validation: OPNsense accepts anything and writes it unquoted into /boot/loader.conf on apply

func systemTunableValidateName(name string) error {
	if err := system.TunableValidate(name, ""); err != nil {
		return fmt.Errorf("must be a sysctl name like kern.ipc.maxsockbuf, got %q", name)
	}
	return nil
}

func systemTunableValidateValue(value string) error {
	if err := system.TunableValidate("x", value); err != nil {
		return fmt.Errorf("must not contain double quotes or control characters, got %q", value)
	}
	return nil
}

// --- lookups

func systemTunableApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemTunableSearch returns the matching tunables in API order, with the raw API objects for json output
func systemTunableSearch(api *system.SystemApi, searchPhrase string) ([]system.Tunable, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("core", "tunables", "search_item")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var tunables = make([]system.Tunable, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &tunables[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected tunable from OPNsense: %w", err)
		}
	}
	return tunables, rows, nil
}

func systemTunableUuid(tunable system.Tunable) string {
	return tunable.Uuid
}

func systemTunableNames(tunable system.Tunable) []string {
	return []string{tunable.Tunable}
}

// systemTunableSelect loads all tunables and finds the one selector refers to
func systemTunableSelect(c *Context, api *system.SystemApi, selector string) (system.Tunable, error) {
	var tunables, _, err = systemTunableSearch(api, "")
	if err != nil {
		return system.Tunable{}, err
	}
	return Select(c, selector, tunables, systemTunableUuid, systemTunableNames)
}

// systemTunableItemNames completes item names from the API
func systemTunableItemNames(c *Context) []string {
	var api, err = systemTunableApi(c)
	if err != nil {
		return nil
	}
	var tunables, _, searchErr = systemTunableSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(tunables))
	for _, tunable := range tunables {
		names = append(names, tunable.Tunable)
	}
	return names
}

// --- output

// systemTunableTypeName explains the sysctl type letter
func systemTunableTypeName(sysctlType string) string {
	switch sysctlType {
	case "w":
		return "runtime"
	case "t":
		return "boot-time"
	case "r":
		return "read-only"
	default:
		return sysctlType
	}
}

// systemTunableSource tells whether the row is stored in the configuration
func systemTunableSource(tunable system.Tunable) string {
	switch {
	case tunable.IsBuiltin():
		return "built-in"
	case tunable.DefaultValue != "":
		return "override"
	default:
		return "custom"
	}
}

func systemTunableTruncate(text string, length int) string {
	var runes = []rune(text)
	if len(runes) <= length {
		return text
	}
	return string(runes[:length-3]) + "..."
}

// systemTunableFields are the fields of show and print detail
func systemTunableFields(tunable system.Tunable) [][2]string {
	var valueLabel = "value"
	if tunable.IsBuiltin() {
		valueLabel = "runtime-value"
	}
	return [][2]string{
		{"uuid", tunable.Uuid},
		{"name", tunable.Tunable},
		{valueLabel, tunable.Value},
		{"default", tunable.DefaultValue},
		{"type", systemTunableTypeName(tunable.Type)},
		{"source", systemTunableSource(tunable)},
		{"description", tunable.Description},
	}
}

func systemTunablePrint(c *Context, args *Args) error {
	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	var all, allRaw, searchErr = systemTunableSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var tunables []system.Tunable
	var raw []json.RawMessage
	var uuids []string
	for i, tunable := range all {
		if args.Bool("changed") && !tunable.IsChanged() {
			continue
		}
		tunables = append(tunables, tunable)
		raw = append(raw, allRaw[i])
		uuids = append(uuids, tunable.Uuid)
	}

	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(tunables))
		for i, tunable := range tunables {
			items[i] = systemTunableFields(tunable)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(tunables))
		for i, tunable := range tunables {
			rows[i] = []string{tunable.Tunable, tunable.Value, tunable.DefaultValue, systemTunableTypeName(tunable.Type),
				systemTunableSource(tunable), systemTunableTruncate(tunable.Description, 60)}
		}
		c.Items([]string{"NAME", "VALUE", "DEFAULT", "TYPE", "SOURCE", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func systemTunableShow(c *Context, args *Args) error {
	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	var tunable, selectErr = systemTunableSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemTunableFields(tunable))
	return nil
}

// --- changes

func systemTunableAdd(c *Context, args *Args) error {
	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var rows, findErr = api.TunableFindByName(name)
	if findErr != nil {
		return findErr
	}
	var configured []system.Tunable
	for _, row := range rows {
		if !row.IsBuiltin() {
			configured = append(configured, row)
		}
	}

	switch {
	case len(configured) == 0:
		var uuid, createErr = api.TunableCreate(system.Tunable{Tunable: name, Value: args.String("value"), Description: args.String("description")})
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case len(configured) > 1:
		var uuids = make([]string, len(configured))
		for i, tunable := range configured {
			uuids[i] = tunable.Uuid
		}
		sort.Strings(uuids)
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("tunable %s is configured %d times (%s), change or remove the duplicates with set or remove",
			name, len(configured), strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("tunable %s is configured already (%s), change it with set or replace it with add ... replace", name, configured[0].Uuid)
	}

	var existing = configured[0]
	var fields = system.TunableFields{"tunable": name, "value": args.String("value"), "descr": args.String("description")}
	if err := api.TunableUpdate(existing.Uuid, fields); err != nil {
		return err
	}
	c.Infof("replaced the existing tunable %s", name)
	c.Println(existing.Uuid)
	return nil
}

func systemTunableSet(c *Context, args *Args) error {
	var fields = system.TunableFields{}
	for arg, field := range map[string]string{"name": "tunable", "value": "value", "description": "descr"} {
		if args.Has(arg) {
			fields[field] = args.String(arg)
		}
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like value= or description= (type \"set ?\" for help)")
	}

	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	var tunable, selectErr = systemTunableSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}

	if !tunable.IsBuiltin() {
		return api.TunableUpdate(tunable.Uuid, fields)
	}

	// a built-in default which is not configured: store an override
	if args.Has("name") && args.String("name") != tunable.Tunable {
		return fmt.Errorf("%s is a built-in default and can not be renamed, use add name=%s to configure a new tunable",
			tunable.Tunable, args.String("name"))
	}
	if !args.Has("value") {
		return fmt.Errorf("%s is a built-in default which is not configured, give value= to override it", tunable.Tunable)
	}
	var uuid, createErr = api.TunableCreate(system.Tunable{Tunable: tunable.Tunable, Value: args.String("value"), Description: args.String("description")})
	if createErr != nil {
		return createErr
	}
	c.Infof("stored an override of the built-in default %s, uuid %s", tunable.Tunable, uuid)
	return nil
}

func systemTunableRemove(c *Context, args *Args) error {
	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	var tunable, selectErr = systemTunableSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if tunable.IsBuiltin() {
		return fmt.Errorf("%s is a built-in default which is not configured and can not be removed, use set %s value=... to override it",
			tunable.Tunable, tunable.Tunable)
	}
	if err := api.TunableRemove(tunable.Uuid); err != nil {
		return err
	}
	if tunable.DefaultValue != "" {
		c.Infof("the built-in default %s=%s applies again", tunable.Tunable, tunable.DefaultValue)
	}
	return nil
}

func systemTunableApply(c *Context, _ *Args) error {
	var api, err = systemTunableApi(c)
	if err != nil {
		return err
	}
	return api.TunableReconfigure()
}
