package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strings"
)

// A declarative settings menu (print, set) for the plain settings of the Dnsmasq and Unbound models

// dnsSettingsValues are flattened model settings; dnsmasq.Settings and unbound.Settings are the same type
type dnsSettingsValues = dnsmasq.Settings

// dnsSetting is one setting: its argument, API name (dotted, relative to what Get / Set use) and kind
type dnsSetting struct {
	Arg  Arg
	Api  string
	Kind dnsFieldKind // dnsText, dnsBool or dnsList (dnsDisabled is not used for settings)
	// Options: the values must be keys of the field's choices (see print options=), several with Kind dnsList
	Options bool
}

type dnsSettingsMenu struct {
	Path      string
	Help      string
	What      string // e.g. "general settings"
	SetLong   string
	ApplyHint string
	Settings  []dnsSetting
	Get       func(c *Context) (dnsSettingsValues, error)
	Set       func(c *Context, patch map[string]string) error
}

func (m *dnsSettingsMenu) optionArgs() []string {
	var names []string
	for _, setting := range m.Settings {
		if setting.Options {
			names = append(names, setting.Arg.Name)
		}
	}
	return names
}

func (m *dnsSettingsMenu) setting(arg string) *dnsSetting {
	for i := range m.Settings {
		if m.Settings[i].Arg.Name == arg {
			return &m.Settings[i]
		}
	}
	return nil
}

func (m *dnsSettingsMenu) register(extra ...*Command) *Menu {
	var menu = Root.Menu(m.Path)
	menu.Help = m.Help
	var printArgs = []Arg{{Name: "json", Type: Bool, Help: "print the settings as one JSON object with the API names"}}
	if options := m.optionArgs(); len(options) > 0 {
		printArgs = append([]Arg{{Name: "options", Help: "list the choices of this setting instead", Values: options}}, printArgs...)
	}
	var setArgs = make([]Arg, 0, len(m.Settings))
	for _, setting := range m.Settings {
		var arg = setting.Arg
		if setting.Options && arg.Complete == nil {
			arg.Complete = m.completeOptions(setting.Api)
		}
		setArgs = append(setArgs, arg)
	}
	menu.Add(
		&Command{Name: "print", Help: "show the " + m.What, Long: `Shows the settings named like the arguments of set. options=<setting> lists the choices of a setting
(key, name, selected) instead.`, Args: printArgs, Run: m.print},
		&Command{Name: "set", Help: "change " + m.What + ", the others are kept",
			Long: strings.TrimSpace(m.SetLong + "\n" + m.ApplyHint), Args: setArgs, Check: m.checkSet, Run: m.set},
	)
	menu.Add(extra...)
	return menu
}

func (m *dnsSettingsMenu) completeOptions(api string) func(c *Context) []string {
	return func(c *Context) []string {
		var settings, err = m.Get(c)
		if err != nil {
			return nil
		}
		var keys []string
		for _, option := range settings.Options[api] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

func (m *dnsSettingsMenu) display(setting dnsSetting, settings dnsSettingsValues) string {
	var value = settings.Values[setting.Api]
	if setting.Kind == dnsBool {
		return YesNo(value)
	}
	return value
}

func (m *dnsSettingsMenu) print(c *Context, args *Args) error {
	var settings, err = m.Get(c)
	if err != nil {
		return err
	}
	if args.Bool("json") && !m.hasOptionsArg(args) {
		var values = map[string]string{}
		for _, setting := range m.Settings {
			values[setting.Api] = settings.Values[setting.Api]
		}
		return c.JSON(values)
	}
	if m.hasOptionsArg(args) {
		var setting = m.setting(strings.ToLower(args.String("options")))
		var choices = settings.Options[setting.Api]
		if args.Bool("json") {
			for _, choice := range choices {
				if err := c.JSON(choice); err != nil {
					return err
				}
			}
			return nil
		}
		var rows [][]string
		for _, choice := range choices {
			var key = choice.Key
			if key == "" {
				key = `""`
			}
			rows = append(rows, []string{key, choice.Value, YesNo(Flag(choice.Selected))})
		}
		c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		return nil
	}
	var fields = make([][2]string, 0, len(m.Settings))
	for _, setting := range m.Settings {
		fields = append(fields, [2]string{setting.Arg.Name, m.display(setting, settings)})
	}
	c.Fields(fields)
	return nil
}

func (m *dnsSettingsMenu) hasOptionsArg(args *Args) bool {
	return len(m.optionArgs()) > 0 && args.Has("options")
}

func (m *dnsSettingsMenu) checkSet(args *Args) error {
	for _, setting := range m.Settings {
		if args.Has(setting.Arg.Name) {
			return nil
		}
	}
	return errors.New("set: nothing to change, give at least one setting (type \"set ?\" for help)")
}

func (m *dnsSettingsMenu) set(c *Context, args *Args) error {
	var given []dnsSetting
	var needOptions bool
	for _, setting := range m.Settings {
		if args.Has(setting.Arg.Name) {
			given = append(given, setting)
			needOptions = needOptions || setting.Options
		}
	}
	// the choices of option fields (interfaces, ...) depend on the firewall: load them to validate the values
	var current dnsSettingsValues
	if needOptions {
		var err error
		if current, err = m.Get(c); err != nil {
			return err
		}
	}
	var patch = map[string]string{}
	for _, setting := range given {
		var value = strings.TrimSpace(args.String(setting.Arg.Name))
		switch {
		case setting.Kind == dnsBool:
			value = Flag(args.Bool(setting.Arg.Name))
		case setting.Options:
			var normalized, err = dnsSettingsOptionValue(current.Options[setting.Api], value, setting.Kind == dnsList)
			if err != nil {
				return fmt.Errorf("%s: %w", setting.Arg.Name, err)
			}
			value = normalized
		case setting.Kind == dnsList:
			value = strings.Join(args.List(setting.Arg.Name), ",")
		default:
			value = dnsCanonicalValue(setting.Arg.Values, value)
		}
		patch[setting.Api] = value
	}
	return m.Set(c, patch)
}

// dnsSettingsOptionValue checks the comma separated keys against the choices (case-insensitive) and returns them
// as OPNsense spells them, "" for none
func dnsSettingsOptionValue(choices []dnsmasq.SettingsOption, value string, multiple bool) (string, error) {
	var keys = splitList(value)
	if !multiple && len(keys) > 1 {
		return "", fmt.Errorf("takes one value, got %q", value)
	}
	var result = make([]string, 0, len(keys))
	for _, key := range keys {
		var found = false
		for _, choice := range choices {
			if choice.Key != "" && strings.EqualFold(choice.Key, key) {
				result = append(result, choice.Key)
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
			return "", fmt.Errorf("unknown value %q, must be one of %s", key, strings.Join(valid, ", "))
		}
	}
	return strings.Join(result, ","), nil
}
