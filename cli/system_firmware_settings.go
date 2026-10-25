package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/firmware/settings: mirror, flavour and release type of System > Firmware > Settings. Changes take effect
// with the next check or update; the subscription key is never printed

func init() {
	var menu = Root.Menu("system/firmware/settings")
	menu.Help = "package mirror, flavour and release type (System > Firmware > Settings)"
	menu.Add(
		&Command{Name: "print", Help: "show the firmware settings",
			Long: `options lists the known choices of mirror, flavour or type (key, name and whether it needs a subscription)
instead. mirror and flavour also take custom values.`,
			Args: []Arg{
				{Name: "options", Help: "list the choices of this setting", Values: []string{"mirror", "flavour", "type"}},
				{Name: "json", Type: Bool, Help: "print the settings (or the choices) as JSON"},
			},
			Run: systemFirmwareSettingsPrint},
		&Command{Name: "set", Help: "change firmware settings, the others are kept",
			Long: `mirror= and flavour= take a key of "print options=mirror|flavour" or a custom value, "" is the
default. type= is "" (community), devel or business. The settings take effect with the next check or update, a
different type or flavour can mean a big update that reboots.

  set mirror=https://mirror.ams1.nl.leaseweb.net/opnsense
  set type=devel`,
			Args: []Arg{
				{Name: "mirror", Help: `the package mirror URL, "" for the default`, Validate: systemFirmwareSettingsValidateText,
					Complete: systemFirmwareSettingsComplete("mirror")},
				{Name: "flavour", Help: `the package flavour, "" for the default`, Validate: systemFirmwareSettingsValidateText,
					Complete: systemFirmwareSettingsComplete("flavour")},
				{Name: "type", Help: `the release type: "" (community), devel or business`, Validate: systemFirmwareSettingsValidateText,
					Complete: systemFirmwareSettingsComplete("type")},
				{Name: "subscription", Help: "the subscription key (business edition)", Validate: systemFirmwareSettingsValidateText},
				{Name: "reboot", Type: Bool, Help: "always reboot after a successful update"},
				{Name: "aux", Type: Bool, Help: "activate the auxiliary packages repository"},
			},
			Check: systemFirmwareSettingsCheckSet,
			Run:   systemFirmwareSettingsSet},
	)
}

func systemFirmwareSettingsValidateText(value string) error {
	if strings.ContainsAny(value, "|\"\n\r") {
		return errors.New(`must not contain | " or line breaks`)
	}
	return nil
}

func systemFirmwareSettingsCheckSet(args *Args) error {
	for _, name := range []string{"mirror", "flavour", "type", "subscription", "reboot", "aux"} {
		if args.Has(name) {
			return nil
		}
	}
	return errors.New(`set: nothing to change, give at least one setting (type "set ?" for help)`)
}

func systemFirmwareSettingsChoices(options system.FirmwareOptions, setting string) []system.FirmwareOption {
	switch setting {
	case "mirror":
		return options.Mirrors
	case "flavour":
		return options.Flavours
	}
	return options.Types
}

func systemFirmwareSettingsComplete(setting string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = systemServiceApi(c)
		if err != nil {
			return nil
		}
		var options, optionsErr = api.FirmwareOptions()
		if optionsErr != nil {
			return nil
		}
		var keys []string
		for _, option := range systemFirmwareSettingsChoices(options, setting) {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

// systemFirmwareSettingsMasked shows whether a secret is set without showing it
func systemFirmwareSettingsMasked(secret string) string {
	if secret == "" {
		return ""
	}
	return "(set)"
}

func systemFirmwareSettingsPrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	if args.Has("options") {
		var options, optionsErr = api.FirmwareOptions()
		if optionsErr != nil {
			return optionsErr
		}
		var choices = systemFirmwareSettingsChoices(options, strings.ToLower(args.String("options")))
		if args.Bool("json") {
			for _, option := range choices {
				if err := c.JSON(map[string]any{"key": option.Key, "name": option.Name, "subscription": option.Subscription}); err != nil {
					return err
				}
			}
			return nil
		}
		var rows = make([][]string, len(choices))
		for i, option := range choices {
			var key = option.Key
			if key == "" {
				key = `""`
			}
			rows[i] = []string{key, option.Name, YesNo(Flag(option.Subscription))}
		}
		c.Table([]string{"KEY", "NAME", "SUBSCRIPTION"}, rows)
		return nil
	}

	var settings, getErr = api.FirmwareSettings()
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		return c.JSON(map[string]any{
			"mirror": settings.Mirror, "flavour": settings.Flavour, "type": settings.Type,
			"subscription": systemFirmwareSettingsMasked(settings.Subscription), "reboot": settings.Reboot,
			"aux": settings.Aux, "plugins": settings.Plugins,
		})
	}
	var orDefault = func(value string) string {
		if value == "" {
			return "(default)"
		}
		return value
	}
	var typeName = settings.Type
	if typeName == "" {
		typeName = "(community)"
	}
	c.Fields([][2]string{
		{"mirror", orDefault(settings.Mirror)},
		{"flavour", orDefault(settings.Flavour)},
		{"type", typeName},
		{"subscription", systemFirmwareSettingsMasked(settings.Subscription)},
		{"reboot", YesNo(settings.Reboot)},
		{"aux", YesNo(settings.Aux)},
		{"plugins", settings.Plugins},
	})
	return nil
}

func systemFirmwareSettingsSet(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var patch system.FirmwareSettingsPatch
	var text = func(name string) *string {
		if !args.Has(name) {
			return nil
		}
		var value = strings.TrimSpace(args.String(name))
		return &value
	}
	patch.Mirror, patch.Flavour, patch.Type, patch.Subscription = text("mirror"), text("flavour"), text("type"), text("subscription")
	if patch.Type != nil {
		// the release types are fixed, check them against the list
		var options, optionsErr = api.FirmwareOptions()
		if optionsErr != nil {
			return optionsErr
		}
		var known []string
		var found = false
		for _, option := range options.Types {
			known = append(known, fmt.Sprintf("%q", option.Key))
			if strings.EqualFold(option.Key, *patch.Type) {
				*patch.Type = option.Key
				found = true
			}
		}
		if !found {
			return fmt.Errorf("type must be one of %s, got %q", strings.Join(known, ", "), *patch.Type)
		}
	}
	for name, target := range map[string]**bool{"reboot": &patch.Reboot, "aux": &patch.Aux} {
		if args.Has(name) {
			var value = args.Bool(name)
			*target = &value
		}
	}
	if err := api.FirmwareSettingsUpdate(patch); err != nil {
		return err
	}
	c.Infof(`saved, the settings take effect with the next "/system/firmware check" or update`)
	return nil
}
