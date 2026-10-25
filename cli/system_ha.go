package cli

import (
	"errors"
	"fmt"
	"net"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/ha: System > High Availability. print/set/apply are the settings (pfsync and the XMLRPC sync to the
// backup node), status asks the backup node for its version, sync pushes the configuration to it and restarts its
// services. The services of the backup node are in /system/ha/service. The XMLRPC password is never printed

const systemHaSyncWarning = "This pushes the configuration of the selected sync items to the backup node and " +
	"restarts all its services."

// systemHaField maps a kebab-case argument to its API field
type systemHaField struct {
	arg    string
	api    string
	kind   string // "bool", "text", "option" (one key), "options" (comma separated keys)
	value  func(s system.HaSyncSettings) string
	target func(p *system.HaSyncSettingsPatch) **string
}

var systemHaFields = []systemHaField{
	{"disable-preempt", "disablepreempt", "bool",
		func(s system.HaSyncSettings) string { return s.DisablePreempt },
		func(p *system.HaSyncSettingsPatch) **string { return &p.DisablePreempt }},
	{"disconnect-ppps", "disconnectppps", "bool",
		func(s system.HaSyncSettings) string { return s.DisconnectPpps },
		func(p *system.HaSyncSettingsPatch) **string { return &p.DisconnectPpps }},
	{"pfsync-interface", "pfsyncinterface", "option",
		func(s system.HaSyncSettings) string { return s.PfsyncInterface },
		func(p *system.HaSyncSettingsPatch) **string { return &p.PfsyncInterface }},
	{"pfsync-peer-ip", "pfsyncpeerip", "text",
		func(s system.HaSyncSettings) string { return s.PfsyncPeerIp },
		func(p *system.HaSyncSettingsPatch) **string { return &p.PfsyncPeerIp }},
	{"pfsync-version", "pfsyncversion", "option",
		func(s system.HaSyncSettings) string { return s.PfsyncVersion },
		func(p *system.HaSyncSettingsPatch) **string { return &p.PfsyncVersion }},
	{"pfsync-defer", "pfsyncdefer", "bool",
		func(s system.HaSyncSettings) string { return s.PfsyncDefer },
		func(p *system.HaSyncSettingsPatch) **string { return &p.PfsyncDefer }},
	{"synchronize-to-ip", "synchronizetoip", "text",
		func(s system.HaSyncSettings) string { return s.SynchronizeToIp },
		func(p *system.HaSyncSettingsPatch) **string { return &p.SynchronizeToIp }},
	{"verify-peer", "verifypeer", "bool",
		func(s system.HaSyncSettings) string { return s.VerifyPeer },
		func(p *system.HaSyncSettingsPatch) **string { return &p.VerifyPeer }},
	{"username", "username", "text",
		func(s system.HaSyncSettings) string { return s.Username },
		func(p *system.HaSyncSettingsPatch) **string { return &p.Username }},
	{"password", "password", "text",
		func(s system.HaSyncSettings) string { return systemFirmwareSettingsMasked(s.Password) },
		func(p *system.HaSyncSettingsPatch) **string { return &p.Password }},
	{"sync-items", "syncitems", "options",
		func(s system.HaSyncSettings) string { return s.SyncItems },
		func(p *system.HaSyncSettingsPatch) **string { return &p.SyncItems }},
}

func init() {
	var menu = Root.Menu("system/ha")
	menu.Help = "high availability: pfsync, configuration sync to the backup node (System > High Availability)"
	menu.Add(
		&Command{Name: "print", Help: "show the HA settings",
			Long: `options lists the choices of pfsync-interface, pfsync-version or sync-items instead (key, name, selected).
The password is shown as (set).`,
			Args: []Arg{
				{Name: "options", Help: "list the choices of this setting", Values: []string{"pfsync-interface", "pfsync-version", "sync-items"}},
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object (password masked)"},
			},
			Run: systemHaPrint},
		&Command{Name: "set", Help: "change HA settings, the others are kept",
			Long: `pfsync-interface= takes an interface key ("" disables pfsync), sync-items= a comma separated list of
the keys of "print options=sync-items" ("" syncs nothing). synchronize-to-ip is the address (or URL) of the
backup node, username and password its XMLRPC login. pfsync changes take effect with apply.

  set pfsync-interface=opt2 pfsync-peer-ip=10.99.0.2
  set synchronize-to-ip=10.99.0.2 username=root password=secret sync-items=aliases,rules,nat`,
			Args: []Arg{
				{Name: "disable-preempt", Type: Bool, Help: "do not let a CARP master give up its role to a higher priority node"},
				{Name: "disconnect-ppps", Type: Bool, Help: "disconnect dialup interfaces of a CARP backup"},
				{Name: "pfsync-interface", Help: `the interface to sync the states over, "" disables pfsync`,
					Complete: systemHaComplete("pfsyncinterface")},
				{Name: "pfsync-peer-ip", Help: `the pfsync peer (unicast), "" for multicast`, Validate: systemHaValidateIp},
				{Name: "pfsync-version", Help: "the pfsync protocol version (both nodes must use the same)",
					Complete: systemHaComplete("pfsyncversion")},
				{Name: "pfsync-defer", Type: Bool, Help: "defer packets until the peer acknowledged the state"},
				{Name: "synchronize-to-ip", Help: `address or URL of the backup node, "" disables the configuration sync`},
				{Name: "verify-peer", Type: Bool, Help: "verify the TLS certificate of the backup node"},
				{Name: "username", Help: "XMLRPC user on the backup node"},
				{Name: "password", Help: "XMLRPC password on the backup node"},
				{Name: "sync-items", Type: List, Help: "what to sync, keys of print options=sync-items",
					Complete: systemHaComplete("syncitems")},
			},
			Check: systemHaCheckSet,
			Run:   systemHaSet},
		&Command{Name: "apply", Help: "apply the pfsync settings (configures pfsync0 and the CARP preemption)",
			Run: systemHaApply},
		&Command{Name: "status", Help: "ask the backup node for its versions",
			Long: `Shows whether the backup node (synchronize-to-ip) answers and its firmware, base and kernel versions;
both nodes should run the same version.`,
			Run: systemHaStatus},
		&Command{Name: "sync", Help: "push the configuration to the backup node and restart its services",
			Confirm: systemHaSyncWarning, Run: systemHaSync},
	)
}

func systemHaValidateIp(value string) error {
	if value != "" && net.ParseIP(value) == nil {
		return fmt.Errorf("must be an IP address or empty, got %q", value)
	}
	return nil
}

func systemHaFieldByArg(arg string) *systemHaField {
	for i := range systemHaFields {
		if systemHaFields[i].arg == arg {
			return &systemHaFields[i]
		}
	}
	return nil
}

func systemHaComplete(apiName string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = systemServiceApi(c)
		if err != nil {
			return nil
		}
		var settings, getErr = api.HaSyncSettingsGet()
		if getErr != nil {
			return nil
		}
		var keys []string
		for _, option := range settings.Options[apiName] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

func systemHaPrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var settings, getErr = api.HaSyncSettingsGet()
	if getErr != nil {
		return getErr
	}
	if args.Has("options") {
		var field = systemHaFieldByArg(strings.ToLower(args.String("options")))
		var options = settings.Options[field.api]
		if args.Bool("json") {
			for _, option := range options {
				if err := c.JSON(map[string]any{"key": option.Key, "name": option.Name, "selected": option.Selected}); err != nil {
					return err
				}
			}
			return nil
		}
		var rows = make([][]string, len(options))
		for i, option := range options {
			var key = option.Key
			if key == "" {
				key = `""`
			}
			rows[i] = []string{key, option.Name, YesNo(Flag(option.Selected))}
		}
		c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		return nil
	}
	if args.Bool("json") {
		var object = map[string]string{}
		for _, field := range systemHaFields {
			object[field.api] = field.value(settings)
		}
		return c.JSON(object)
	}
	var fields = make([][2]string, 0, len(systemHaFields))
	for _, field := range systemHaFields {
		var value = field.value(settings)
		switch {
		case field.kind == "bool":
			value = YesNo(value)
		case field.arg == "pfsync-interface" && value == "":
			value = "(disabled)"
		}
		fields = append(fields, [2]string{field.arg, value})
	}
	c.Fields(fields)
	return nil
}

func systemHaCheckSet(args *Args) error {
	for _, field := range systemHaFields {
		if args.Has(field.arg) {
			return nil
		}
	}
	return errors.New(`set: nothing to change, give at least one setting (type "set ?" for help)`)
}

func systemHaSet(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var current system.HaSyncSettings
	var loaded = false
	var patch system.HaSyncSettingsPatch
	for _, field := range systemHaFields {
		if !args.Has(field.arg) {
			continue
		}
		var value string
		switch field.kind {
		case "bool":
			value = Flag(args.Bool(field.arg))
		case "text":
			value = strings.TrimSpace(args.String(field.arg))
			if field.arg == "password" {
				value = args.String(field.arg)
			}
		default:
			// the choices depend on the firewall (interfaces, release, installed plugins): validate against them
			if !loaded {
				if current, err = api.HaSyncSettingsGet(); err != nil {
					return err
				}
				loaded = true
			}
			var normalized, valueErr = systemHaOptionValue(current.Options[field.api], args.String(field.arg), field.kind == "option")
			if valueErr != nil {
				return fmt.Errorf("%s: %w", field.arg, valueErr)
			}
			value = normalized
		}
		*field.target(&patch) = &value
	}
	return api.HaSyncSettingsUpdate(patch)
}

// systemHaOptionValue checks the comma separated keys against the choices (case-insensitive) and returns them as
// OPNsense spells them. single allows one key ("" when the choices have an empty key, e.g. pfsync disabled)
func systemHaOptionValue(choices []system.HaSyncOption, value string, single bool) (string, error) {
	var keys = splitList(value)
	if single {
		if len(keys) > 1 {
			return "", fmt.Errorf("takes one value, got %q", value)
		}
		if len(keys) == 0 {
			for _, choice := range choices {
				if choice.Key == "" {
					return "", nil
				}
			}
			return "", errors.New("must not be empty")
		}
	}
	var result = make([]string, 0, len(keys))
	for _, key := range keys {
		var found = ""
		for _, choice := range choices {
			if choice.Key != "" && strings.EqualFold(choice.Key, key) {
				found = choice.Key
			}
		}
		if found == "" {
			var known = make([]string, 0, len(choices))
			for _, choice := range choices {
				if choice.Key != "" {
					known = append(known, choice.Key)
				}
			}
			return "", fmt.Errorf("unknown value %q, one of %s", key, strings.Join(known, ", "))
		}
		result = append(result, found)
	}
	return strings.Join(result, ","), nil
}

func systemHaApply(c *Context, _ *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	return api.HaSyncReconfigure()
}

func systemHaStatus(c *Context, _ *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var version, versionErr = api.HaPeerVersionGet()
	if versionErr != nil {
		return versionErr
	}
	if !version.Reachable {
		c.Fields([][2]string{{"peer", "unreachable"}, {"message", version.Message}})
		return nil
	}
	c.Fields([][2]string{
		{"peer", "reachable"},
		{"firmware", version.Firmware},
		{"base", version.Base},
		{"kernel", version.Kernel},
		{"local-firmware", version.Local},
	})
	if version.Local != "" && version.Local != version.Firmware {
		c.Infof("warning: the backup node runs %s, this firewall %s: update them to the same version", version.Firmware, version.Local)
	}
	return nil
}

func systemHaSync(c *Context, _ *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var count, syncErr = api.HaSync()
	if syncErr != nil {
		return syncErr
	}
	if count > 0 {
		c.Infof("configuration pushed, %d services restarted on the backup node", count)
	}
	return nil
}
