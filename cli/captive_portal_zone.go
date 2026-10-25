package cli

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

// /captive-portal/zone: the zones of Services > Captive Portal > Administration (api/captiveportal/settings).
// Items are selected by the # of print, the uuid or the description (the natural key of add). Interfaces,
// authentication servers, the group and the certificate are given by key or name and resolved with the option
// lists of get_zone, the template by its name.
//
// Zones are always added disabled: an enabled zone redirects every client on its interfaces to the portal (once
// applied, and its firewall rules are loaded with every filter reload), so enable asks for confirmation

const (
	captivePortalZoneItemHelp = "the #, uuid or description of the zone"
	captivePortalZoneEnable   = "An enabled zone redirects all clients on its interfaces to the login page (after the next reconfigure or filter reload); make sure you can still reach the firewall."
)

// how a zone argument maps to the API value
type captivePortalZoneKind int

const (
	captivePortalZonePlain    captivePortalZoneKind = iota
	captivePortalZoneFlag                           // yes/no as 1/0
	captivePortalZoneList                           // comma separated
	captivePortalZoneOption                         // option key(s) given by key or description
	captivePortalZoneTemplate                       // template uuid given by name
)

type captivePortalZoneField struct {
	Arg
	field string
	kind  captivePortalZoneKind
}

var captivePortalZoneServerNamePattern = regexp.MustCompile(`^[0-9a-zA-Z.,_\-]*$`)

// captivePortalZoneFields are the field arguments of add and set, in the order of show
func captivePortalZoneFields(add bool) []captivePortalZoneField {
	var required = func(arg Arg) Arg {
		arg.Required = add
		return arg
	}
	return []captivePortalZoneField{
		{required(Arg{Name: "description", Validate: captivePortalZoneValidateDescription,
			Help: "description, also the name of the zone"}), "description", captivePortalZonePlain},
		{required(Arg{Name: "interfaces", Type: List, Validate: captivePortalZoneValidateNotEmpty, Complete: captivePortalZoneOptionNames("interfaces"),
			Help: "interfaces (keys like opt2 or names) whose clients must log in; only enabled interfaces with a static address"}), "interfaces", captivePortalZoneOption},
		{Arg{Name: "auth-servers", Type: List, Complete: captivePortalZoneOptionNames("authservers"),
			Help: "authentication servers for the login, e.g. \"Local Database\" or a voucher server; empty: no login, only accept"}, "authservers", captivePortalZoneOption},
		{Arg{Name: "enforce-group", Complete: captivePortalZoneOptionNames("authEnforceGroup"),
			Help: "only members of this local group may log in, empty for all"}, "authEnforceGroup", captivePortalZoneOption},
		{Arg{Name: "idle-timeout", Type: Int, Validate: captivePortalZoneValidateMinutes,
			Help: "minutes without traffic until a client is logged off, 0 for never"}, "idletimeout", captivePortalZonePlain},
		{Arg{Name: "hard-timeout", Type: Int, Validate: captivePortalZoneValidateMinutes,
			Help: "minutes until a client is logged off anyway, 0 for never"}, "hardtimeout", captivePortalZonePlain},
		{Arg{Name: "concurrent-logins", Type: Bool, Help: "allow several logins of the same user"}, "concurrentlogins", captivePortalZoneFlag},
		{Arg{Name: "roaming", Type: Bool, Help: "keep the session when the client changes its address"}, "roaming", captivePortalZoneFlag},
		{Arg{Name: "disable-rules", Type: Bool, Help: "don't add the automatic firewall rules (write your own)"}, "disableRules", captivePortalZoneFlag},
		{Arg{Name: "always-send-accounting", Type: Bool, Help: "send accounting requests also for servers without accounting"},
			"alwaysSendAccountingReqs", captivePortalZoneFlag},
		{Arg{Name: "certificate", Complete: captivePortalZoneOptionNames("certificate"),
			Help: "certificate (its description) to serve the login page over https, empty for http"}, "certificate", captivePortalZoneOption},
		{Arg{Name: "server-name", Validate: captivePortalZoneValidateServerName,
			Help: "host name of the login page (should match the certificate), empty for the interface address"}, "servername", captivePortalZonePlain},
		{Arg{Name: "allowed-addresses", Type: List, Validate: captivePortalZoneValidateAddresses,
			Help: "addresses or networks that never have to log in"}, "allowedAddresses", captivePortalZoneList},
		{Arg{Name: "allowed-macs", Type: List, Validate: ValidateMACList,
			Help: "MAC addresses that never have to log in"}, "allowedMACAddresses", captivePortalZoneList},
		{Arg{Name: "extended-pre-auth-data", Type: Bool, Help: "pass more client data to the login page"}, "extendedPreAuthData", captivePortalZoneFlag},
		{Arg{Name: "template", Complete: captivePortalTemplateItemNames,
			Help: "custom login page (template name), empty for the default"}, "template", captivePortalZoneTemplate},
	}
}

func captivePortalZoneArgs(fields []captivePortalZoneField) []Arg {
	var args = make([]Arg, len(fields))
	for i, field := range fields {
		args[i] = field.Arg
	}
	return args
}

func init() {
	var menu = Root.Menu("captive-portal/zone")
	menu.Help = "captive portal zones: interfaces whose clients must log in (Services > Captive Portal > Administration)"
	var item = Arg{Name: "item", Help: captivePortalZoneItemHelp, Positional: true, Required: true, Complete: captivePortalZoneItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the zones", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every zone"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "search", Help: "only zones where any field contains this text"},
		}, Run: captivePortalZonePrint},
		&Command{Name: "show", Help: "show all fields of one zone", Args: []Arg{item}, Run: captivePortalZoneShow},
		&Command{Name: "add", Help: "add a disabled zone, prints its uuid",
			Long: `The zone is always added disabled, enable it with enable. Fields not given get the OPNsense defaults
(no timeouts, roaming, concurrent logins). The description names the zone: if it exists already, add fails unless
replace is given, then that zone is replaced completely (fields not given are reset to the defaults, its state is kept).

  add description=guests interfaces=opt2 auth-servers="Local Database" idle-timeout=30

` + captivePortalApplyHint,
			Args: append(captivePortalZoneArgs(captivePortalZoneFields(true)),
				Arg{Name: "replace", Type: Bool, Help: "replace the zone with the same description"}),
			Run: captivePortalZoneAdd},
		&Command{Name: "set", Help: "change fields of a zone, the others are kept",
			Long: `description= renames the zone, an empty value clears a list (e.g. allowed-macs=). Use enable / disable to
change its state.
` + captivePortalApplyHint,
			Args: append([]Arg{item}, captivePortalZoneArgs(captivePortalZoneFields(false))...),
			Run:  captivePortalZoneSet},
		&Command{Name: "remove", Help: "remove a zone", Long: "An active zone stays active until reconfigure.\n" + captivePortalApplyHint,
			Args: []Arg{item}, Run: captivePortalZoneRemove},
		&Command{Name: "enable", Help: "enable a zone", Long: captivePortalZoneEnable + "\n" + captivePortalApplyHint,
			Args: []Arg{item}, Confirm: captivePortalZoneEnable, Run: captivePortalZoneEnabler(true)},
		&Command{Name: "disable", Help: "disable a zone", Long: captivePortalApplyHint, Args: []Arg{item}, Run: captivePortalZoneEnabler(false)},
	)
}

// --- validation

func captivePortalZoneValidateDescription(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty, it names the zone")
	}
	return openvpnInstanceValidateText(value)
}

func captivePortalZoneValidateNotEmpty(value string) error {
	if len(splitList(value)) == 0 {
		return errors.New("must not be empty")
	}
	return nil
}

func captivePortalZoneValidateMinutes(value string) error {
	if value == "" {
		return errors.New("must not be empty, 0 means no timeout")
	}
	return ValidateRange(0, 10080)(value)
}

func captivePortalZoneValidateServerName(value string) error {
	if len(value) > 1024 || !captivePortalZoneServerNamePattern.MatchString(value) {
		return fmt.Errorf("must be a host name or address (letters, digits, . , _ -), got %q", value)
	}
	return nil
}

func captivePortalZoneValidateAddresses(value string) error {
	for _, element := range splitList(value) {
		if net.ParseIP(element) == nil {
			if _, _, err := net.ParseCIDR(element); err != nil {
				return fmt.Errorf("must be addresses or networks like 192.168.1.10 or 10.0.0.0/24, got %q", element)
			}
		}
	}
	return nil
}

// --- lookups

func captivePortalZoneSelect(c *Context, api *captiveportal.CaptivePortalApi, selector string) (captiveportal.Zone, []captiveportal.Zone, error) {
	var zones, err = api.ZoneList("")
	if err != nil {
		return captiveportal.Zone{}, nil, err
	}
	var zone, selectErr = Select(c, selector, zones, func(zone captiveportal.Zone) string { return zone.Uuid },
		func(zone captiveportal.Zone) []string { return []string{zone.Description} })
	return zone, zones, selectErr
}

func captivePortalZoneItemNames(c *Context) []string {
	var api, err = captivePortalApi(c)
	if err != nil {
		return nil
	}
	var zones, listErr = api.ZoneList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, zone := range zones {
		names = append(names, zone.Description)
	}
	return names
}

func captivePortalZoneOptionNames(field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = captivePortalApi(c)
		if err != nil {
			return nil
		}
		var options, optionsErr = api.ZoneOptions()
		if optionsErr != nil {
			return nil
		}
		var names []string
		for _, option := range options[field] {
			if option.Key != "" {
				names = append(names, option.Key)
			}
		}
		return names
	}
}

// captivePortalZoneFieldsOf returns the given field arguments as API fields, references resolved
func captivePortalZoneFieldsOf(api *captiveportal.CaptivePortalApi, args *Args, specs []captivePortalZoneField) (captiveportal.ZoneFields, error) {
	var fields = captiveportal.ZoneFields{}
	var options map[string][]captiveportal.Option
	var templates []captiveportal.Template
	for _, spec := range specs {
		if !args.Has(spec.Name) {
			continue
		}
		var value = strings.TrimSpace(args.String(spec.Name))
		switch spec.kind {
		case captivePortalZoneFlag:
			fields[spec.field] = Flag(args.Bool(spec.Name))
		case captivePortalZoneList:
			fields[spec.field] = strings.Join(args.List(spec.Name), ",")
		case captivePortalZoneOption:
			if options == nil {
				var err error
				if options, err = api.ZoneOptions(); err != nil {
					return nil, err
				}
			}
			var elements = []string{value}
			if spec.Type == List {
				elements = args.List(spec.Name)
			}
			var keys []string
			for _, element := range elements {
				var key, err = captivePortalResolveOption(options[spec.field], spec.Name, element)
				if err != nil {
					return nil, err
				}
				if key != "" {
					keys = append(keys, key)
				}
			}
			fields[spec.field] = strings.Join(keys, ",")
		case captivePortalZoneTemplate:
			var uuid string
			if value != "" {
				if templates == nil {
					var err error
					if templates, err = api.TemplateList(""); err != nil {
						return nil, err
					}
				}
				var template, err = captivePortalTemplateResolve(templates, value)
				if err != nil {
					return nil, err
				}
				uuid = template.Uuid
			}
			fields[spec.field] = uuid
		default:
			fields[spec.field] = value
		}
	}
	return fields, nil
}

// --- output

func captivePortalZoneDetail(zone captiveportal.Zone, options map[string][]captiveportal.Option, templates []captiveportal.Template) [][2]string {
	var template = zone.Template
	for _, candidate := range templates {
		if template != "" && candidate.Uuid == template {
			template = candidate.Name
		}
	}
	var interfaces = strings.ReplaceAll(zone.InterfaceNames, ", ", ",")
	if interfaces == "" {
		interfaces = zone.Interfaces
	}
	return [][2]string{
		{"uuid", zone.Uuid},
		{"description", zone.Description},
		{"disabled", YesNo(Flag(zone.Enabled == "0"))},
		{"zone-id", zone.ZoneId},
		{"interfaces", interfaces},
		{"auth-servers", zone.AuthServers},
		{"enforce-group", captivePortalOptionText(options["authEnforceGroup"], zone.AuthEnforceGroup)},
		{"idle-timeout", zone.IdleTimeout},
		{"hard-timeout", zone.HardTimeout},
		{"concurrent-logins", YesNo(zone.ConcurrentLogins)},
		{"roaming", YesNo(zone.Roaming)},
		{"disable-rules", YesNo(zone.DisableRules)},
		{"always-send-accounting", YesNo(zone.AlwaysSendAccountingReqs)},
		{"certificate", captivePortalOptionText(options["certificate"], zone.Certificate)},
		{"server-name", zone.ServerName},
		{"allowed-addresses", zone.AllowedAddresses},
		{"allowed-macs", zone.AllowedMACAddresses},
		{"extended-pre-auth-data", YesNo(zone.ExtendedPreAuthData)},
		{"template", template},
	}
}

func captivePortalZonePrint(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var raw, zones, listErr = api.ZoneListRaw(args.String("search"))
	if listErr != nil {
		return listErr
	}
	var uuids = make([]string, len(zones))
	for i, zone := range zones {
		uuids[i] = zone.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			if err := c.JSON(row); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var options, optionsErr = api.ZoneOptions()
		if optionsErr != nil {
			return optionsErr
		}
		var templates, templatesErr = api.TemplateList("")
		if templatesErr != nil {
			return templatesErr
		}
		var items = make([][][2]string, len(zones))
		for i, zone := range zones {
			items[i] = captivePortalZoneDetail(zone, options, templates)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(zones))
		for i, zone := range zones {
			rows[i] = []string{YesNo(Flag(zone.Enabled == "0")), zone.ZoneId, strings.ReplaceAll(zone.InterfaceNames, ", ", ","),
				zone.AuthServers, zone.IdleTimeout, zone.HardTimeout, zone.Description}
		}
		c.Items([]string{"DISABLED", "ZONE-ID", "INTERFACES", "AUTH-SERVERS", "IDLE-TIMEOUT", "HARD-TIMEOUT", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func captivePortalZoneShow(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var zone, _, selectErr = captivePortalZoneSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	options, err := api.ZoneOptions()
	if err != nil {
		return err
	}
	templates, err := api.TemplateList("")
	if err != nil {
		return err
	}
	c.Fields(captivePortalZoneDetail(zone, options, templates))
	return nil
}

// --- changes

// captivePortalZoneDefaults are the values of a new zone (model defaults), the base of add ... replace
var captivePortalZoneDefaults = captiveportal.ZoneFields{"disableRules": "0", "authservers": "", "roaming": "1",
	"alwaysSendAccountingReqs": "0", "authEnforceGroup": "", "idletimeout": "0", "hardtimeout": "0", "concurrentlogins": "1",
	"certificate": "", "servername": "", "allowedAddresses": "", "allowedMACAddresses": "", "extendedPreAuthData": "0", "template": ""}

// captivePortalZoneError names the fields of an OPNsense validation error by their argument names
func captivePortalZoneError(err error) error {
	return openvpnValidationArgs(err, "zone.", func(field string) string {
		for _, spec := range captivePortalZoneFields(false) {
			if spec.field == field {
				return spec.Name
			}
		}
		return ""
	})
}

func captivePortalZoneAdd(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = captivePortalZoneFieldsOf(api, args, captivePortalZoneFields(true))
	if fieldsErr != nil {
		return fieldsErr
	}
	var zones, listErr = api.ZoneList("")
	if listErr != nil {
		return listErr
	}
	var existing = coreapi.Filter(zones, func(zone captiveportal.Zone) bool {
		return strings.EqualFold(zone.Description, fields["description"])
	})
	switch {
	case len(existing) == 0:
		fields["enabled"] = "0"
		var uuid, createErr = api.ZoneCreate(fields)
		if createErr != nil {
			return captivePortalZoneError(createErr)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, zone := range existing {
			uuids[i] = zone.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d zones with description %q (%s), change or remove them with set or remove",
			len(existing), fields["description"], strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a zone with description %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Description, existing[0].Uuid)
	}

	var replacement = captiveportal.ZoneFields{}
	for name, value := range captivePortalZoneDefaults {
		replacement[name] = value
	}
	for name, value := range fields {
		replacement[name] = value
	}
	if err := api.ZoneUpdate(existing[0].Uuid, replacement); err != nil {
		return captivePortalZoneError(err)
	}
	c.Infof("replaced the existing zone %q", existing[0].Description)
	c.Println(existing[0].Uuid)
	return nil
}

func captivePortalZoneSet(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = captivePortalZoneFieldsOf(api, args, captivePortalZoneFields(false))
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like idle-timeout= or description= (type \"set ?\" for help)")
	}
	var zone, zones, selectErr = captivePortalZoneSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if description, renamed := fields["description"]; renamed {
		for _, other := range zones {
			if other.Uuid != zone.Uuid && strings.EqualFold(other.Description, description) {
				return fmt.Errorf("another zone with description %q exists already (%s)", description, other.Uuid)
			}
		}
	}
	return captivePortalZoneError(api.ZoneUpdate(zone.Uuid, fields))
}

func captivePortalZoneRemove(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var zone, _, selectErr = captivePortalZoneSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.ZoneRemove(zone.Uuid)
}

func captivePortalZoneEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = captivePortalApi(c)
		if err != nil {
			return err
		}
		var zone, _, selectErr = captivePortalZoneSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.ZoneSetEnabled(zone.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("zone %q is already %s", zone.Description, EnabledWord(enabled))
		}
		return nil
	}
}
