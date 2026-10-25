package cli

import (
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/logging/destination: remote syslog targets. Items are selected by the # of print, the uuid or the
// description (exact, case-insensitive)

func init() {
	var menu = Root.Menu("system/logging/destination")
	menu.Help = "remote logging destinations (send logs to a remote syslog server)"
	var item = Arg{Name: "item", Positional: true, Required: true, Help: "the #, uuid or description of the destination",
		Complete: systemLoggingDestinationComplete}
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the remote logging destinations",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every destination"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only destinations where any field contains this text"},
			},
			Run: systemLoggingDestinationPrint,
		},
		&Command{
			Name: "show",
			Help: "show all fields of one remote logging destination",
			Args: []Arg{item},
			Run:  systemLoggingDestinationShow,
		},
		&Command{
			Name: "add",
			Help: "add a remote logging destination, prints its uuid",
			Long: `A destination with the same description must not exist, unless replace is given: then that destination
is replaced completely (fields not given get their defaults). Use a unique description to be able to select
the destination by it later. ` + systemLoggingApplyHint,
			Args: append(systemLoggingDestinationArgs(true),
				Arg{Name: "replace", Type: Bool, Help: "replace the destination with the same description instead of failing"}),
			Run: systemLoggingDestinationAdd,
		},
		&Command{
			Name: "set",
			Help: "change fields of a remote logging destination, the others are kept",
			Long: `An empty value clears a list (level=""). description= renames the destination.
` + systemLoggingApplyHint,
			Args: append([]Arg{item}, systemLoggingDestinationArgs(false)...),
			Run:  systemLoggingDestinationSet,
		},
		&Command{
			Name: "remove",
			Help: "remove a remote logging destination",
			Long: systemLoggingApplyHint,
			Args: []Arg{item},
			Run:  systemLoggingDestinationRemove,
		},
		&Command{
			Name: "enable",
			Help: "enable a remote logging destination",
			Long: systemLoggingApplyHint,
			Args: []Arg{item},
			Run:  systemLoggingDestinationToggle(true),
		},
		&Command{
			Name: "disable",
			Help: "disable a remote logging destination",
			Long: systemLoggingApplyHint,
			Args: []Arg{item},
			Run:  systemLoggingDestinationToggle(false),
		},
	)
}

// systemLoggingDestinationArgs are the field arguments of add (with defaults) and set
func systemLoggingDestinationArgs(add bool) []Arg {
	var defaultDisabled, defaultTransport, defaultPort = "", "", ""
	if add {
		defaultDisabled, defaultTransport, defaultPort = "no", "udp4", "514"
	}
	var hostname = Arg{Name: "hostname", Help: "IP address or hostname of the remote syslog server",
		Validate: systemLoggingRequired(nil)}
	hostname.Required = add
	return []Arg{
		{Name: "disabled", Type: Bool, Default: defaultDisabled, Help: "don't send logs to this destination"},
		{Name: "transport", Default: defaultTransport, Values: system.LoggingTransports,
			Help: "transport protocol, must match the address family of hostname", Validate: systemLoggingRequired(nil)},
		hostname,
		{Name: "port", Type: Int, Default: defaultPort, Help: "port of the remote syslog server", Validate: systemLoggingRequired(ValidatePort)},
		{Name: "program", Type: List, Help: `applications to send, like filterlog,unbound, "" for all`},
		{Name: "level", Type: List, Values: system.LoggingLevels, Help: `levels to send (` + strings.Join(system.LoggingLevels, ", ") + `), "" for all`},
		{Name: "facility", Type: List, Values: system.LoggingFacilities, Help: `facilities to send (kern, user, daemon, auth, local0..local7, ...), "" for all`},
		{Name: "certificate", Help: "refid of the client certificate, required for tls4 / tls6"},
		{Name: "rfc5424", Type: Bool, Help: "send messages in RFC 5424 format instead of RFC 3164 (BSD)"},
		{Name: "description", Help: "description, used to select the destination"},
	}
}

// systemLoggingDestinationFields returns the given (set) or all (add, with defaults) field arguments as API values
func systemLoggingDestinationFields(args *Args, all bool) system.LoggingDestinationFields {
	var value = func(name string, convert func(string) string) *string {
		if !all && !args.Has(name) {
			return nil
		}
		var v = convert(args.String(name))
		return &v
	}
	var trim = strings.TrimSpace
	var lower = func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	var list = func(convert func(string) string) func(string) string {
		return func(v string) string {
			var elements = splitList(v)
			for i := range elements {
				elements[i] = convert(elements[i])
			}
			return strings.Join(elements, ",")
		}
	}
	var flag = func(v string) string {
		var b, _ = parseBool(v)
		return Flag(b)
	}
	var notFlag = func(v string) string {
		var b, _ = parseBool(v)
		return Flag(!b)
	}
	return system.LoggingDestinationFields{
		Enabled:     value("disabled", notFlag),
		Transport:   value("transport", lower),
		Hostname:    value("hostname", trim),
		Port:        value("port", trim),
		Program:     value("program", list(trim)),
		Level:       value("level", list(lower)),
		Facility:    value("facility", list(lower)),
		Certificate: value("certificate", trim),
		Rfc5424:     value("rfc5424", flag),
		Description: value("description", func(v string) string { return v }),
	}
}

// systemLoggingDestinations lists all destinations in API order
func systemLoggingDestinations(c *Context) (*system.SystemApi, []system.LoggingDestination, error) {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return nil, nil, err
	}
	var destinations, listErr = api.LoggingDestinationList("")
	return api, destinations, listErr
}

// systemLoggingDestinationSelect resolves the item argument to a destination
func systemLoggingDestinationSelect(c *Context, args *Args) (*system.SystemApi, system.LoggingDestination, error) {
	var api, destinations, err = systemLoggingDestinations(c)
	if err != nil {
		return nil, system.LoggingDestination{}, err
	}
	var destination, selectErr = Select(c, args.String("item"), destinations,
		func(d system.LoggingDestination) string { return d.Uuid },
		func(d system.LoggingDestination) []string { return []string{d.Description} })
	return api, destination, selectErr
}

func systemLoggingDestinationComplete(c *Context) []string {
	var _, destinations, err = systemLoggingDestinations(c)
	if err != nil {
		return nil
	}
	var names []string
	for _, d := range destinations {
		if d.Description != "" { // the completion quotes descriptions with spaces
			names = append(names, d.Description)
		}
	}
	return names
}

// systemLoggingDisabled renders the "1"/"0" enabled flag of the API as the disabled yes/no of the CLI
func systemLoggingDisabled(enabled string) string {
	switch enabled {
	case "1":
		return "no"
	case "0":
		return "yes"
	}
	return enabled
}

func systemLoggingDestinationDetail(d system.LoggingDestination) [][2]string {
	return [][2]string{
		{"uuid", d.Uuid},
		{"disabled", systemLoggingDisabled(d.Enabled)},
		{"transport", d.Transport},
		{"hostname", d.Hostname},
		{"port", d.Port},
		{"program", d.Program},
		{"level", d.Level},
		{"facility", d.Facility},
		{"certificate", d.Certificate},
		{"rfc5424", YesNo(d.Rfc5424)},
		{"description", d.Description},
	}
}

func systemLoggingDestinationPrint(c *Context, args *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	var search = args.String("search")
	if args.Bool("json") {
		var endpoint = api.EndpointForPluginControllerMethod("syslog", "settings", "search_destinations")
		var rows, searchErr = coreapi.Search[map[string]any](api.OPNsense, endpoint, search)
		if searchErr != nil {
			return searchErr
		}
		for _, row := range rows {
			if err := c.JSON(row); err != nil {
				return err
			}
		}
		return nil
	}

	var destinations, listErr = api.LoggingDestinationList(search)
	if listErr != nil {
		return listErr
	}
	var uuids = make([]string, 0, len(destinations))
	for _, d := range destinations {
		uuids = append(uuids, d.Uuid)
	}
	if args.Bool("detail") {
		var items = make([][][2]string, 0, len(destinations))
		for _, d := range destinations {
			items = append(items, systemLoggingDestinationDetail(d))
		}
		c.Details(items, uuids)
		return nil
	}
	var rows = make([][]string, 0, len(destinations))
	for _, d := range destinations {
		rows = append(rows, []string{systemLoggingDisabled(d.Enabled), d.Transport, d.Hostname, d.Port, d.Program, d.Level, d.Facility, d.Description})
	}
	c.Items([]string{"DISABLED", "TRANSPORT", "HOSTNAME", "PORT", "PROGRAM", "LEVEL", "FACILITY", "DESCRIPTION"}, rows, uuids)
	return nil
}

func systemLoggingDestinationShow(c *Context, args *Args) error {
	var _, destination, err = systemLoggingDestinationSelect(c, args)
	if err != nil {
		return err
	}
	c.Fields(systemLoggingDestinationDetail(destination))
	return nil
}

func systemLoggingDestinationAdd(c *Context, args *Args) error {
	var fields = systemLoggingDestinationFields(args, true)
	var api, destinations, err = systemLoggingDestinations(c)
	if err != nil {
		return err
	}

	// the description is the natural key: an existing one is replaced with replace, else it's an error
	var description = *fields.Description
	var existing []system.LoggingDestination
	if strings.TrimSpace(description) != "" {
		existing = coreapi.Filter(destinations, func(d system.LoggingDestination) bool {
			return strings.EqualFold(strings.TrimSpace(d.Description), strings.TrimSpace(description))
		})
	}
	var uuids = make([]string, 0, len(existing))
	for _, d := range existing {
		uuids = append(uuids, d.Uuid)
	}
	switch {
	case len(existing) > 0 && !args.Bool("replace"):
		return fmt.Errorf("a destination with description %q exists already (%s), change it with set or replace it with add ... replace",
			description, strings.Join(uuids, ", "))
	case len(existing) > 1:
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("logging destination with description %q, %d candidates: %s, cannot replace",
			description, len(existing), strings.Join(uuids, ", "))}
	case len(existing) == 1:
		if err := api.LoggingDestinationUpdate(existing[0].Uuid, fields); err != nil {
			return err
		}
		c.Infof("replaced the existing destination %q", existing[0].Description)
		c.Println(existing[0].Uuid)
		return nil
	}

	var uuid, createErr = api.LoggingDestinationCreate(system.LoggingDestination{
		Enabled:     *fields.Enabled,
		Transport:   *fields.Transport,
		Hostname:    *fields.Hostname,
		Port:        *fields.Port,
		Program:     *fields.Program,
		Level:       *fields.Level,
		Facility:    *fields.Facility,
		Certificate: *fields.Certificate,
		Rfc5424:     *fields.Rfc5424,
		Description: *fields.Description,
	})
	if createErr != nil {
		return createErr
	}
	c.Println(uuid)
	return nil
}

func systemLoggingDestinationSet(c *Context, args *Args) error {
	var fields = systemLoggingDestinationFields(args, false)
	if fields == (system.LoggingDestinationFields{}) {
		return fmt.Errorf("set: nothing to change, give at least one field like port= or description= (type \"set ?\" for help)")
	}
	var api, destination, err = systemLoggingDestinationSelect(c, args)
	if err != nil {
		return err
	}
	return api.LoggingDestinationUpdate(destination.Uuid, fields)
}

func systemLoggingDestinationRemove(c *Context, args *Args) error {
	var api, destination, err = systemLoggingDestinationSelect(c, args)
	if err != nil {
		return err
	}
	return api.LoggingDestinationRemove(destination.Uuid)
}

func systemLoggingDestinationToggle(enable bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, destination, err = systemLoggingDestinationSelect(c, args)
		if err != nil {
			return err
		}
		var changed, toggleErr = api.LoggingDestinationSetEnabled(destination.Uuid, enable)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("destination %s is already %s", systemLoggingDestinationName(destination), EnabledWord(enable))
		}
		return nil
	}
}

// systemLoggingDestinationName names a destination in messages: its description, else its uuid
func systemLoggingDestinationName(destination system.LoggingDestination) string {
	if strings.TrimSpace(destination.Description) != "" {
		return fmt.Sprintf("%q", destination.Description)
	}
	return destination.Uuid
}
