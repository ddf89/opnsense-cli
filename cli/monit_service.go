package cli

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"opnsense-cli/opnsense/api/monit"
	"regexp"
	"strings"
)

// /monit/service: the monitored services, /monit/test: the service tests, /monit/alert: the alert recipients
// (Monit > Settings). Services and tests are selected by the # of print, the uuid or the name, alerts by the #,
// the uuid, the recipient or the description

func init() {
	idsMonitRegister(monitServiceRecords)
	idsMonitRegister(monitTestRecords)
	idsMonitRegister(monitAlertRecords)
}

var monitServiceNamePattern = regexp.MustCompile(`^[0-9a-zA-Z._\-$]{1,255}$`)

func monitValidateServiceName(value string) error {
	if !monitServiceNamePattern.MatchString(value) {
		return fmt.Errorf("must be 1-255 letters, digits, . _ - or $, got %q", value)
	}
	return nil
}

var monitTestNamePattern = regexp.MustCompile(`^[0-9a-zA-Z._\-]{1,255}$`)

func monitValidateTestName(value string) error {
	if !monitTestNamePattern.MatchString(value) {
		return fmt.Errorf("must be 1-255 letters, digits, . _ or - (no spaces), got %q", value)
	}
	return nil
}

func monitValidatePath(value string) error {
	if value != "" && !strings.HasPrefix(value, "/") {
		return fmt.Errorf("must be an absolute path, got %q", value)
	}
	return idsMonitValidateNoSpaces(value)
}

// monitValidateCommand accepts an absolute path with arguments
func monitValidateCommand(value string) error {
	if value != "" && !strings.HasPrefix(value, "/") {
		return fmt.Errorf("must be an absolute path of a program with its arguments, got %q", value)
	}
	return idsMonitValidateText(value)
}

func monitValidateEmail(value string) error {
	if value == "" {
		return nil
	}
	if address, err := mail.ParseAddress(value); err != nil || address.Address != value {
		return fmt.Errorf("must be an email address like admin@example.com, got %q", value)
	}
	return nil
}

func monitServiceNames(c *Context) []string {
	var api, err = monitApi(c)
	if err != nil {
		return nil
	}
	var services, _, searchErr = api.ServiceSearch("")
	if searchErr != nil {
		return nil
	}
	var names []string
	for _, service := range services {
		names = append(names, service.Name)
	}
	return names
}

func monitTestNames(c *Context) []string {
	var api, err = monitApi(c)
	if err != nil {
		return nil
	}
	var tests, _, searchErr = api.TestSearch("")
	if searchErr != nil {
		return nil
	}
	var names []string
	for _, test := range tests {
		names = append(names, test.Name)
	}
	return names
}

// monitTestUuids resolves test names (or uuids) to uuids
func monitTestUuids(c *Context, value string) (string, error) {
	if len(splitList(value)) == 0 {
		return "", nil
	}
	var api, err = monitApi(c)
	if err != nil {
		return "", err
	}
	var tests, _, searchErr = api.TestSearch("")
	if searchErr != nil {
		return "", searchErr
	}
	return idsMonitNamesToUuids("test", value, tests, func(t monit.Test) string { return t.Uuid }, func(t monit.Test) string { return t.Name })
}

// monitServiceUuids resolves service names (or uuids) to uuids
func monitServiceUuids(c *Context, value string) (string, error) {
	if len(splitList(value)) == 0 {
		return "", nil
	}
	var api, err = monitApi(c)
	if err != nil {
		return "", err
	}
	var services, _, searchErr = api.ServiceSearch("")
	if searchErr != nil {
		return "", searchErr
	}
	return idsMonitNamesToUuids("service", value, services, func(s monit.Service) string { return s.Uuid },
		func(s monit.Service) string { return s.Name })
}

// monitServiceDependNames renders the depends uuids as service names (the search has no display names for them)
func monitServiceDependNames(depends string, services []monit.Service) string {
	var names []string
	for _, uuid := range splitList(depends) {
		var name = uuid
		for _, service := range services {
			if service.Uuid == uuid {
				name = service.Name
			}
		}
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

// monitServiceInterface checks the interface against the choices of OPNsense
func monitServiceInterface(c *Context, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	var api, err = monitApi(c)
	if err != nil {
		return "", err
	}
	var interfaces, listErr = api.ServiceInterfaces()
	if listErr != nil {
		return "", listErr
	}
	var keys []string
	for _, choice := range interfaces {
		if strings.EqualFold(choice.Key, value) {
			return choice.Key, nil
		}
		keys = append(keys, choice.Key)
	}
	return "", fmt.Errorf("unknown interface %q, valid are: %s", value, strings.Join(keys, ", "))
}

func monitServiceInterfaceKeys(c *Context) []string {
	var api, err = monitApi(c)
	if err != nil {
		return nil
	}
	var interfaces, listErr = api.ServiceInterfaces()
	if listErr != nil {
		return nil
	}
	var keys []string
	for _, choice := range interfaces {
		keys = append(keys, choice.Key)
	}
	return keys
}

func monitServiceEnabled(s monit.Service) bool { return s.Enabled == "1" }

// monitServiceList returns the services, with the depends shown by name in the rows of print detail
func monitServiceList(c *Context, search string) ([]monit.Service, []json.RawMessage, error) {
	var api, err = monitApi(c)
	if err != nil {
		return nil, nil, err
	}
	var services, raw, searchErr = api.ServiceSearch(search)
	if searchErr != nil {
		return nil, nil, searchErr
	}
	var all = services
	if search != "" {
		if all, _, searchErr = api.ServiceSearch(""); searchErr != nil {
			return nil, nil, searchErr
		}
	}
	for i := range services {
		services[i].Depends = monitServiceDependNames(services[i].Depends, all)
	}
	return services, raw, nil
}

var monitServiceRecords = &idsMonitRecords[monit.Service, monit.ServiceFields]{
	what:     "service",
	path:     "monit/service",
	help:     "monitored services: processes, files, hosts, the system... (Monit > Settings > Service Settings)",
	itemHelp: "the #, uuid or name of the service",
	hint:     monitApplyHint,
	addLong: `type decides what is checked: process (pidfile= or match=), file, fifo, filesystem, directory (path=),
host (address=), system (the firewall, name $HOST), custom (path= of a script whose exit status is tested) or
network (interface= or address=). tests are names of /monit/test items allowed for the type.

  add name=sshd type=process pidfile=/var/run/sshd.pid tests=... start="/usr/local/etc/rc.d/openssh start"`,
	list:  monitServiceList,
	uuid:  func(s monit.Service) string { return s.Uuid },
	names: func(s monit.Service) []string { return []string{s.Name} },
	key:   "name",
	keyOf: func(s monit.Service) string { return s.Name },
	create: func(c *Context, patch monit.ServiceFields) (string, error) {
		var api, err = monitApi(c)
		if err != nil {
			return "", err
		}
		return api.ServiceCreate(patch)
	},
	update: func(c *Context, uuid string, patch monit.ServiceFields) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.ServiceUpdate(uuid, patch)
	},
	remove: func(c *Context, uuid string) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.ServiceRemove(uuid)
	},
	removeLong: "A service other services depend on can not be removed.",
	enabled:    monitServiceEnabled,
	columns:    []string{"DISABLED", "NAME", "TYPE", "TARGET", "TESTS", "DESCRIPTION"},
	row: func(s monit.Service) []string {
		var target = s.Path
		switch {
		case s.Pidfile != "":
			target = s.Pidfile
		case s.Match != "":
			target = "match " + s.Match
		case s.Address != "":
			target = s.Address
		case s.Interface != "":
			target = s.Interface
		}
		return []string{YesNo(Flag(!monitServiceEnabled(s))), s.Name, s.Type, target, idsMonitListDisplay(s.TestNames, s.Tests), s.Description}
	},
	fields: []idsMonitField[monit.Service, monit.ServiceFields]{
		{Arg: Arg{Name: "name", Help: "the unique name: letters, digits, . _ - and $", Validate: monitValidateServiceName},
			show: func(s monit.Service) string { return s.Name }, target: func(f *monit.ServiceFields) **string { return &f.Name }},
		idsMonitDisabledField("keep the service, but don't monitor it", monitServiceEnabled,
			func(f *monit.ServiceFields) **string { return &f.Enabled }),
		{Arg: Arg{Name: "description", Help: "any text", Validate: idsMonitValidateText},
			show: func(s monit.Service) string { return s.Description }, target: func(f *monit.ServiceFields) **string { return &f.Description }},
		{Arg: Arg{Name: "type", Help: "what the service is", Values: monit.ServiceTypes, Required: true},
			show: func(s monit.Service) string { return s.Type }, target: func(f *monit.ServiceFields) **string { return &f.Type },
			convert: func(_ *Context, value string) (string, error) { return strings.ToLower(value), nil }},
		{Arg: Arg{Name: "pidfile", Help: "process: the PID file", Validate: monitValidatePath},
			show: func(s monit.Service) string { return s.Pidfile }, target: func(f *monit.ServiceFields) **string { return &f.Pidfile }},
		{Arg: Arg{Name: "match", Help: "process: a regular expression matching the process instead of pidfile", Validate: idsMonitValidateNoSpaces},
			show: func(s monit.Service) string { return s.Match }, target: func(f *monit.ServiceFields) **string { return &f.Match }},
		{Arg: Arg{Name: "path", Help: "file, fifo, filesystem, directory: the path; custom: the script", Validate: monitValidatePath},
			show: func(s monit.Service) string { return s.Path }, target: func(f *monit.ServiceFields) **string { return &f.Path }},
		{Arg: Arg{Name: "address", Help: "host, network: the host name or IP address", Validate: idsMonitValidateNoSpaces},
			show: func(s monit.Service) string { return s.Address }, target: func(f *monit.ServiceFields) **string { return &f.Address }},
		{Arg: Arg{Name: "interface", Help: "network: the interface, like lan", Complete: monitServiceInterfaceKeys},
			show: func(s monit.Service) string { return s.Interface }, target: func(f *monit.ServiceFields) **string { return &f.Interface },
			convert: monitServiceInterface},
		{Arg: Arg{Name: "start", Help: "the command to start the service: absolute path with arguments", Validate: monitValidateCommand},
			show: func(s monit.Service) string { return s.Start }, target: func(f *monit.ServiceFields) **string { return &f.Start }},
		{Arg: Arg{Name: "stop", Help: "the command to stop the service: absolute path with arguments", Validate: monitValidateCommand},
			show: func(s monit.Service) string { return s.Stop }, target: func(f *monit.ServiceFields) **string { return &f.Stop }},
		{Arg: Arg{Name: "timeout", Type: Int, Default: "300", Help: "the program timeout in seconds (1-86400)", Validate: ValidateRange(1, 86400)},
			show: func(s monit.Service) string { return s.Timeout }, target: func(f *monit.ServiceFields) **string { return &f.Timeout }},
		{Arg: Arg{Name: "start-timeout", Type: Int, Default: "30", Help: "seconds to wait for a start (0-86400)", Validate: ValidateRange(0, 86400)},
			show: func(s monit.Service) string { return s.StartTimeout }, target: func(f *monit.ServiceFields) **string { return &f.StartTimeout }},
		{Arg: Arg{Name: "tests", Type: List, Help: "the names of the tests (see /monit/test), they must fit the type", Complete: monitTestNames},
			show:   func(s monit.Service) string { return idsMonitListDisplay(s.TestNames, s.Tests) },
			target: func(f *monit.ServiceFields) **string { return &f.Tests }, convert: monitTestUuids},
		{Arg: Arg{Name: "depends", Type: List, Help: "the names of services this one depends on", Complete: monitServiceNames},
			show: func(s monit.Service) string { return s.Depends }, target: func(f *monit.ServiceFields) **string { return &f.Depends },
			convert: monitServiceUuids},
		{Arg: Arg{Name: "polltime", Help: `when to check: a cron like schedule or "every 2 cycles", "" for every cycle`, Validate: idsMonitValidateText},
			show: func(s monit.Service) string { return s.Polltime }, target: func(f *monit.ServiceFields) **string { return &f.Polltime }},
	},
}

var monitTestRecords = &idsMonitRecords[monit.Test, monit.TestFields]{
	what:     "test",
	path:     "monit/test",
	help:     "service tests: conditions and the action when they fail (Monit > Settings > Service Tests)",
	itemHelp: "the #, uuid or name of the test",
	hint:     monitApplyHint,
	printLong: `TYPE is derived by OPNsense from the condition ("Custom" for conditions without a known pattern), a
service accepts only tests of types that fit its own type.`,
	addLong: `  add name=HighCpu condition="cpu usage is greater than 90%" action=alert`,
	setLong: `The type of a test used by a service can not change, also not through a new condition.`,
	list: func(c *Context, search string) ([]monit.Test, []json.RawMessage, error) {
		var api, err = monitApi(c)
		if err != nil {
			return nil, nil, err
		}
		return api.TestSearch(search)
	},
	uuid:  func(t monit.Test) string { return t.Uuid },
	names: func(t monit.Test) []string { return []string{t.Name} },
	key:   "name",
	keyOf: func(t monit.Test) string { return t.Name },
	create: func(c *Context, patch monit.TestFields) (string, error) {
		var api, err = monitApi(c)
		if err != nil {
			return "", err
		}
		return api.TestCreate(patch)
	},
	update: func(c *Context, uuid string, patch monit.TestFields) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.TestUpdate(uuid, patch)
	},
	remove: func(c *Context, uuid string) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.TestRemove(uuid)
	},
	removeLong: "A test used by a service can not be removed.",
	columns:    []string{"NAME", "TYPE", "CONDITION", "ACTION", "PATH"},
	row:        func(t monit.Test) []string { return []string{t.Name, t.Type, t.Condition, t.Action, t.Path} },
	fields: []idsMonitField[monit.Test, monit.TestFields]{
		{Arg: Arg{Name: "name", Help: "the name: letters, digits, . _ - (no spaces)", Validate: monitValidateTestName},
			show: func(t monit.Test) string { return t.Name }, target: func(f *monit.TestFields) **string { return &f.Name }},
		{Arg: Arg{Name: "type"}, show: func(t monit.Test) string { return t.Type }},
		{Arg: Arg{Name: "condition", Help: `the Monit condition like "memory usage is greater than 75%"`, Required: true,
			Validate: idsMonitValidateText},
			show: func(t monit.Test) string { return t.Condition }, target: func(f *monit.TestFields) **string { return &f.Condition }},
		{Arg: Arg{Name: "action", Help: "what Monit does when the test fails", Values: monit.TestActions, Required: true},
			show: func(t monit.Test) string { return t.Action }, target: func(f *monit.TestFields) **string { return &f.Action },
			convert: func(_ *Context, value string) (string, error) { return strings.ToLower(value), nil }},
		{Arg: Arg{Name: "path", Help: "action exec: the program to run (absolute path)", Validate: monitValidatePath},
			show: func(t monit.Test) string { return t.Path }, target: func(f *monit.TestFields) **string { return &f.Path }},
	},
}

func monitAlertEnabled(a monit.Alert) bool { return a.Enabled == "1" }

var monitAlertRecords = &idsMonitRecords[monit.Alert, monit.AlertFields]{
	what:     "alert",
	path:     "monit/alert",
	help:     "alert recipients: who gets mail about which events (Monit > Settings > Alert Settings)",
	itemHelp: "the #, uuid, recipient or description of the alert",
	hint:     monitApplyHint,
	addLong: `Recipients need not be unique (e.g. one alert per event set), add always creates a new alert.

  add recipient=admin@example.com events=nonexist,resource reminder=10`,
	list: func(c *Context, search string) ([]monit.Alert, []json.RawMessage, error) {
		var api, err = monitApi(c)
		if err != nil {
			return nil, nil, err
		}
		return api.AlertSearch(search)
	},
	uuid:  func(a monit.Alert) string { return a.Uuid },
	names: func(a monit.Alert) []string { return []string{a.Recipient, a.Description} },
	create: func(c *Context, patch monit.AlertFields) (string, error) {
		var api, err = monitApi(c)
		if err != nil {
			return "", err
		}
		return api.AlertCreate(patch)
	},
	update: func(c *Context, uuid string, patch monit.AlertFields) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.AlertUpdate(uuid, patch)
	},
	remove: func(c *Context, uuid string) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.AlertRemove(uuid)
	},
	enabled: monitAlertEnabled,
	columns: []string{"DISABLED", "RECIPIENT", "NOT-ON", "EVENTS", "REMINDER", "DESCRIPTION"},
	row: func(a monit.Alert) []string {
		return []string{YesNo(Flag(!monitAlertEnabled(a))), a.Recipient, YesNo(a.NotOn), a.Events, a.Reminder, a.Description}
	},
	check: func(args *Args) error {
		if args.Bool("not-on") && args.Has("events") && len(args.List("events")) == 0 {
			return fmt.Errorf("not-on needs at least one event")
		}
		return nil
	},
	fields: []idsMonitField[monit.Alert, monit.AlertFields]{
		{Arg: Arg{Name: "recipient", Help: "the email address", Required: true, Validate: monitValidateEmail},
			show: func(a monit.Alert) string { return a.Recipient }, target: func(f *monit.AlertFields) **string { return &f.Recipient }},
		idsMonitDisabledField("keep the alert, but don't send it", monitAlertEnabled,
			func(f *monit.AlertFields) **string { return &f.Enabled }),
		{Arg: Arg{Name: "description", Help: "any text", Validate: idsMonitValidateText},
			show: func(a monit.Alert) string { return a.Description }, target: func(f *monit.AlertFields) **string { return &f.Description }},
		{Arg: Arg{Name: "events", Type: List, Help: `the events to notify about, "" for all`, Values: monit.AlertEvents},
			show: func(a monit.Alert) string { return a.Events }, target: func(f *monit.AlertFields) **string { return &f.Events },
			convert: func(_ *Context, value string) (string, error) {
				return strings.ToLower(strings.Join(splitList(value), ",")), nil
			}},
		{Arg: Arg{Name: "not-on", Type: Bool, Default: "no", Help: "invert events: notify about all events except these"},
			show: func(a monit.Alert) string { return YesNo(a.NotOn) }, target: func(f *monit.AlertFields) **string { return &f.NotOn }},
		{Arg: Arg{Name: "format", Help: `the mail format like "subject: $SERVICE $EVENT", "" for the default`, Validate: monitValidateFormat},
			show: func(a monit.Alert) string { return a.Format }, target: func(f *monit.AlertFields) **string { return &f.Format }},
		{Arg: Arg{Name: "reminder", Type: Int, Help: `send the alert again every n cycles while the error lasts, "" for never`,
			Validate: ValidateRange(0, 86400)},
			show: func(a monit.Alert) string { return a.Reminder }, target: func(f *monit.AlertFields) **string { return &f.Reminder }},
	},
}

func monitValidateFormat(value string) error {
	if strings.ContainsAny(value, "{}") {
		return fmt.Errorf(`must not contain "{" or "}", got %q`, value)
	}
	return idsMonitValidateText(value)
}
