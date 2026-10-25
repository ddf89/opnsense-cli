package cli

import (
	"encoding/json"
	"net/url"
	"opnsense-cli/opnsense/api/monit"
	"strings"
)

// /monit: Services > Monit (api/monit). /monit/settings are the general settings, /monit/service the monitored
// services, /monit/test their tests, /monit/alert the alert recipients, /monit/status the status report and
// /monit/service-control the Monit daemon

const monitApplyHint = `Changes are only saved, run "/monit/service-control reconfigure" to apply them.`

func init() {
	Root.Menu("monit").Help = "Monit: service monitoring and alerts"

	var menu = Root.Menu("monit/settings")
	menu.Help = "general Monit settings: polling, mail server, httpd, M/Monit"
	menu.Add(
		&Command{Name: "print", Help: "show the settings",
			Long: `Shows the general settings, the passwords only as "(set)". options=<field> lists the choices of an
option field.`,
			Args: monitSettingsForm.printArgs(), Run: monitSettingsForm.print},
		&Command{Name: "set", Help: "change settings, the others are kept",
			Long: `Changes the given settings, the others are kept. Lists are comma separated, "" clears them.

  set interval=60 mail-server=mail.example.com mail-port=587 mail-ssl

` + monitApplyHint,
			Args: monitSettingsForm.setArgs(), Run: monitSettingsForm.runSet},
	)

	var status = Root.Menu("monit/status")
	status.Help = "the Monit status report (Monit > Status)"
	status.Add(&Command{Name: "print", Help: "show the status of all monitored services",
		Long: `Shows the report of "monit status": every service with its state and the values of its tests. Monit
must be running. json prints the status as one JSON object (OPNsense's form of Monit's XML status, the httpd
password masked).`,
		Args: []Arg{{Name: "json", Type: Bool, Help: "print the status as one JSON object"}}, Run: monitStatusPrint})

	var control = Root.Menu("monit/service-control")
	control.Help = "the Monit daemon"
	control.Add(
		&Command{Name: "status", Help: "show whether Monit is running", Run: monitControlStatus},
		&Command{Name: "start", Help: "start Monit", Run: monitControlAction("start")},
		&Command{Name: "stop", Help: "stop Monit", Run: monitControlAction("stop")},
		&Command{Name: "restart", Help: "restart Monit", Run: monitControlAction("restart")},
		&Command{Name: "reconfigure", Help: "apply the saved configuration (write it and start Monit or make it reload, stop it when disabled)",
			Run: monitControlAction("reconfigure")},
	)
}

func monitApi(c *Context) (*monit.MonitApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &monit.MonitApi{OPNsense: opn}, nil
}

// monitHideUrlPassword replaces the password of a URL like http://user:secret@host/ by ********
func monitHideUrlPassword(value string) string {
	var parsed, err = url.Parse(value)
	if err != nil || parsed.User == nil {
		return value
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		parsed.User = url.UserPassword(parsed.User.Username(), "xxxxxxxx")
		return strings.Replace(parsed.String(), "xxxxxxxx", "********", 1)
	}
	return value
}

var monitSettingsForm = &idsMonitSettingsForm{
	settings: []idsMonitSetting{
		{Arg: Arg{Name: "enabled", Type: Bool, Help: "run Monit"}, path: "enabled"},
		{Arg: Arg{Name: "interval", Type: Int, Help: "seconds between two checks (0-86400)", Validate: ValidateRange(0, 86400)}, path: "interval"},
		{Arg: Arg{Name: "start-delay", Type: Int, Help: "seconds to wait after start before the first check (0-86400)",
			Validate: ValidateRange(0, 86400)}, path: "startdelay"},
		{Arg: Arg{Name: "mail-server", Type: List, Help: "the mail servers for alerts, host names or IP addresses"}, path: "mailserver"},
		{Arg: Arg{Name: "mail-port", Type: Int, Help: "the port of the mail servers", Validate: ValidateRange(0, 65535)}, path: "port"},
		{Arg: Arg{Name: "mail-username", Help: `the user name for the mail server, "" for none`, Validate: idsMonitValidateNoSpaces}, path: "username"},
		{Arg: Arg{Name: "mail-password", Help: `the password for the mail server, "" for none`, Validate: idsMonitValidateNoSpaces},
			path: "password", secret: true},
		{Arg: Arg{Name: "mail-ssl", Type: Bool, Help: "use SSL/TLS for the mail server"}, path: "ssl"},
		{Arg: Arg{Name: "mail-ssl-version", Help: "the SSL/TLS version", Values: []string{"auto", "tlsv1", "tlsv11", "tlsv12", "tlsv13"}},
			path: "sslversion", option: true},
		{Arg: Arg{Name: "mail-ssl-verify", Type: Bool, Help: "verify the certificate of the mail server"}, path: "sslverify"},
		{Arg: Arg{Name: "log-file", Help: `the log file (absolute path) or "syslog", "" for the default`, Validate: idsMonitValidateNoSpaces},
			path: "logfile"},
		{Arg: Arg{Name: "state-file", Help: `the state file (absolute path), "" for the default`, Validate: idsMonitValidateNoSpaces}, path: "statefile"},
		{Arg: Arg{Name: "eventqueue-path", Help: `the directory of the event queue (alerts that could not be sent), "" for none`,
			Validate: idsMonitValidateNoSpaces}, path: "eventqueuePath"},
		{Arg: Arg{Name: "eventqueue-slots", Type: Int, Help: `the size of the event queue, "" for unlimited`, Validate: ValidateRange(0, 1<<30)},
			path: "eventqueueSlots"},
		{Arg: Arg{Name: "httpd-enabled", Type: Bool, Help: "run the Monit web interface (needs httpd-password)"}, path: "httpdEnabled"},
		{Arg: Arg{Name: "httpd-username", Help: "the user name of the web interface", Validate: idsMonitValidateNoSpaces}, path: "httpdUsername"},
		{Arg: Arg{Name: "httpd-password", Help: "the password of the web interface", Validate: idsMonitValidateNoSpaces},
			path: "httpdPassword", secret: true},
		{Arg: Arg{Name: "httpd-port", Type: Int, Help: "the port of the web interface", Validate: ValidatePort}, path: "httpdPort"},
		{Arg: Arg{Name: "httpd-allow", Type: List, Help: "hosts and networks allowed to use the web interface"}, path: "httpdAllow"},
		{Arg: Arg{Name: "mmonit-url", Help: `the M/Monit collector URL like http://user:pass@host:8080/collector, "" for none`,
			Validate: idsMonitValidateNoSpaces}, path: "mmonitUrl", render: monitHideUrlPassword},
		{Arg: Arg{Name: "mmonit-timeout", Type: Int, Help: "the timeout for M/Monit in seconds (0-86400)", Validate: ValidateRange(0, 86400)},
			path: "mmonitTimeout"},
		{Arg: Arg{Name: "mmonit-register-credentials", Type: Bool, Help: "register the httpd credentials with M/Monit"},
			path: "mmonitRegisterCredentials"},
	},
	get: func(c *Context) (map[string]idsMonitSettingsField, error) {
		var api, err = monitApi(c)
		if err != nil {
			return nil, err
		}
		var settings, getErr = api.SettingsGet()
		if getErr != nil {
			return nil, getErr
		}
		var fields = make(map[string]idsMonitSettingsField, len(settings))
		for path, setting := range settings {
			var field = idsMonitSettingsField{Value: setting.Value}
			if setting.IsOption() {
				field.Options = make([]idsMonitSettingsOption, len(setting.Options))
				for i, option := range setting.Options {
					field.Options[i] = idsMonitSettingsOption(option)
				}
			}
			fields[path] = field
		}
		return fields, nil
	},
	set: func(c *Context, values map[string]string) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		return api.SettingsSet(values)
	},
}

func monitStatusPrint(c *Context, args *Args) error {
	var api, err = monitApi(c)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		var status, statusErr = api.StatusXml()
		if statusErr != nil {
			return statusErr
		}
		return c.JSON(monitStatusHideCredentials(status))
	}
	var text, statusErr = api.StatusText()
	if statusErr != nil {
		return statusErr
	}
	c.Println(text)
	return nil
}

// monitStatusHideCredentials masks the httpd password Monit puts into its XML status (server.credentials, sent when
// M/Monit is set up with "register credentials")
func monitStatusHideCredentials(status json.RawMessage) json.RawMessage {
	var document map[string]any
	if json.Unmarshal(status, &document) != nil {
		return status
	}
	var server, _ = document["server"].(map[string]any)
	var credentials, _ = server["credentials"].(map[string]any)
	if password, ok := credentials["password"]; !ok || password == "" {
		return status
	}
	credentials["password"] = "********"
	var masked, err = json.Marshal(document)
	if err != nil {
		return status
	}
	return masked
}

func monitControlStatus(c *Context, _ *Args) error {
	var api, err = monitApi(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.DaemonStatus()
	if statusErr != nil {
		return statusErr
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func monitControlAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = monitApi(c)
		if err != nil {
			return err
		}
		switch action {
		case "start":
			return api.DaemonStart()
		case "stop":
			return api.DaemonStop()
		case "restart":
			return api.DaemonRestart()
		default:
			return api.DaemonReconfigure()
		}
	}
}
