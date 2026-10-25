package cli

import (
	"opnsense-cli/opnsense/api/ids"
)

// /ids: Services > Intrusion Detection (Suricata, api/ids). /ids/settings are the general settings, /ids/service
// controls Suricata; rule sets, rules, policies, user defined rules and alerts have their own menus

// idsApplyHint ends the help of the commands that change the rule configuration
const idsApplyHint = `Changes are only saved, run "/ids/service reload-rules" to install the rules with them (or
"/ids/service reconfigure" after settings changes).`

// idsStartWarning is the confirmation of the commands that (re)start Suricata
const idsStartWarning = "This (re)starts Suricata with the saved settings. In IPS mode (netmap or divert) it inspects " +
	"the traffic of the selected interfaces inline and drops what the rules say, possibly also your connection to the firewall."

func init() {
	Root.Menu("ids").Help = "intrusion detection and prevention (Suricata)"

	var menu = Root.Menu("ids/settings")
	menu.Help = "general intrusion detection settings (Administration > Settings)"
	menu.Add(
		&Command{Name: "print", Help: "show the settings",
			Long: `Shows the general settings. options=<field> lists the choices of an option field (like interfaces)
with their key, display name and whether they are selected.`,
			Args: idsSettingsForm.printArgs(), Run: idsSettingsForm.print},
		&Command{Name: "set", Help: "change settings, the others are kept",
			Long: `Changes the given settings, the others are kept. Lists are comma separated, "" clears them.

  set enabled mode=pcap interfaces=wan home-networks=192.168.0.0/16,10.0.0.0/8

mode pcap is IDS (alerts only); netmap and divert are IPS modes that inspect the traffic inline and can drop it,
including the connection to the firewall. Changes are only saved, run "/ids/service reconfigure" to apply them.`,
			Args: idsSettingsForm.setArgs(), Run: idsSettingsForm.runSet},
	)

	var service = Root.Menu("ids/service")
	service.Help = "the Suricata service"
	service.Add(
		&Command{Name: "status", Help: "show whether Suricata is running", Run: idsServiceStatus},
		&Command{Name: "start", Help: "start Suricata", Confirm: idsStartWarning, Run: idsServiceAction("start")},
		&Command{Name: "stop", Help: "stop Suricata", Run: idsServiceAction("stop")},
		&Command{Name: "restart", Help: "restart Suricata", Confirm: idsStartWarning, Run: idsServiceAction("restart")},
		&Command{Name: "reconfigure", Help: "apply the saved settings: rewrite the configuration, install the rules, (re)start or stop Suricata",
			Long: `Like Apply in the GUI: writes the Suricata configuration and installs the rules, then starts or
restarts Suricata when it is enabled and stops it when not. The first reconfigure also creates the daily rule
update cron job.`,
			Confirm: idsStartWarning, Run: idsServiceAction("reconfigure")},
		&Command{Name: "reload-rules", Help: "install the rules with the rule set, policy and adjustment changes and reload them",
			Long: `Installs the rules with the saved rule set, policy, rule adjustment and user rule changes and makes a
running Suricata reload them without a restart. OPNsense reports an error when Suricata is not running, the rules
are installed anyway.`,
			Run: idsServiceAction("reload-rules")},
	)
}

func idsApi(c *Context) (*ids.IdsApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &ids.IdsApi{OPNsense: opn}, nil
}

// --- /ids/settings

var idsSettingsForm = &idsMonitSettingsForm{
	settings: []idsMonitSetting{
		{Arg: Arg{Name: "enabled", Type: Bool, Help: "run Suricata"}, path: "enabled"},
		{Arg: Arg{Name: "mode", Help: "pcap: IDS (alerts only), netmap / divert: IPS (inline, can drop traffic)",
			Values: []string{"pcap", "netmap", "divert"}}, path: "mode", option: true},
		{Arg: Arg{Name: "divert-listeners", Type: Int, Help: "the number of divert listeners (1-256)", Validate: ValidateRange(1, 256)},
			path: "divert_listeners"},
		{Arg: Arg{Name: "promiscuous", Type: Bool, Help: "promiscuous mode, also see the traffic of other hosts (VLANs, bridges)"}, path: "promisc"},
		{Arg: Arg{Name: "interfaces", Type: List, Help: "the interfaces to inspect, like wan"}, path: "interfaces", option: true},
		{Arg: Arg{Name: "home-networks", Type: List, Help: "the home networks (HOME_NET), comma separated CIDRs"}, path: "homenet"},
		{Arg: Arg{Name: "default-packet-size", Type: Int, Help: `packet size in bytes (82-65535), "" for the default`,
			Validate: ValidateRange(82, 65535)}, path: "defaultPacketSize"},
		{Arg: Arg{Name: "alert-log-rotate", Help: "rotate the alert log", Values: []string{"weekly", "daily"}},
			path: "AlertLogrotate", option: true, aliases: map[string]string{"weekly": "W0D23", "daily": "D0"}},
		{Arg: Arg{Name: "alert-log-keep", Type: Int, Help: "the number of rotated alert logs to keep (1-1000)", Validate: ValidateRange(1, 1000)},
			path: "AlertSaveLogs"},
		{Arg: Arg{Name: "pattern-matcher", Help: "the multi pattern matcher: default, ac (Aho-Corasick), ac-ks (Ken Steele) or hs (Hyperscan)",
			Values: []string{"default", "ac", "ac-ks", "hs"}}, path: "MPMAlgo", option: true, aliases: map[string]string{"default": ""}},
		{Arg: Arg{Name: "detect-profile", Help: "the detection profile (memory use vs. performance)",
			Values: []string{"default", "low", "medium", "high", "custom"}}, path: "detect.Profile", option: true, aliases: map[string]string{"default": ""}},
		{Arg: Arg{Name: "detect-toclient-groups", Type: Int, Help: `toclient groups of the custom profile (0-65535), "" for the default`,
			Validate: ValidateRange(0, 65535)}, path: "detect.toclient_groups"},
		{Arg: Arg{Name: "detect-toserver-groups", Type: Int, Help: `toserver groups of the custom profile (0-65535), "" for the default`,
			Validate: ValidateRange(0, 65535)}, path: "detect.toserver_groups"},
		{Arg: Arg{Name: "syslog", Type: Bool, Help: "send the alerts to the system log"}, path: "syslog"},
		{Arg: Arg{Name: "syslog-eve", Type: Bool, Help: "send the alerts in eve (JSON) format to the system log"}, path: "syslog_eve"},
		{Arg: Arg{Name: "log-payload", Type: Bool, Help: "log the packet payload with the alerts"}, path: "LogPayload"},
		{Arg: Arg{Name: "verbosity", Help: "the Suricata log level", Values: []string{"default", "info", "perf", "config", "debug"}},
			path: "verbosity", option: true,
			aliases: map[string]string{"default": "", "info": "v", "perf": "vv", "config": "vvv", "debug": "vvvv"}},
		{Arg: Arg{Name: "eve-http", Type: Bool, Help: "log HTTP requests in the eve log"}, path: "eveLog.http.enable"},
		{Arg: Arg{Name: "eve-http-extended", Type: Bool, Help: "log extended HTTP information"}, path: "eveLog.http.extended"},
		{Arg: Arg{Name: "eve-http-dump-headers", Help: "log all HTTP headers of", Values: []string{"none", "request", "response", "both"}},
			path: "eveLog.http.dumpAllHeaders", option: true, aliases: map[string]string{"none": ""}},
		{Arg: Arg{Name: "eve-tls", Type: Bool, Help: "log TLS handshakes in the eve log"}, path: "eveLog.tls.enable"},
		{Arg: Arg{Name: "eve-tls-extended", Type: Bool, Help: "log extended TLS information"}, path: "eveLog.tls.extended"},
		{Arg: Arg{Name: "eve-tls-session-resumption", Type: Bool, Help: "log TLS session resumptions"}, path: "eveLog.tls.sessionResumption"},
		{Arg: Arg{Name: "eve-tls-custom", Type: List, Help: "custom TLS fields to log, like subject,issuer,sni,ja3"}, path: "eveLog.tls.custom", option: true},
	},
	get: func(c *Context) (map[string]idsMonitSettingsField, error) {
		var api, err = idsApi(c)
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
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		return api.SettingsSet(values)
	},
}

// --- /ids/service

func idsServiceStatus(c *Context, _ *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.ServiceStatus()
	if statusErr != nil {
		return statusErr
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func idsServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = idsApi(c)
		if err != nil {
			return err
		}
		switch action {
		case "start":
			return api.ServiceStart()
		case "stop":
			return api.ServiceStop()
		case "restart":
			return api.ServiceRestart()
		case "reload-rules":
			return api.ServiceReloadRules()
		default:
			return api.ServiceReconfigure()
		}
	}
}
