package cli

import (
	"errors"
	"fmt"
	"strings"

	"opnsense-cli/opnsense/api/ipsec"
)

// /vpn/ipsec/settings: VPN > IPsec > Mobile & Advanced Settings (api/ipsec/settings): general options, the
// strongSwan daemon options, log levels and the attributes pushed to mobile clients. IPsec itself is switched on
// and off with /vpn/ipsec/service enable|disable

const vpnIpsecSettingsHint = `Changes are only saved, run "/vpn/ipsec/service reconfigure" to apply them.`

var vpnIpsecLogLevels = [][2]string{{"silent", "-1"}, {"audit", "0"}, {"control", "1"}, {"debug", "2"}, {"raw", "3"}, {"private", "4"}}

var vpnIpsecSettingsForm = func(api *ipsec.IPsecApi) (ipsec.Form, error) { return api.SettingsGet() }

func vpnIpsecSettingsFields() []vpnIpsecField {
	var flag = func(name string, field string, help string) vpnIpsecField {
		return vpnIpsecField{Arg: Arg{Name: name, Type: Bool, Help: help}, field: field, kind: vpnIpsecFlag}
	}
	var number = func(name string, field string, help string, min int, max int) vpnIpsecField {
		return vpnIpsecField{Arg: Arg{Name: name, Type: Int, Help: help, Validate: ValidateRange(min, max)}, field: field}
	}
	var decimal = func(name string, field string, help string) vpnIpsecField {
		return vpnIpsecField{Arg: Arg{Name: name, Help: help, Validate: vpnIpsecValidateDecimal}, field: field}
	}
	var networks = func(name string, field string, help string) vpnIpsecField {
		return vpnIpsecField{Arg: Arg{Name: name, Type: List, Help: help, Validate: vpnIpsecValidateNetworks}, field: field, kind: vpnIpsecList}
	}
	var text = func(name string, field string, help string) vpnIpsecField {
		return vpnIpsecField{Arg: Arg{Name: name, Help: help, Validate: vpnIpsecValidateText}, field: field}
	}
	var fields = []vpnIpsecField{
		flag("prefer-old-sa", "general.preferred_oldsa", "always prefer older SAs over new ones"),
		flag("disable-vpn-rules", "general.disablevpnrules", "don't add the automatic VPN firewall rules of legacy tunnels"),
		networks("passthrough-networks", "general.passthrough_networks", "networks exempt from IPsec processing, e.g. the LAN"),
		{Arg: Arg{Name: "user-source", Type: List, Help: "authentication servers for Xauth (deprecated)",
			Complete: vpnIpsecCompleteRef(vpnIpsecSettingsForm, "general.user_source", false)}, field: "general.user_source", kind: vpnIpsecRefList},
		{Arg: Arg{Name: "local-group", Help: "only members of this group may log in with Xauth (deprecated)",
			Complete: vpnIpsecCompleteRef(vpnIpsecSettingsForm, "general.local_group", false)}, field: "general.local_group", kind: vpnIpsecRef},
		number("max-ikev1-exchanges", "charon.max_ikev1_exchanges", "maximum concurrent IKEv1 phase 2 exchanges per IKE SA (deprecated)", 0, 65536),
		number("threads", "charon.threads", "number of worker threads, default 16", 1, 65536),
		number("ikesa-table-size", "charon.ikesa_table_size", "size of the IKE SA hash table, default 32", 1, 65536),
		number("ikesa-table-segments", "charon.ikesa_table_segments", "locked segments of the IKE SA hash table, default 4", 1, 65536),
		number("init-limit-half-open", "charon.init_limit_half_open", "refuse new connections above this number of half open IKE SAs, default 1000", 1, 65536),
		flag("ignore-acquire-ts", "charon.ignore_acquire_ts", "ignore the traffic selectors of kernel acquires (default yes)"),
		flag("install-routes", "charon.install_routes", "install routes for the tunnels into a separate routing table"),
		flag("cisco-unity", "charon.cisco_unity", "send the Cisco Unity vendor id (IKEv1, deprecated)"),
		flag("make-before-break", "charon.make_before_break", "reauthenticate IKEv2 make-before-break"),
		number("reqid-base", "charon.reqid_base", "first reqid assigned automatically", 0, 1<<31-1),
		number("retry-initiate-interval", "charon.retry_initiate_interval", "seconds between retries when the remote address can not be resolved, 0 disables", 0, 1<<31-1),
		number("retransmit-tries", "charon.retransmit_tries", "retransmissions before giving up", 0, 1<<31-1),
		decimal("retransmit-timeout", "charon.retransmit_timeout", "retransmission timeout in seconds"),
		decimal("retransmit-base", "charon.retransmit_base", "base of the exponential retransmission backoff"),
		number("retransmit-jitter", "charon.retransmit_jitter", "maximum random jitter of the retransmission timeout in percent", 0, 100),
		number("retransmit-limit", "charon.retransmit_limit", "upper limit of the retransmission timeout in seconds, 0 disables", 0, 1<<31-1),
		flag("log-ike-name", "charon.syslog.daemon.ike_name", "prefix log lines with the connection name (default yes)"),
		flag("log-level-prefix", "charon.syslog.daemon.log_level", "add the log level to each log line"),
	}
	for _, subsystem := range ipsec.SettingsLogLevelFields {
		fields = append(fields, vpnIpsecMap(Arg{Name: "log-" + subsystem,
			Help: "log level of " + subsystem + ": silent, audit, control (default), debug, raw or private (includes keys)"},
			"charon.syslog.daemon."+subsystem, vpnIpsecLogLevels...))
	}
	var pfsGroups = [][2]string{{"none", ""}}
	for _, group := range []string{"1", "2", "5", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "28", "29", "30", "31"} {
		pfsGroups = append(pfsGroups, [2]string{group, group})
	}
	return append(fields,
		networks("mobile-subnets", "charon.plugins.attr.subnet", "networks pushed to mobile clients (macOS uses them as routes)"),
		vpnIpsecField{Arg: Arg{Name: "mobile-dns", Type: List, Help: "DNS servers pushed to mobile clients", Validate: ValidateIPList}, field: "charon.plugins.attr.dns", kind: vpnIpsecList},
		vpnIpsecField{Arg: Arg{Name: "mobile-wins", Type: List, Help: "WINS servers pushed to mobile clients", Validate: ValidateIPList}, field: "charon.plugins.attr.nbns", kind: vpnIpsecList},
		networks("unity-split-include", "charon.plugins.attr.split-include", "Cisco Unity: networks to tunnel (deprecated)"),
		text("unity-default-domain", "charon.plugins.attr.x_28674", "Cisco Unity: default search domain"),
		text("unity-split-dns", "charon.plugins.attr.x_28675", "Cisco Unity: space separated domains to resolve with the pushed DNS servers"),
		text("unity-banner", "charon.plugins.attr.x_28672", "Cisco Unity: login banner"),
		flag("unity-save-password", "charon.plugins.attr.x_28673", "Cisco Unity: allow clients to save the Xauth password"),
		vpnIpsecMap(Arg{Name: "unity-pfs-group", Help: "Cisco Unity: PFS group (DH group number), none to not push one"},
			"charon.plugins.attr.x_28679", pfsGroups...),
		vpnIpsecField{Arg: Arg{Name: "radius-servers", Type: List, Help: "RADIUS servers for eap-radius",
			Complete: vpnIpsecCompleteRef(vpnIpsecSettingsForm, "charon.plugins.eap-radius.servers", false)},
			field: "charon.plugins.eap-radius.servers", kind: vpnIpsecRefList},
		flag("radius-accounting", "charon.plugins.eap-radius.accounting", "send RADIUS accounting"),
		flag("radius-class-group", "charon.plugins.eap-radius.class_group", "use the RADIUS class attribute as group"),
		vpnIpsecField{Arg: Arg{Name: "pam-service", Help: "PAM service for xauth-pam, default ipsec", Validate: vpnIpsecNotEmpty}, field: "charon.plugins.xauth-pam.pam_service"},
		flag("pam-session", "charon.plugins.xauth-pam.session", "open a PAM session for each IKE SA"),
		flag("pam-trim-email", "charon.plugins.xauth-pam.trim_email", "use only the user part of an email address as Xauth username (default yes)"),
	)
}

func vpnIpsecValidateDecimal(value string) error {
	if value == "" {
		return nil
	}
	var dot = false
	for i, char := range value {
		switch {
		case char >= '0' && char <= '9':
		case char == '.' && !dot && i > 0:
			dot = true
		default:
			return fmt.Errorf("must be a number like 4 or 1.8, got %q", value)
		}
	}
	return nil
}

func vpnIpsecSettingsArgNames() []string {
	var names []string
	for _, spec := range vpnIpsecSettingsFields() {
		if spec.kind == vpnIpsecRef || spec.kind == vpnIpsecRefList {
			names = append(names, spec.Name)
		}
	}
	return names
}

func init() {
	var menu = Root.Menu("vpn/ipsec/settings")
	menu.Help = "mobile client and advanced strongSwan settings (VPN > IPsec > Mobile & Advanced Settings)"
	menu.Add(
		&Command{Name: "print", Help: "show the settings",
			Long: `Shows the settings named like the arguments of set. options=<field> lists the choices of a reference
field instead (key, name, selected). json prints one object with the API field names (lists comma separated).`,
			Args: []Arg{
				{Name: "options", Values: vpnIpsecSettingsArgNames(), Help: "list the choices of this field"},
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object"},
			},
			Run: vpnIpsecSettingsPrint},
		&Command{Name: "set", Help: "change settings, the others are kept",
			Long: "An empty value clears a field (lists), the references (user-source, local-group, radius-servers) are\n" +
				"given by name.\n" + vpnIpsecSettingsHint,
			Args: vpnIpsecArgs(vpnIpsecSettingsFields()), Run: vpnIpsecSettingsSet},
	)
}

// vpnIpsecSettingsPresent returns the fields this OPNsense version knows
func vpnIpsecSettingsPresent(form ipsec.Form) []vpnIpsecField {
	var present []vpnIpsecField
	for _, spec := range vpnIpsecSettingsFields() {
		if _, found := form[spec.field]; found {
			present = append(present, spec)
		}
	}
	return present
}

func vpnIpsecSettingsPrint(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var form, formErr = api.SettingsGet()
	if formErr != nil {
		return formErr
	}
	if args.Has("options") {
		var name = strings.ToLower(args.String("options"))
		for _, spec := range vpnIpsecSettingsFields() {
			if spec.Name != name {
				continue
			}
			var rows [][]string
			for _, option := range form.Options(spec.field) {
				rows = append(rows, []string{option.Key, strings.TrimSpace(option.Description), YesNo(Flag(option.Selected))})
			}
			c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		}
		return nil
	}
	var present = vpnIpsecSettingsPresent(form)
	if args.Bool("json") {
		var values = map[string]string{}
		for _, spec := range present {
			values[spec.field] = form.Value(spec.field)
		}
		return c.JSON(values)
	}
	var values = form.Values()
	c.Fields(vpnIpsecDetail(values, func(field string) string { return values[field] }, form, present))
	return nil
}

func vpnIpsecSettingsSet(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var specs = vpnIpsecSettingsFields()
	var fields, fieldsErr = vpnIpsecFieldsOf(api, args, specs, vpnIpsecSettingsForm)
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one setting like threads= (type \"set ?\" for help)")
	}
	return vpnIpsecValidationArgs(api.SettingsUpdate(fields), "ipsec.", specs)
}
