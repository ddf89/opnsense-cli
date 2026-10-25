package ipsec

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The settings of VPN > IPsec > Mobile & Advanced Settings (api/ipsec/settings): general options and the
// strongSwan (charon) daemon options, plugins (attr for mobile clients, eap-radius, xauth-pam) and log levels.
// Field names are the API paths below "ipsec" joined with dots, e.g. "charon.syslog.daemon.ike"

// SettingsLogLevelFields are the charon log subsystems, each "charon.syslog.daemon.<name>" takes -1 (silent) to 4
var SettingsLogLevelFields = []string{"app", "asn", "cfg", "chd", "dmn", "enc", "esp", "ike", "imc", "imv", "job",
	"knl", "lib", "mgr", "net", "pts", "tls", "tnc"}

// SettingsFieldNames are the writable settings. general.enabled (IPsec on/off) is not among them, it is a link to
// the legacy ipsec/enable flag: see IsEnabled / SetEnabled
var SettingsFieldNames = func() []string {
	var names = []string{
		"general.preferred_oldsa", "general.disablevpnrules", "general.passthrough_networks", "general.user_source",
		"general.local_group",
		"charon.max_ikev1_exchanges", "charon.threads", "charon.ikesa_table_size", "charon.ikesa_table_segments",
		"charon.init_limit_half_open", "charon.ignore_acquire_ts", "charon.install_routes", "charon.cisco_unity",
		"charon.make_before_break", "charon.retransmit_tries", "charon.retransmit_timeout", "charon.retransmit_base",
		"charon.retransmit_jitter", "charon.retransmit_limit", "charon.reqid_base", "charon.retry_initiate_interval",
		"charon.syslog.daemon.ike_name", "charon.syslog.daemon.log_level",
	}
	for _, subsystem := range SettingsLogLevelFields {
		names = append(names, "charon.syslog.daemon."+subsystem)
	}
	return append(names,
		"charon.plugins.attr.subnet", "charon.plugins.attr.split-include", "charon.plugins.attr.x_28674",
		"charon.plugins.attr.x_28675", "charon.plugins.attr.x_28672", "charon.plugins.attr.x_28673",
		"charon.plugins.attr.x_28679", "charon.plugins.attr.dns", "charon.plugins.attr.nbns",
		"charon.plugins.eap-radius.servers", "charon.plugins.eap-radius.accounting", "charon.plugins.eap-radius.class_group",
		"charon.plugins.xauth-pam.pam_service", "charon.plugins.xauth-pam.session", "charon.plugins.xauth-pam.trim_email",
	)
}()

// SettingsGet returns the settings with their option lists (authentication servers, groups, log levels, ...).
// Fields this OPNsense version does not know are missing
func (opn *IPsecApi) SettingsGet() (Form, error) {
	var form, err = opn.getForm(opn.endpoint("settings", "get"), "ipsec")
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, errors.New("unexpected answer from ipsec/settings/get: no settings")
	}
	return form, nil
}

// SettingsUpdate changes the given settings (see SettingsFieldNames), the others are kept. An empty value clears
// a field. Returns *ValidationError when OPNsense refuses a value (fields named like "ipsec.charon.threads")
func (opn *IPsecApi) SettingsUpdate(fields Fields) error {
	if len(fields) == 0 {
		return errors.New("no settings to change")
	}
	var body = map[string]any{}
	for name, value := range fields {
		if !slices.Contains(SettingsFieldNames, name) {
			return fmt.Errorf("unknown ipsec setting %q", name)
		}
		var node = body
		var path = strings.Split(name, ".")
		for _, segment := range path[:len(path)-1] {
			var child, exists = node[segment].(map[string]any)
			if !exists {
				child = map[string]any{}
				node[segment] = child
			}
			node = child
		}
		node[path[len(path)-1]] = value
	}
	var _, err = opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"ipsec": body})
	return err
}
