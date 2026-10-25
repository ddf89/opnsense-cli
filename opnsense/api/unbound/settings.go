package unbound

import (
	"opnsense-cli/opnsense/api/internal/dnsmodel"
)

// Settings are the plain settings of Unbound (api/unbound/settings/get|set): API names below the model root,
// like "general.port", "advanced.prefetch", "acls.default_action" or "forwarding.enabled". Booleans are "1"/"0",
// option fields (general.active_interface, advanced.logverbosity, ...) the comma separated selected keys with
// their choices in Options
type Settings = dnsmodel.Settings

// settingsArrays are the record lists of the model, they are not settings
var settingsArrays = []string{"acls.acl", "dnsbl", "dots", "hosts", "aliases"}

// SettingsGet returns the plain settings of all sections (general, advanced, acls, forwarding)
func (opn *UnboundApi) SettingsGet() (Settings, error) {
	return opn.settings("unbound", settingsArrays...)
}

// settings flattens the settings below root (like "unbound.general"), names relative to root
func (opn *UnboundApi) settings(root string, skip ...string) (Settings, error) {
	return dnsmodel.GetSettings(opn.OPNsense, opn.settingsEndpoint("get"), root, skip...)
}

// SettingsSet changes the settings of patch (names like "general.port", see Settings), the others are kept.
// Only saved: ServiceReconfigure applies them (ServiceReconfigureGeneral for the general settings)
func (opn *UnboundApi) SettingsSet(patch Patch) error {
	return dnsmodel.SetSettings(opn.OPNsense, opn.settingsEndpoint("set"), "unbound", patch)
}
