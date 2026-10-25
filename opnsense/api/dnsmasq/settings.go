package dnsmasq

import (
	"opnsense-cli/opnsense/api/internal/dnsmodel"
)

// Settings are the general settings of Dnsmasq (api/dnsmasq/settings/get|set): API field name to value, the DHCP
// ones prefixed "dhcp." (like "dhcp.domain"). Booleans are "1"/"0", option fields (interface, add_mac,
// dhcp.no_interface) the comma separated selected keys with their choices in Options
type Settings = dnsmodel.Settings

// settingsArrays are the record lists of the model, they are not settings
var settingsArrays = []string{"hosts", "domainoverrides", "dhcp_tags", "dhcp_ranges", "dhcp_options", "dhcp_boot"}

// SettingsGet returns the general settings
func (opn *DnsmasqApi) SettingsGet() (Settings, error) {
	return dnsmodel.GetSettings(opn.OPNsense, opn.settingsEndpoint("get"), "dnsmasq", settingsArrays...)
}

// SettingsSet changes the settings of patch (API names like "port" or "dhcp.domain"), the others are kept. Only
// saved, ServiceReconfigure applies them
func (opn *DnsmasqApi) SettingsSet(patch Patch) error {
	return dnsmodel.SetSettings(opn.OPNsense, opn.settingsEndpoint("set"), "dnsmasq", patch)
}
