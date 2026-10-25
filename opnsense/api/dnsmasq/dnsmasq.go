package dnsmasq

import (
	coreapi "opnsense-cli/opnsense/api"
)

// DnsmasqApi wraps the OPNsense Dnsmasq DNS & DHCP API (api/dnsmasq/...), available since OPNsense 25.1
//
//goland:noinspection GoNameStartsWithPackageName
type DnsmasqApi struct {
	*coreapi.OPNsense
}

func (opn *DnsmasqApi) settingsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("dnsmasq", "settings", method)
}
