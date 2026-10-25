package openvpn

import (
	coreapi "opnsense-cli/opnsense/api"
)

// OpenVPNApi wraps the OPNsense OpenVPN API behind VPN > OpenVPN (api/openvpn/instances, client_overwrites,
// service, export), the MVC instances replaced the legacy servers / clients pages
//
//goland:noinspection GoNameStartsWithPackageName
type OpenVPNApi struct {
	*coreapi.OPNsense
}

func (opn *OpenVPNApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("openvpn", controller, method)
}
