package firewall

import (
	coreapi "opnsense-cli/opnsense/api"
)

// FirewallApi wraps the OPNsense firewall configuration APIs behind the Firewall menu (api/firewall/alias,
// alias_util, filter, source_nat, d_nat, one_to_one, npt, group, category and api/trafficshaper). The live
// diagnostics (log, states, statistics) are in package diagnostics
//
//goland:noinspection GoNameStartsWithPackageName
type FirewallApi struct {
	*coreapi.OPNsense
}

func (opn *FirewallApi) endpoint(module string, controller string, method string) string {
	return opn.EndpointForPluginControllerMethod(module, controller, method)
}
