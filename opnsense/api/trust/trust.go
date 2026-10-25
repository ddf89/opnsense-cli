package trust

import (
	coreapi "opnsense-cli/opnsense/api"
)

// TrustApi wraps the OPNsense API behind System > Trust (api/trust/ca, cert, crl, settings): certificate
// authorities, certificates, revocation lists and the trust store settings
//
//goland:noinspection GoNameStartsWithPackageName
type TrustApi struct {
	*coreapi.OPNsense
}

func (opn *TrustApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("trust", controller, method)
}
