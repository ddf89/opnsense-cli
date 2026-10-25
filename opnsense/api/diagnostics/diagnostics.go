package diagnostics

import (
	coreapi "opnsense-cli/opnsense/api"
)

// DiagnosticsApi wraps the OPNsense diagnostics APIs (api/diagnostics/...): log files, firewall live log, traffic, activity.
// Live views are text/event-stream endpoints, read them with (*coreapi.OPNsense).Stream
//
//goland:noinspection GoNameStartsWithPackageName
type DiagnosticsApi struct {
	*coreapi.OPNsense
}

func (opn *DiagnosticsApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("diagnostics", controller, method)
}
