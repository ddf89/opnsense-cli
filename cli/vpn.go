package cli

import (
	"errors"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// Shared parts of the /vpn menus: /vpn/openvpn (instance, static-key, client-override, session, route, export)

func init() {
	Root.Menu("vpn").Help = "virtual private networks (VPN)"
	Root.Menu("vpn/openvpn").Help = "instances, static keys, client specific overrides, sessions, routes and client export (VPN > OpenVPN)"
}

// openvpnApi returns the OpenVPN API on the session's connection
func openvpnApi(c *Context) (*openvpn.OpenVPNApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &openvpn.OpenVPNApi{OPNsense: opn}, nil
}

// openvpnValidationArgs renames the fields of a validation error of OPNsense ("instance.server") to the
// argument names ("tunnel-network"), so the message names what was typed. argOf maps an API field name (without
// the prefix) to the argument name, "" keeps the API name
func openvpnValidationArgs(err error, prefix string, argOf func(field string) string) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var renamed = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		var name = field
		if rest, found := strings.CutPrefix(field, prefix); found {
			if arg := argOf(rest); arg != "" {
				name = arg
			}
		}
		if previous, exists := renamed[name]; exists {
			message = previous + "; " + message
		}
		renamed[name] = message
	}
	return &coreapi.ValidationError{Validations: renamed}
}
