package cli

import (
	"opnsense-cli/opnsense/api/trust"
)

// Shared parts of the /system/trust menus: authority, certificate, revocation, settings

func init() {
	Root.Menu("system/trust").Help = "certificate authorities, certificates, revocation lists and settings (System > Trust)"
}

// trustApi returns the Trust API on the session's connection
func trustApi(c *Context) (*trust.TrustApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &trust.TrustApi{OPNsense: opn}, nil
}
