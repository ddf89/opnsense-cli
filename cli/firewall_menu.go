package cli

import (
	"opnsense-cli/opnsense/api/firewall"
)

// Shared parts of the /firewall menus: alias, rule, nat/*, group, category, shaper/*, state, log

func init() {
	Root.Menu("firewall").Help = "aliases, rules, NAT, groups, categories, shaper, states and log (Firewall)"
	Root.Menu("firewall/nat").Help = "source, destination (port forward), one-to-one and NPTv6 NAT (Firewall > NAT)"
}

// firewallApi returns the firewall configuration API on the session's connection
func firewallApi(c *Context) (*firewall.FirewallApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &firewall.FirewallApi{OPNsense: opn}, nil
}
