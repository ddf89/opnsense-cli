package cli

import (
	"opnsense-cli/opnsense/api/system"
)

// /system/wizard: the settings of the setup wizard (System > Wizard). Read-only: the API can only re-apply the
// whole wizard (WAN, LAN incl. DHCP, root password) and reload all services, so there is no set

func init() {
	var menu = Root.Menu("system/wizard")
	menu.Help = "setup wizard settings (System > Wizard), read-only"
	menu.Add(&Command{
		Name: "print",
		Help: "show the settings of the setup wizard (general, DNS, WAN, LAN), passwords are never shown",
		Long: `There is no set: the API always re-applies the whole wizard (WAN, LAN incl. its DHCP range, root
password) and reloads all services. Change the settings in their own menus instead.`,
		Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings as one JSON object"}},
		Run:  systemWizardPrint,
	})
}

// systemWizardFields lists the wizard settings in print order, flags rendered as yes/no
func systemWizardFields(w system.Wizard) [][2]string {
	return [][2]string{
		{"hostname", w.Hostname},
		{"domain", w.Domain},
		{"language", w.Language},
		{"timezone", w.Timezone},
		{"dns-servers", w.DnsServers},
		{"dns-allow-override", YesNo(w.DnsAllowOverride)},
		{"unbound.enabled", YesNo(w.Unbound.Enabled)},
		{"unbound.dnssec", YesNo(w.Unbound.Dnssec)},
		{"unbound.dnssec-stripped", YesNo(w.Unbound.DnssecStripped)},
		{"wan.disable", YesNo(w.Wan.Disable)},
		{"wan.ipv4-type", w.Wan.Ipv4Type},
		{"wan.ipaddr", w.Wan.Ipaddr},
		{"wan.gateway", w.Wan.Gateway},
		{"wan.dhcp-hostname", w.Wan.DhcpHostname},
		{"wan.pppoe-username", w.Wan.PppoeUsername},
		{"wan.pppoe-provider", w.Wan.PppoeProvider},
		{"wan.spoof-mac", w.Wan.SpoofMac},
		{"wan.mtu", w.Wan.Mtu},
		{"wan.mss", w.Wan.Mss},
		{"wan.block-private", YesNo(w.Wan.BlockPriv)},
		{"wan.block-bogons", YesNo(w.Wan.BlockBogons)},
		{"lan.ipaddr", w.Lan.Ipaddr},
		{"lan.disable", YesNo(w.Lan.Disable)},
		{"lan.configure-dhcp", YesNo(w.Lan.ConfigureDhcp)},
		{"deployment-type.multiwan", YesNo(w.DeploymentType.Multiwan)},
		{"deployment-type.dhcp-dns-registration", YesNo(w.DeploymentType.DhcpDnsRegistration)},
		{"deployment-type.maxthreads", w.DeploymentType.Maxthreads},
	}
}

func systemWizardPrint(c *Context, args *Args) error {
	var opn, err = c.Api()
	if err != nil {
		return err
	}
	var api = &system.SystemApi{OPNsense: opn}
	wizard, err := api.WizardGet()
	if err != nil {
		return err
	}

	if args.Bool("json") {
		return c.JSON(systemWizardJSON(wizard))
	}
	c.Fields(systemWizardFields(wizard))
	return nil
}

// systemWizardJSON mirrors the API object (keys and raw values) without its password fields, option lists are
// reduced to the selected keys
func systemWizardJSON(w system.Wizard) map[string]any {
	return map[string]any{
		"hostname":         w.Hostname,
		"domain":           w.Domain,
		"language":         w.Language,
		"timezone":         w.Timezone,
		"dns_servers":      w.DnsServers,
		"dnsallowoverride": w.DnsAllowOverride,
		"unbound":          w.Unbound,
		"interfaces": map[string]any{
			"wan": map[string]string{
				"disable":        w.Wan.Disable,
				"ipv4_type":      w.Wan.Ipv4Type,
				"spoofmac":       w.Wan.SpoofMac,
				"mtu":            w.Wan.Mtu,
				"mss":            w.Wan.Mss,
				"ipaddr":         w.Wan.Ipaddr,
				"gateway":        w.Wan.Gateway,
				"dhcphostname":   w.Wan.DhcpHostname,
				"pppoe_username": w.Wan.PppoeUsername,
				"pppoe_provider": w.Wan.PppoeProvider,
				"blockpriv":      w.Wan.BlockPriv,
				"blockbogons":    w.Wan.BlockBogons,
			},
			"lan": w.Lan,
		},
		"deployment_type": w.DeploymentType,
	}
}
