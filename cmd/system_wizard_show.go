package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemWizardShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the settings of the setup wizard (general, DNS, WAN, LAN), passwords are never shown",
	Args:  cobra.NoArgs,
	Run:   systemWizardShowRun,
}

func init() {
	systemWizardCmd.AddCommand(systemWizardShowCmd)
}

func systemWizardShowRun(_ *cobra.Command, _ []string) {
	var systemApi = system.SystemApi{OPNsense: GetOPNsenseApi()}

	var wizard, err = systemApi.WizardGet()
	if err != nil {
		log.Fatal(err)
	}

	printFields([][2]string{
		{"hostname", wizard.Hostname},
		{"domain", wizard.Domain},
		{"language", wizard.Language},
		{"timezone", wizard.Timezone},
		{"dns_servers", wizard.DnsServers},
		{"dnsallowoverride", wizard.DnsAllowOverride},
		{"unbound.enabled", wizard.Unbound.Enabled},
		{"unbound.dnssec", wizard.Unbound.Dnssec},
		{"unbound.dnssecstripped", wizard.Unbound.DnssecStripped},
		{"wan.disable", wizard.Wan.Disable},
		{"wan.ipv4_type", wizard.Wan.Ipv4Type},
		{"wan.ipaddr", wizard.Wan.Ipaddr},
		{"wan.gateway", wizard.Wan.Gateway},
		{"wan.dhcphostname", wizard.Wan.DhcpHostname},
		{"wan.pppoe_username", wizard.Wan.PppoeUsername},
		{"wan.pppoe_provider", wizard.Wan.PppoeProvider},
		{"wan.spoofmac", wizard.Wan.SpoofMac},
		{"wan.mtu", wizard.Wan.Mtu},
		{"wan.mss", wizard.Wan.Mss},
		{"wan.blockpriv", wizard.Wan.BlockPriv},
		{"wan.blockbogons", wizard.Wan.BlockBogons},
		{"lan.ipaddr", wizard.Lan.Ipaddr},
		{"lan.disable", wizard.Lan.Disable},
		{"lan.configure_dhcp", wizard.Lan.ConfigureDhcp},
		{"deployment_type.multiwan", wizard.DeploymentType.Multiwan},
		{"deployment_type.dhcp_dns_registration", wizard.DeploymentType.DhcpDnsRegistration},
		{"deployment_type.maxthreads", wizard.DeploymentType.Maxthreads},
	})
}
