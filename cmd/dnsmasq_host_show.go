package cmd

import (
	"github.com/spf13/cobra"
)

var dnsmasqHostShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a Dnsmasq host override selected by --uuid or --host / --domain",
	Args:  cobra.NoArgs,
	Run:   dnsmasqHostShowRun,
}

func init() {
	dnsmasqHostSetupLookupFlags(dnsmasqHostShowCmd)
	dnsmasqHostCmd.AddCommand(dnsmasqHostShowCmd)
}

func dnsmasqHostShowRun(_ *cobra.Command, _ []string) {
	var host = dnsmasqHostLookup(newDnsmasqHostApi())

	printFields([][2]string{
		{"UUID", host.Uuid},
		{"Host", host.Host},
		{"Domain", host.Domain},
		{"IP", host.Ip},
		{"CNAMEs", host.Cnames},
		{"Aliases", host.Aliases},
		{"HW address", host.Hwaddr},
		{"Client ID", host.ClientId},
		{"Lease time", host.LeaseTime},
		{"Local", dnsmasqHostYesNo(host.Local)},
		{"Ignore", dnsmasqHostYesNo(host.Ignore)},
		{"Tag", host.SetTag},
		{"Description", host.Description},
		{"Comments", host.Comments},
	})
}
