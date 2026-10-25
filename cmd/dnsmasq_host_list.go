package cmd

import (
	"log"
	"strings"

	"github.com/spf13/cobra"
)

var dnsmasqHostListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Dnsmasq host overrides",
	Args:  cobra.NoArgs,
	Run:   dnsmasqHostListRun,
}

func init() {
	dnsmasqHostListCmd.Flags().StringVar(&dnsmasqHostSearch, "search", "", "only list entries containing this phrase in any column")
	dnsmasqHostCmd.AddCommand(dnsmasqHostListCmd)
}

func dnsmasqHostListRun(_ *cobra.Command, _ []string) {
	var hosts, err = newDnsmasqHostApi().HostList(dnsmasqHostSearch)
	if err != nil {
		log.Fatal(err)
	}

	var rows = make([][]string, 0, len(hosts))
	for _, host := range hosts {
		rows = append(rows, []string{
			host.Uuid,
			host.Host,
			host.Domain,
			strings.ReplaceAll(host.Ip, ",", ", "),
			strings.ReplaceAll(host.Hwaddr, ",", ", "),
			strings.ReplaceAll(host.Cnames, ",", ", "),
			host.Description,
		})
	}
	printTable([]string{"UUID", "HOST", "DOMAIN", "IP", "HWADDR", "CNAMES", "DESCRIPTION"}, rows)
}
