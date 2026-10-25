package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqDomainUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a Dnsmasq domain override, only the given flags are changed",
	Long: `Select the entry with --uuid, or with --domain (plus --ip if the domain is forwarded to several servers).
--domain and --ip only select the entry, use --new-domain / --new-ip to change them.
Only explicitly given flags are sent, pass an empty value (e.g. --port "") to clear a field.`,
	Run: dnsmasqDomainUpdateRun,
}

func init() {
	dnsmasqDomainAddLookupFlags(dnsmasqDomainUpdateCmd)
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainNewDomain, "new-domain", "", "", "change the domain")
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainNewIp, "new-ip", "", "", "change the DNS server ip, empty to answer the domain locally")
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainPort, "port", "", "", "port of the DNS server, empty for 53")
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainSrcip, "srcip", "", "", "source IP address for queries to the DNS server")
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainSequence, "sequence", "", "", "order of the entry in the generated config, 1-99999")
	dnsmasqDomainUpdateCmd.Flags().StringVarP(&dnsmasqDomainDescription, "description", "", "", "Entry description")

	dnsmasqDomainCmd.AddCommand(dnsmasqDomainUpdateCmd)
}

func dnsmasqDomainUpdateRun(cmd *cobra.Command, _ []string) {
	var fields dnsmasq.DomainOverrideFields
	var changed = func(flag string, value *string) *string {
		if cmd.Flags().Changed(flag) {
			return value
		}
		return nil
	}
	fields.Domain = changed("new-domain", &dnsmasqDomainNewDomain)
	fields.Ip = changed("new-ip", &dnsmasqDomainNewIp)
	fields.Port = changed("port", &dnsmasqDomainPort)
	fields.Srcip = changed("srcip", &dnsmasqDomainSrcip)
	fields.Sequence = changed("sequence", &dnsmasqDomainSequence)
	fields.Description = changed("description", &dnsmasqDomainDescription)

	if fields == (dnsmasq.DomainOverrideFields{}) {
		log.Fatal("Nothing to update, please set at least one of --new-domain, --new-ip, --port, --srcip, --sequence, --description")
	}
	if fields.Domain != nil && *fields.Domain == "" {
		log.Fatal("--new-domain must not be empty")
	}
	if fields.Sequence != nil && *fields.Sequence == "" {
		log.Fatal("--sequence must not be empty")
	}
	dnsmasqDomainValidateIp("new-ip", dnsmasqDomainNewIp)
	dnsmasqDomainValidateFields()

	var dnsmasqApi = dnsmasqDomainApi()
	var domainOverride = dnsmasqDomainLookup(dnsmasqApi)

	if err := dnsmasqApi.DomainOverrideUpdate(domainOverride.Uuid, fields); err != nil {
		log.Fatal(err)
	}
	fmt.Println(domainOverride.Uuid)
}
