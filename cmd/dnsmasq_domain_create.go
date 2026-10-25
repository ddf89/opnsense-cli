package cmd

import (
	"errors"
	"fmt"
	"log"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"

	"github.com/spf13/cobra"
)

var dnsmasqDomainCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a Dnsmasq domain override, or update the one with the same domain and ip",
	Long: `Forward queries for --domain (and its subdomains) to the DNS server --ip[#--port].
Without --ip the domain is answered locally only (from host overrides / leases).

Idempotent: if an entry with the same domain AND the same ip exists, it is updated with the given values
(flags not given are reset to their defaults), otherwise a new entry is created. So one domain can be
forwarded to several servers by running create once per --ip. Prints the uuid.`,
	Run: dnsmasqDomainCreateRun,
}

// dnsmasqDomainCreateSequence is separate from dnsmasqDomainSequence, a shared variable would get the default of update ("")
var dnsmasqDomainCreateSequence string

func init() {
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainDomain, "domain", "", "", "the domain to forward, like corp.lan (required)")
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainIp, "ip", "", "", "the DNS server to forward to (IPv4 or IPv6), empty to answer the domain locally")
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainPort, "port", "", "", "port of the DNS server, empty for 53")
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainSrcip, "srcip", "", "", "source IP address for queries to the DNS server")
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainCreateSequence, "sequence", "", "1", "order of the entry in the generated config, 1-99999")
	dnsmasqDomainCreateCmd.Flags().StringVarP(&dnsmasqDomainDescription, "description", "", "", "Entry description")

	_ = dnsmasqDomainCreateCmd.MarkFlagRequired("domain")

	dnsmasqDomainCmd.AddCommand(dnsmasqDomainCreateCmd)
}

func dnsmasqDomainCreateRun(_ *cobra.Command, _ []string) {
	dnsmasqDomainValidateIp("ip", dnsmasqDomainIp)
	dnsmasqDomainValidateFields()
	dnsmasqDomainValidateRange("sequence", dnsmasqDomainCreateSequence, 1, 99999)
	if dnsmasqDomainCreateSequence == "" {
		log.Fatal("--sequence must not be empty")
	}

	var domainOverride = dnsmasq.DomainOverride{
		Domain:      dnsmasqDomainDomain,
		Ip:          dnsmasqDomainIp,
		Port:        dnsmasqDomainPort,
		Srcip:       dnsmasqDomainSrcip,
		Sequence:    dnsmasqDomainCreateSequence,
		Description: dnsmasqDomainDescription,
	}

	var uuid, created, err = dnsmasqDomainApi().DomainOverrideCreateOrUpdate(domainOverride)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%s\nSeveral entries with the same domain and ip exist, please use update --uuid or remove the duplicates", tooMany.Name)
	}
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("Created domain override for %s", dnsmasqDomainDomain)
	} else {
		log.Printf("Found entry with same domain and ip, updated it")
	}
	fmt.Println(uuid)
}
