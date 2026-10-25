package cmd

import (
	"errors"
	"fmt"
	"log"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"os"

	"github.com/spf13/cobra"
)

var dnsmasqHostCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a Dnsmasq host override, an existing entry with the same host / domain is overwritten",
	Long: `Create a Dnsmasq host override / DHCP reservation and print its uuid.

If an entry with the same host and domain exists, it is updated instead and all its fields are
replaced by the given flags (fields without a flag are cleared), so running create twice is idempotent.
Use "update" to change single fields.`,
	Args: cobra.NoArgs,
	Run:  dnsmasqHostCreateRun,
}

func init() {
	dnsmasqHostCreateCmd.Flags().StringVar(&dnsmasqHostHost, "host", "", "hostname (required)")
	dnsmasqHostCreateCmd.Flags().StringVar(&dnsmasqHostDomain, "domain", "", "domain of the host")
	dnsmasqHostSetupFieldFlags(dnsmasqHostCreateCmd)
	_ = dnsmasqHostCreateCmd.MarkFlagRequired("host")

	dnsmasqHostCmd.AddCommand(dnsmasqHostCreateCmd)
}

func dnsmasqHostCreateRun(cmd *cobra.Command, _ []string) {
	var fields = dnsmasqHostFieldsFromFlags(cmd, false)
	var host = dnsmasq.Host{
		Host:        dnsmasqHostHost,
		Domain:      dnsmasqHostDomain,
		Local:       fields["local"],
		Ip:          fields["ip"],
		Cnames:      fields["cnames"],
		ClientId:    fields["client_id"],
		Hwaddr:      fields["hwaddr"],
		LeaseTime:   fields["lease_time"],
		Ignore:      fields["ignore"],
		Description: fields["descr"],
		Comments:    fields["comments"],
		Aliases:     fields["aliases"],
	}

	var uuid, updated, err = newDnsmasqHostApi().HostCreateOrUpdate(host)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%v, please update one with \"update --uuid\" or remove the duplicates", err)
	}
	if err != nil {
		log.Fatal(err)
	}
	if updated {
		_, _ = fmt.Fprintf(os.Stderr, "Found entry with same FQDN %s, updated it\n", host.FQDN())
	}
	fmt.Println(uuid)
}
