package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var dnsmasqHostUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update fields of an existing Dnsmasq host override",
	Long: `Update an existing Dnsmasq host override selected by --uuid or --host / --domain and print its uuid.

Only the flags given are changed, all other fields are kept. Clear a field with an empty value, e.g. --cname "".
To rename an entry use --new-host / --new-domain, or select it by --uuid and pass the new --host / --domain.`,
	Args: cobra.NoArgs,
	Run:  dnsmasqHostUpdateRun,
}

func init() {
	dnsmasqHostSetupLookupFlags(dnsmasqHostUpdateCmd)
	dnsmasqHostUpdateCmd.Flags().StringVar(&dnsmasqHostNewHost, "new-host", "", "rename the entry to this hostname")
	dnsmasqHostUpdateCmd.Flags().StringVar(&dnsmasqHostNewDomain, "new-domain", "", "move the entry to this domain (\"\" removes the domain)")
	dnsmasqHostSetupFieldFlags(dnsmasqHostUpdateCmd)

	dnsmasqHostCmd.AddCommand(dnsmasqHostUpdateCmd)
}

func dnsmasqHostUpdateRun(cmd *cobra.Command, _ []string) {
	var api = newDnsmasqHostApi()
	var fields = dnsmasqHostFieldsFromFlags(cmd, true)
	var flags = cmd.Flags()

	var uuid = dnsmasqHostUuid
	if uuid != "" {
		// selected by uuid, so --host / --domain are new values
		if flags.Changed("host") && flags.Changed("new-host") || flags.Changed("domain") && flags.Changed("new-domain") {
			log.Fatal("with --uuid use either --host / --domain or --new-host / --new-domain to rename")
		}
		if flags.Changed("host") {
			fields["host"] = dnsmasqHostHost
		}
		if flags.Changed("domain") {
			fields["domain"] = dnsmasqHostDomain
		}
	} else {
		uuid = dnsmasqHostLookup(api).Uuid
	}
	if flags.Changed("new-host") {
		fields["host"] = dnsmasqHostNewHost
	}
	if flags.Changed("new-domain") {
		fields["domain"] = dnsmasqHostNewDomain
	}

	if len(fields) == 0 {
		log.Fatal("nothing to update, please set at least one field flag")
	}
	if host, isset := fields["host"]; isset && host == "" {
		log.Fatal("the hostname must not be empty")
	}

	if err := api.HostUpdate(uuid, fields); err != nil {
		log.Fatal(err)
	}
	fmt.Println(uuid)
}
