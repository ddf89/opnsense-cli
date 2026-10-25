package cmd

import (
	"errors"
	"log"
	"net"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	// lookup flags of update / show / rm, --domain and --ip are the values on create
	dnsmasqDomainUuid   string
	dnsmasqDomainDomain string
	dnsmasqDomainIp     string
	// new values on update
	dnsmasqDomainNewDomain string
	dnsmasqDomainNewIp     string
	// field flags of create / update
	dnsmasqDomainPort        string
	dnsmasqDomainSrcip       string
	dnsmasqDomainSequence    string
	dnsmasqDomainDescription string
	// list filter
	dnsmasqDomainSearch string
)

var dnsmasqDomainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Manage Dnsmasq domain overrides (forward a domain to a specific DNS server)",
}

func init() {
	dnsmasqCmd.AddCommand(dnsmasqDomainCmd)
}

func dnsmasqDomainApi() *dnsmasq.DnsmasqApi {
	return &dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}
}

// dnsmasqDomainAddLookupFlags adds --uuid / --domain / --ip used to select a single entry
func dnsmasqDomainAddLookupFlags(command *cobra.Command) {
	command.Flags().StringVarP(&dnsmasqDomainUuid, "uuid", "", "", "select the entry by uuid")
	command.Flags().StringVarP(&dnsmasqDomainDomain, "domain", "", "", "select the entry by domain (exact match, case-insensitive)")
	command.Flags().StringVarP(&dnsmasqDomainIp, "ip", "", "", "together with --domain: select the entry forwarding to this server ip")
}

// dnsmasqDomainLookup resolves the lookup flags to a single entry or exits with a helpful message
func dnsmasqDomainLookup(dnsmasqApi *dnsmasq.DnsmasqApi) dnsmasq.DomainOverride {
	if dnsmasqDomainUuid != "" && (dnsmasqDomainDomain != "" || dnsmasqDomainIp != "") {
		log.Fatal("Please use either --uuid or --domain [--ip], not both")
	}
	if dnsmasqDomainUuid == "" && dnsmasqDomainDomain == "" {
		log.Fatal("Please set --uuid or --domain [--ip] to select the entry")
	}

	if dnsmasqDomainUuid != "" {
		var domainOverride, err = dnsmasqApi.DomainOverrideGet(dnsmasqDomainUuid)
		if err != nil {
			log.Fatal(err)
		}
		return domainOverride
	}

	var domainOverride, err = dnsmasqApi.DomainOverrideFind(dnsmasqDomainDomain, dnsmasqDomainIp)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%s\nThe lookup is ambiguous, please select the entry with --uuid (or --ip)", tooMany.Name)
	}
	if err != nil {
		log.Fatal(err)
	}
	return domainOverride
}

// dnsmasqDomainValidateIp exits if value is neither empty nor a valid IPv4/IPv6 address
func dnsmasqDomainValidateIp(flag string, value string) {
	if value != "" && net.ParseIP(value) == nil {
		log.Fatalf("--%s is not a valid IPv4 or IPv6 address (no CIDR, no port): %s", flag, value)
	}
}

// dnsmasqDomainValidateRange exits if value is neither empty nor a number between min and max
func dnsmasqDomainValidateRange(flag string, value string, min int, max int) {
	if value == "" {
		return
	}
	if number, err := strconv.Atoi(value); err != nil || number < min || number > max {
		log.Fatalf("--%s must be a number between %d and %d: %s", flag, min, max, value)
	}
}

// dnsmasqDomainValidateFields checks the field flags shared by create and update
func dnsmasqDomainValidateFields() {
	dnsmasqDomainValidateRange("port", dnsmasqDomainPort, 1, 65535)
	dnsmasqDomainValidateRange("sequence", dnsmasqDomainSequence, 1, 99999)
	dnsmasqDomainValidateIp("srcip", dnsmasqDomainSrcip)
}
