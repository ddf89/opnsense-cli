package cmd

import (
	"fmt"
	"log"
	"net"
	opnsenseapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var unboundHostOverrideCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an Unbound Host Override, replaces the entry with the same FQDN and record type if there is one",
	Long: `Create an Unbound Host Override.
If there already is an entry with the same host, domain and record type, it is replaced: all fields are set
from the flags, flags not given are reset to their defaults.`,
	Run: hostOverrideCreateUpdateRun,
}

var unboundHostOverrideUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing Unbound Host Override by uuid or FQDN and record type",
	Long: `Update an existing Unbound Host Override, found by --uuid or by --host, --domain and --rr.
Only the given flags are changed, all other values are kept.`,
	Run: hostOverrideCreateUpdateRun,
}

func init() {
	setupUnboundHostOverrideCreateUpdateCommand(unboundHostOverrideCreateCmd)
	setupUnboundHostOverrideCreateUpdateCommand(unboundHostOverrideUpdateCmd)
	unboundHostOverrideUpdateCmd.Flags().StringVarP(&HOSTOVERRIDEuuid, "uuid", "", "", "update the entry with this uuid instead of looking it up by host / domain / rr")
	_ = unboundHostOverrideCreateCmd.MarkFlagRequired("host")
	_ = unboundHostOverrideCreateCmd.MarkFlagRequired("domain")
	unboundHostOverrideCmd.AddCommand(unboundHostOverrideCreateCmd)
	unboundHostOverrideCmd.AddCommand(unboundHostOverrideUpdateCmd)
}

func setupUnboundHostOverrideCreateUpdateCommand(command *cobra.Command) {
	command.Flags().StringVarP(&HOSTOVERRIDEhost, "host", "", "", "the host part")
	command.Flags().StringVarP(&HOSTOVERRIDEdomain, "domain", "", "", "the domain part")
	command.Flags().StringVarP(&HOSTOVERRIDErr, "rr", "", "A", "Record type: A, AAAA, MX or TXT")
	command.Flags().StringVarP(&HOSTOVERRIDEip, "ip", "", "", "the IP address, IPv4 like 10.10.10.10 for A, IPv6 for AAAA. Required for A and AAAA")
	command.Flags().StringVarP(&HOSTOVERRIDEmxprio, "mxprio", "", "", "MX priority, a number. Required for MX")
	command.Flags().StringVarP(&HOSTOVERRIDEmx, "mx", "", "", "MX host like mail.domain.tld. Required for MX")
	command.Flags().StringVarP(&HOSTOVERRIDEtxtdata, "txtdata", "", "", "TXT record content. Required for TXT")
	command.Flags().StringVarP(&HOSTOVERRIDEttl, "ttl", "", "", "TTL in seconds, defaults to empty (Unbound default)")
	command.Flags().StringVarP(&HOSTOVERRIDEaddptr, "addptr", "", "1", "Also create a PTR record for A / AAAA: 1 (true) by default, 0 to disable")
	command.Flags().StringVarP(&HOSTOVERRIDEdescription, "description", "", "", "Entry description")
	command.Flags().StringVarP(&HOSTOVERRIDEnabled, "enabled", "", "1", "Should the entry be enabled. 1 (true) by default")

}

// validateHostOverride checks the fields required by the record type, other record types are validated by OPNsense
func validateHostOverride(hostOverride unbound.HostOverride) error {
	switch hostOverride.Rr {
	case "A", "AAAA":
		var ip = net.ParseIP(hostOverride.Ip)
		if ip == nil {
			return fmt.Errorf("please set --ip to a valid IP address for %s records, got: %q", hostOverride.Rr, hostOverride.Ip)
		}
		// OPNsense accepts an IPv4 address for AAAA records, so check the address family ourselves
		var isIPv6 = strings.Contains(hostOverride.Ip, ":")
		if hostOverride.Rr == "A" && isIPv6 {
			return fmt.Errorf("an A record needs an IPv4 address, got: %s", hostOverride.Ip)
		}
		if hostOverride.Rr == "AAAA" && !isIPv6 {
			return fmt.Errorf("an AAAA record needs an IPv6 address, got: %s", hostOverride.Ip)
		}
	case "MX":
		if hostOverride.Mx == "" || hostOverride.Mxprio == "" {
			return fmt.Errorf("please set --mx and --mxprio for MX records")
		}
		if _, err := strconv.Atoi(hostOverride.Mxprio); err != nil {
			return fmt.Errorf("--mxprio must be a number, got: %s", hostOverride.Mxprio)
		}
	case "TXT":
		if hostOverride.Txtdata == "" {
			return fmt.Errorf("please set --txtdata for TXT records")
		}
	}

	if hostOverride.Ip != "" && (hostOverride.Rr == "MX" || hostOverride.Rr == "TXT") {
		return fmt.Errorf("--ip is only used for A and AAAA records, not for %s", hostOverride.Rr)
	}
	return nil
}

// hostOverrideFromFlags sets all fields given on the command line, with allFields also the defaults of the flags not given
func hostOverrideFromFlags(command *cobra.Command, hostOverride *unbound.HostOverride, allFields bool) {
	var fields = []struct {
		flag  string
		value string
		field *string
	}{
		{"host", HOSTOVERRIDEhost, &hostOverride.Host},
		{"domain", HOSTOVERRIDEdomain, &hostOverride.Domain},
		{"rr", strings.ToUpper(HOSTOVERRIDErr), &hostOverride.Rr},
		{"ip", HOSTOVERRIDEip, &hostOverride.Ip},
		{"mxprio", HOSTOVERRIDEmxprio, &hostOverride.Mxprio},
		{"mx", HOSTOVERRIDEmx, &hostOverride.Mx},
		{"txtdata", HOSTOVERRIDEtxtdata, &hostOverride.Txtdata},
		{"ttl", HOSTOVERRIDEttl, &hostOverride.Ttl},
		{"addptr", HOSTOVERRIDEaddptr, &hostOverride.Addptr},
		{"description", HOSTOVERRIDEdescription, &hostOverride.Description},
		{"enabled", HOSTOVERRIDEnabled, &hostOverride.Enabled},
	}
	for _, field := range fields {
		if allFields || command.Flags().Changed(field.flag) {
			*field.field = field.value
		}
	}

	// switching an existing entry to MX / TXT: drop its IP, OPNsense would still validate it
	if !allFields && (hostOverride.Rr == "MX" || hostOverride.Rr == "TXT") && !command.Flags().Changed("ip") {
		hostOverride.Ip = ""
	}
}

func hostOverrideCreateUpdateRun(command *cobra.Command, _ []string) {
	var unboundApi = unbound.UnboundApi{OPNsense: GetOPNsenseApi()}
	var isCreate = command.Name() == "create"

	var existing unbound.HostOverride
	var err error
	if HOSTOVERRIDEuuid != "" {
		existing, err = unboundApi.HostOverrideGet(HOSTOVERRIDEuuid)
		if err != nil {
			log.Fatal(err)
		}
	} else { // no uuid given, update the entry with the same FQDN and record type if there is one
		if HOSTOVERRIDEhost == "" || HOSTOVERRIDEdomain == "" {
			log.Fatal("Please either set host and domain or set uuid")
		}
		existing, err = unboundApi.HostOverrideGetByFQDNAndRr(HOSTOVERRIDEhost, HOSTOVERRIDEdomain, strings.ToUpper(HOSTOVERRIDErr))
		if err == nil && isCreate {
			log.Printf("Found entry with same FQDN and record type, replacing uuid: %s", existing.Uuid)
		} else if err != nil && (!isCreate || !opnsenseapi.IsNotFound(err)) {
			log.Fatal(hostOverrideLookupError(err))
		}
	}

	// create sets the complete entry, update keeps all values not given on the command line
	var isNew = existing.Uuid == ""
	var hostOverride = existing
	hostOverrideFromFlags(command, &hostOverride, isCreate)

	if err := validateHostOverride(hostOverride); err != nil {
		log.Fatal(err)
	}

	if isNew {
		var uuid, err = unboundApi.HostOverrideCreate(hostOverride)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Created successfully, uuid: %s\n", uuid)
	} else {
		var uuid, err = unboundApi.HostOverrideUpdate(hostOverride)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Updated successfully, uuid: %s\n", uuid)
	}
}
