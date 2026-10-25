package cmd

import (
	"errors"
	"fmt"
	"log"
	"net"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	dnsmasqHostUuid        string
	dnsmasqHostHost        string
	dnsmasqHostDomain      string
	dnsmasqHostNewHost     string
	dnsmasqHostNewDomain   string
	dnsmasqHostIps         []string
	dnsmasqHostCnames      []string
	dnsmasqHostAliases     []string
	dnsmasqHostHwaddrs     []string
	dnsmasqHostClientId    string
	dnsmasqHostLeaseTime   string
	dnsmasqHostLocal       bool
	dnsmasqHostIgnore      bool
	dnsmasqHostDescription string
	dnsmasqHostComments    string
	dnsmasqHostSearch      string
)

var dnsmasqHostCmd = &cobra.Command{
	Use:   "host",
	Short: "Manage Dnsmasq host overrides and DHCP reservations",
}

func init() {
	dnsmasqCmd.AddCommand(dnsmasqHostCmd)
}

func newDnsmasqHostApi() *dnsmasq.DnsmasqApi {
	return &dnsmasq.DnsmasqApi{OPNsense: GetOPNsenseApi()}
}

// dnsmasqHostSetupLookupFlags adds --uuid / --host / --domain to select an existing entry
func dnsmasqHostSetupLookupFlags(command *cobra.Command) {
	command.Flags().StringVar(&dnsmasqHostUuid, "uuid", "", "select the entry by uuid")
	command.Flags().StringVar(&dnsmasqHostHost, "host", "", "select the entry by hostname (exact, case-insensitive)")
	command.Flags().StringVar(&dnsmasqHostDomain, "domain", "", "domain of the entry selected by --host, omit for entries without domain")
}

// dnsmasqHostSetupFieldFlags adds the flags for all writable fields except host / domain
func dnsmasqHostSetupFieldFlags(command *cobra.Command) {
	command.Flags().StringSliceVar(&dnsmasqHostIps, "ip", nil, "IPv4/IPv6 address, repeat or comma separate for multiple")
	command.Flags().StringSliceVar(&dnsmasqHostCnames, "cname", nil, "CNAME pointing to this host, repeat or comma separate for multiple")
	command.Flags().StringSliceVar(&dnsmasqHostAliases, "alias", nil, "additional name of this host, repeat or comma separate for multiple")
	command.Flags().StringSliceVar(&dnsmasqHostHwaddrs, "hwaddr", nil, "MAC address for a DHCP reservation, repeat or comma separate for multiple")
	command.Flags().StringVar(&dnsmasqHostClientId, "client-id", "", "DHCP client identifier for the reservation")
	command.Flags().StringVar(&dnsmasqHostLeaseTime, "lease-time", "", "DHCP lease time in seconds")
	command.Flags().BoolVar(&dnsmasqHostLocal, "local", false, "the domain is local, answer only from hosts / DHCP")
	command.Flags().BoolVar(&dnsmasqHostIgnore, "ignore", false, "ignore DHCP requests of this client")
	command.Flags().StringVar(&dnsmasqHostDescription, "description", "", "entry description")
	command.Flags().StringVar(&dnsmasqHostComments, "comments", "", "entry comments")
}

// dnsmasqHostFieldsFromFlags returns the field flags as API fields. With onlyChanged only explicitly set flags are
// returned, an explicitly empty list flag (--ip "") clears the field
func dnsmasqHostFieldsFromFlags(command *cobra.Command, onlyChanged bool) dnsmasq.HostFields {
	var fields = dnsmasq.HostFields{}
	var set = func(flag string, field string, value string) {
		if !onlyChanged || command.Flags().Changed(flag) {
			fields[field] = value
		}
	}

	set("ip", "ip", dnsmasqHostJoinList("--ip", dnsmasqHostIps, dnsmasqHostValidateIp))
	set("cname", "cnames", dnsmasqHostJoinList("--cname", dnsmasqHostCnames, nil))
	set("alias", "aliases", dnsmasqHostJoinList("--alias", dnsmasqHostAliases, nil))
	set("hwaddr", "hwaddr", dnsmasqHostJoinList("--hwaddr", dnsmasqHostHwaddrs, dnsmasqHostValidateMac))
	set("client-id", "client_id", dnsmasqHostClientId)
	set("lease-time", "lease_time", dnsmasqHostValidateLeaseTime(dnsmasqHostLeaseTime))
	set("local", "local", strconv.Itoa(BoolToInt(dnsmasqHostLocal)))
	set("ignore", "ignore", strconv.Itoa(BoolToInt(dnsmasqHostIgnore)))
	set("description", "descr", dnsmasqHostDescription)
	set("comments", "comments", dnsmasqHostComments)
	return fields
}

// dnsmasqHostJoinList trims, validates / normalizes and comma joins the values of a list flag
func dnsmasqHostJoinList(flag string, values []string, normalize func(string) (string, error)) string {
	var cleaned = make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if normalize != nil {
			var normalized, err = normalize(value)
			if err != nil {
				log.Fatalf("invalid %s value %q: %v", flag, value, err)
			}
			value = normalized
		}
		cleaned = append(cleaned, value)
	}
	return strings.Join(cleaned, ",")
}

func dnsmasqHostValidateIp(value string) (string, error) {
	var ip = net.ParseIP(value)
	if ip == nil {
		return "", errors.New("not an IPv4 or IPv6 address")
	}
	return ip.String(), nil
}

func dnsmasqHostValidateMac(value string) (string, error) {
	var mac, err = net.ParseMAC(value)
	if err != nil {
		return "", errors.New("not a MAC address like aa:bb:cc:dd:ee:ff")
	}
	return mac.String(), nil
}

func dnsmasqHostValidateLeaseTime(value string) string {
	if value == "" {
		return value
	}
	if seconds, err := strconv.Atoi(value); err != nil || seconds < 0 {
		log.Fatalf("invalid --lease-time value %q: must be a number of seconds", value)
	}
	return value
}

// dnsmasqHostLookup returns the entry selected by --uuid or --host / --domain, exits on errors
func dnsmasqHostLookup(api *dnsmasq.DnsmasqApi) dnsmasq.Host {
	var host, err = dnsmasqHostFind(api, dnsmasqHostUuid, dnsmasqHostHost, dnsmasqHostDomain)
	if err != nil {
		log.Fatal(err)
	}
	return host
}

func dnsmasqHostFind(api *dnsmasq.DnsmasqApi, uuid string, hostname string, domain string) (dnsmasq.Host, error) {
	if uuid != "" {
		return api.HostGet(uuid)
	}
	if hostname == "" {
		return dnsmasq.Host{}, errors.New("please set either --uuid or --host (and --domain)")
	}

	var host, err = api.HostGetByFQDN(hostname, domain)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		return host, fmt.Errorf("%w, please select one with --uuid", err)
	}
	return host, err
}

func dnsmasqHostYesNo(value string) string {
	if value == "1" {
		return "yes"
	}
	return "no"
}
