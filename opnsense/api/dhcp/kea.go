package dhcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// Kea DHCP (Services > Kea DHCP, api/kea): the DHCPv4 and DHCPv6 servers with their subnets, reservations, custom
// options, HA peers and (v6) prefix delegation pools, the leases, the control agent and DHCP DDNS settings and the
// kea service. Changes take effect with the reconfigure of KeaService.
//
// Quirks (26.7): a DHCPv6 subnet is refused unless its interface is selected in the DHCPv6 general settings; a
// reservation must be inside its subnet and have exactly one of MAC address / client id (v4) or DUID / MAC (v6);
// DHCPv4 subnets with option_data_autocollect get routers, DNS and NTP servers overwritten with the firewall's
// address in the subnet on every save; search returns the DDNS TSIG secret in clear text

// KeaSubnet4 is a DHCPv4 subnet (kea/dhcpv4 search_subnet). Lists are comma separated, Pools newline separated
// (ranges "a-b" or CIDR), flags "0"/"1"
type KeaSubnet4 struct {
	Base
	Subnet                     string `json:"subnet"`
	Description                string `json:"description"`
	Pools                      string `json:"pools"`
	ValidLifetime              string `json:"valid_lifetime"`
	NextServer                 string `json:"next_server"`
	MatchClientId              string `json:"match-client-id"`
	Allocator                  string `json:"allocator"` // "", iterative, random, flq
	OptionDataAutocollect      string `json:"option_data_autocollect"`
	DomainNameServers          string `json:"option_data.domain_name_servers"`
	DomainSearch               string `json:"option_data.domain_search"`
	Routers                    string `json:"option_data.routers"`
	StaticRoutes               string `json:"option_data.static_routes"`          // dest-ip,router-ip pairs
	ClasslessStaticRoute       string `json:"option_data.classless_static_route"` // net-router pairs, comma separated
	DomainName                 string `json:"option_data.domain_name"`
	NtpServers                 string `json:"option_data.ntp_servers"`
	TimeServers                string `json:"option_data.time_servers"`
	TftpServerName             string `json:"option_data.tftp_server_name"`
	BootFileName               string `json:"option_data.boot_file_name"`
	V6OnlyPreferred            string `json:"option_data.v6_only_preferred"`
	V4Dnr                      string `json:"option_data.v4_dnr"`
	Option                     string `json:"option"` // uuids of KeaOption4
	DdnsForwardZone            string `json:"ddns_forward_zone"`
	DdnsReverseZone            string `json:"ddns_reverse_zone"`
	DdnsQualifyingSuffix       string `json:"ddns_qualifying_suffix"`
	DdnsDnsServer              string `json:"ddns_dns_server"`
	DdnsDnsPort                string `json:"ddns_dns_port"`
	DdnsDomainKeyName          string `json:"ddns_domain_key_name"`
	DdnsDomainKeySecret        string `json:"ddns_domain_key_secret"`
	DdnsDomainKeyAlgorithm     string `json:"ddns_domain_key_algorithm"`
	DdnsOverrideNoUpdate       string `json:"ddns_override_no_update"`
	DdnsOverrideClientUpdate   string `json:"ddns_override_client_update"`
	DdnsUpdateOnRenew          string `json:"ddns_update_on_renew"`
	DdnsConflictResolutionMode string `json:"ddns_conflict_resolution_mode"`
}

// KeaSubnet6 is a DHCPv6 subnet (kea/dhcpv6 search_subnet). With DynamicPrefix the subnet is empty and follows the
// prefix delegated to Interface
type KeaSubnet6 struct {
	Base
	Subnet                     string `json:"subnet"`
	Interface                  string `json:"interface"`
	Description                string `json:"description"`
	Pools                      string `json:"pools"`
	ValidLifetime              string `json:"valid_lifetime"`
	Allocator                  string `json:"allocator"`
	PdAllocator                string `json:"pd-allocator"`
	OptionDataAutocollect      string `json:"option_data_autocollect"`
	DnsServers                 string `json:"option_data.dns_servers"`
	DomainSearch               string `json:"option_data.domain_search"`
	V6Dnr                      string `json:"option_data.v6_dnr"`
	Option                     string `json:"option"` // uuids of KeaOption6
	DynamicPrefix              string `json:"dynamic_prefix"`
	DdnsForwardZone            string `json:"ddns_forward_zone"`
	DdnsReverseZone            string `json:"ddns_reverse_zone"`
	DdnsQualifyingSuffix       string `json:"ddns_qualifying_suffix"`
	DdnsDnsServer              string `json:"ddns_dns_server"`
	DdnsDnsPort                string `json:"ddns_dns_port"`
	DdnsDomainKeyName          string `json:"ddns_domain_key_name"`
	DdnsDomainKeySecret        string `json:"ddns_domain_key_secret"`
	DdnsDomainKeyAlgorithm     string `json:"ddns_domain_key_algorithm"`
	DdnsOverrideNoUpdate       string `json:"ddns_override_no_update"`
	DdnsOverrideClientUpdate   string `json:"ddns_override_client_update"`
	DdnsUpdateOnRenew          string `json:"ddns_update_on_renew"`
	DdnsConflictResolutionMode string `json:"ddns_conflict_resolution_mode"`
}

// KeaReservation4 is a static DHCPv4 lease (kea/dhcpv4 search_reservation). Subnet is the uuid of the subnet,
// SubnetDisplay its network. Exactly one of HwAddress and ClientId identifies the client
type KeaReservation4 struct {
	Base
	Subnet            string `json:"subnet"`
	SubnetDisplay     string `json:"%subnet"`
	IpAddress         string `json:"ip_address"`
	HwAddress         string `json:"hw_address"`
	ClientId          string `json:"client_id"`
	Hostname          string `json:"hostname"`
	Description       string `json:"description"`
	NextServer        string `json:"next_server"`
	DomainNameServers string `json:"option_data.domain_name_servers"`
	DomainSearch      string `json:"option_data.domain_search"`
	Routers           string `json:"option_data.routers"`
	StaticRoutes      string `json:"option_data.static_routes"`
	ClasslessRoutes   string `json:"option_data.classless_static_route"`
	DomainName        string `json:"option_data.domain_name"`
	NtpServers        string `json:"option_data.ntp_servers"`
	TimeServers       string `json:"option_data.time_servers"`
	TftpServerName    string `json:"option_data.tftp_server_name"`
	BootFileName      string `json:"option_data.boot_file_name"`
	Option            string `json:"option"`
}

// KeaReservation6 is a static DHCPv6 lease (kea/dhcpv6 search_reservation): an address and/or a delegated prefix
// for the client with this DUID (or MAC address)
type KeaReservation6 struct {
	Base
	Subnet        string `json:"subnet"`
	SubnetDisplay string `json:"%subnet"`
	IpAddress     string `json:"ip_address"`
	Prefix        string `json:"prefix"`
	Duid          string `json:"duid"`
	HwAddress     string `json:"hw_address"`
	Hostname      string `json:"hostname"`
	DomainSearch  string `json:"domain_search"`
	Option        string `json:"option"`
	Description   string `json:"description"`
}

// KeaPdPool is a DHCPv6 prefix delegation pool (kea/dhcpv6 search_pd_pool): Prefix/PrefixLen is split into
// prefixes of DelegatedLen
type KeaPdPool struct {
	Base
	Subnet        string `json:"subnet"`
	SubnetDisplay string `json:"%subnet"`
	Prefix        string `json:"prefix"`
	PrefixLen     string `json:"prefix_len"`
	DelegatedLen  string `json:"delegated_len"`
	Description   string `json:"description"`
}

// KeaOption is a custom DHCP option (kea/dhcpv4 or dhcpv6 search_option), sent to the subnets and reservations
// that refer to it, optionally only when the client sent MatchCode with MatchData
type KeaOption struct {
	Base
	Code          string `json:"code"`
	CodeDisplay   string `json:"%code"`
	Encoding      string `json:"encoding"` // hex, ipv4-address, ipv6-address, uint8, uint16, uint32, int32, boolean, string, fqdn
	Data          string `json:"data"`
	Force         string `json:"force"`
	MatchCode     string `json:"match_code"`
	MatchEncoding string `json:"match_encoding"`
	MatchData     string `json:"match_data"`
	Description   string `json:"description"`
}

// KeaPeer is a high availability peer (kea/dhcpv4 or dhcpv6 search_peer)
type KeaPeer struct {
	Base
	Name string `json:"name"`
	Role string `json:"role"` // primary or standby
	Url  string `json:"url"`
}

// KeaSubnets4 are the DHCPv4 subnets
func (opn *DhcpApi) KeaSubnets4() *Collection[KeaSubnet4] {
	return newCollection[KeaSubnet4](opn, collectionSpec{"kea", "dhcpv4", "subnet", "subnet4", "kea dhcpv4 subnet", false})
}

// KeaSubnets6 are the DHCPv6 subnets
func (opn *DhcpApi) KeaSubnets6() *Collection[KeaSubnet6] {
	return newCollection[KeaSubnet6](opn, collectionSpec{"kea", "dhcpv6", "subnet", "subnet6", "kea dhcpv6 subnet", false})
}

// KeaReservations4 are the DHCPv4 reservations
func (opn *DhcpApi) KeaReservations4() *Collection[KeaReservation4] {
	return newCollection[KeaReservation4](opn, collectionSpec{"kea", "dhcpv4", "reservation", "reservation", "kea dhcpv4 reservation", false})
}

// KeaReservations6 are the DHCPv6 reservations
func (opn *DhcpApi) KeaReservations6() *Collection[KeaReservation6] {
	return newCollection[KeaReservation6](opn, collectionSpec{"kea", "dhcpv6", "reservation", "reservation", "kea dhcpv6 reservation", false})
}

// KeaPdPools are the DHCPv6 prefix delegation pools
func (opn *DhcpApi) KeaPdPools() *Collection[KeaPdPool] {
	return newCollection[KeaPdPool](opn, collectionSpec{"kea", "dhcpv6", "pd_pool", "pd_pool", "kea dhcpv6 pd pool", false})
}

// KeaOptions4 are the custom DHCPv4 options
func (opn *DhcpApi) KeaOptions4() *Collection[KeaOption] {
	return newCollection[KeaOption](opn, collectionSpec{"kea", "dhcpv4", "option", "option", "kea dhcpv4 option", false})
}

// KeaOptions6 are the custom DHCPv6 options
func (opn *DhcpApi) KeaOptions6() *Collection[KeaOption] {
	return newCollection[KeaOption](opn, collectionSpec{"kea", "dhcpv6", "option", "option", "kea dhcpv6 option", false})
}

// KeaPeers4 are the DHCPv4 high availability peers
func (opn *DhcpApi) KeaPeers4() *Collection[KeaPeer] {
	return newCollection[KeaPeer](opn, collectionSpec{"kea", "dhcpv4", "peer", "peer", "kea dhcpv4 peer", false})
}

// KeaPeers6 are the DHCPv6 high availability peers
func (opn *DhcpApi) KeaPeers6() *Collection[KeaPeer] {
	return newCollection[KeaPeer](opn, collectionSpec{"kea", "dhcpv6", "peer", "peer", "kea dhcpv6 peer", false})
}

// The settings of Kea: KeaDhcp4Settings / KeaDhcp6Settings have the sections general (enabled, interfaces, ...),
// lexpire (lease expiry processing) and ha (high availability); KeaCtrlAgentSettings and KeaDdnsSettings only general
var (
	KeaDhcp4Settings     = SettingsSpec{"kea", "dhcpv4", "dhcpv4", "kea dhcpv4 settings"}
	KeaDhcp6Settings     = SettingsSpec{"kea", "dhcpv6", "dhcpv6", "kea dhcpv6 settings"}
	KeaCtrlAgentSettings = SettingsSpec{"kea", "ctrl_agent", "ctrlagent", "kea control agent settings"}
	KeaDdnsSettings      = SettingsSpec{"kea", "ddns", "ddns", "kea ddns settings"}
)

// KeaService is the kea service (DHCPv4, DHCPv6, control agent and DDNS daemons). Reconfigure regenerates the
// configuration and starts the daemons when DHCPv4 or DHCPv6 is enabled, else stops them
var KeaService = Service{"kea", "kea"}

// --- leases

// KeaLease is a lease of the Kea DHCPv4 or DHCPv6 server (kea/leases4 or leases6 search)
type KeaLease struct {
	Address string `json:"address"`
	// PrefixLen is 128 (v6) or 32 for addresses, shorter for delegated prefixes
	PrefixLen Text `json:"prefix_len"`
	// Type is the v6 lease type (IA_NA, IA_PD), empty for v4
	Type     Text `json:"type"`
	Hwaddr   Text `json:"hwaddr"`
	Duid     Text `json:"duid"`
	ClientId Text `json:"client_id"`
	Iaid     Text `json:"iaid"`
	Hostname Text `json:"hostname"`
	// ValidLifetime is in seconds, Expire a unix epoch
	ValidLifetime Text `json:"valid_lifetime"`
	Expire        Text `json:"expire"`
	// State is 0 for an active lease, 1 declined, 2 expired-reclaimed
	State Text `json:"state"`
	// Interface is the device (vtnet0), InterfaceName the OPNsense key (lan), InterfaceDescr its description (LAN)
	Interface      Text `json:"if"`
	InterfaceName  Text `json:"if_name"`
	InterfaceDescr Text `json:"if_descr"`
	MacInfo        Text `json:"mac_info"`
	// LeaseType is "static" when a reservation matches, else "dynamic"
	LeaseType Text `json:"lease_type"`
}

// ExpireTime converts Expire, ok is false for leases without expiry
func (lease KeaLease) ExpireTime() (time.Time, bool) {
	var epoch int64
	if _, err := fmt.Sscan(string(lease.Expire), &epoch); err != nil || epoch <= 0 {
		return time.Time{}, false
	}
	return time.Unix(epoch, 0), true
}

// StateText names the lease state: active, declined, expired or the number
func (lease KeaLease) StateText() string {
	switch lease.State {
	case "0", "":
		return "active"
	case "1":
		return "declined"
	case "2":
		return "expired"
	}
	return string(lease.State)
}

func keaLeaseController(version int) (string, error) {
	switch version {
	case 4:
		return "leases4", nil
	case 6:
		return "leases6", nil
	}
	return "", fmt.Errorf("kea leases: unknown IP version %d", version)
}

// KeaLeases returns the leases of the DHCPv4 (version 4) or DHCPv6 (6) server where any column contains
// searchPhrase ("" for all), as typed leases and as the raw objects. Kea must be running, else there are none
func (opn *DhcpApi) KeaLeases(version int, searchPhrase string) ([]KeaLease, []json.RawMessage, error) {
	var controller, err = keaLeaseController(version)
	if err != nil {
		return nil, nil, err
	}
	var raws, searchErr = coreapi.Search[json.RawMessage](opn.OPNsense, opn.EndpointForPluginControllerMethod("kea", controller, "search"), searchPhrase)
	if searchErr != nil {
		return nil, nil, searchErr
	}
	var leases = make([]KeaLease, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &leases[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected kea lease from OPNsense: %w", err)
		}
	}
	return leases, raws, nil
}

// KeaLeaseRemove deletes the leases of these addresses from the running DHCPv4 (4) or DHCPv6 (6) server; a client
// gets a new lease on its next request. OPNsense refuses the whole call when one address could not be deleted
func (opn *DhcpApi) KeaLeaseRemove(version int, addresses ...string) error {
	var controller, err = keaLeaseController(version)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("no lease address given")
	}
	for _, address := range addresses {
		var ip = net.ParseIP(address)
		if ip == nil || (ip.To4() != nil) != (version == 4) {
			return fmt.Errorf("invalid IPv%d lease address %q", version, address)
		}
	}
	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	var endpoint = opn.EndpointForPluginControllerMethod("kea", controller, "del_lease") + "/" + strings.Join(addresses, ",")
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &result); err != nil {
		// failures are a UserException: HTTP 500 {"errorMessage":"Failed to delete lease(s): <ip>: <why>"}
		return err
	}
	if result.Status != "ok" {
		if result.Message != "" {
			return fmt.Errorf("removing the kea lease failed: %s", result.Message)
		}
		return fmt.Errorf("removing the kea lease failed: status %q", result.Status)
	}
	return nil
}
