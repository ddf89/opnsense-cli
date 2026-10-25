package dnsmasq

import (
	"encoding/json"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// Lease is a DHCP lease as returned by api/dnsmasq/leases/search (read-only, parsed from /var/db/dnsmasq.leases)
type Lease struct {
	Address string `json:"address"`
	// Hwaddr is the MAC address (IPv4), for IPv6 it is derived from the DUID when possible
	Hwaddr string `json:"hwaddr"`
	// Iaid is only set for IPv6 leases
	Iaid string `json:"iaid"`
	// Hostname and ClientId are "*" when the client did not send one
	Hostname string `json:"hostname"`
	ClientId string `json:"client_id"`
	// Expire is the expiry as unix epoch, 0 for leases that never expire
	Expire json.Number `json:"expire"`
	// Interface is the OS device name (e.g. igc1), InterfaceName the OPNsense key (e.g. lan)
	Interface      string `json:"if"`
	InterfaceDescr string `json:"if_descr"`
	InterfaceName  string `json:"if_name"`
	MacInfo        string `json:"mac_info"`
	// LeaseType is "static" when a dnsmasq host reservation matches, else "dynamic"
	LeaseType string `json:"lease_type"`
}

// ExpireTime converts Expire to a time, ok is false for leases without (or with an unparsable) expiry
func (lease Lease) ExpireTime() (expire time.Time, ok bool) {
	var epoch, err = lease.Expire.Int64()
	if err != nil || epoch <= 0 {
		return time.Time{}, false
	}
	return time.Unix(epoch, 0), true
}

// LeaseList returns all current DHCP leases, searchPhrase is a substring match over the visible columns ("" for all)
func (opn *DnsmasqApi) LeaseList(searchPhrase string) ([]Lease, error) {
	var endpoint = opn.EndpointForPluginControllerMethod("dnsmasq", "leases", "search")
	return coreapi.Search[Lease](opn.OPNsense, endpoint, searchPhrase)
}
