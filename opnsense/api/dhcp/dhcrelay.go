package dhcp

// DHCP relay (Services > DHCRelay, api/dhcrelay): destinations are named lists of DHCP servers of one address
// family, a relay forwards the DHCP requests received on an interface to a destination. An interface can have one
// IPv4 and one IPv6 relay. Changes take effect with RelayReconfigure.
//
// Quirks (26.7): a destination used by a relay can not be removed (HTTP 500 naming the relay); the relay model of
// the 26.7 release has no circuit/remote id fields (the stable/26.7 branch added them later); search_relay adds a
// status column (green running, red stopped, grey disabled)

// RelayDestination is a named list of DHCP servers (dhcrelay/settings search_dest), all IPv4 or all IPv6
type RelayDestination struct {
	Base
	Name string `json:"name"`
	// Server are the addresses of the DHCP servers, comma separated
	Server string `json:"server"`
}

// Relay forwards the DHCP requests of an interface to a destination (dhcrelay/settings search_relay)
type Relay struct {
	Base
	Enabled   string `json:"enabled"`
	Interface string `json:"interface"`
	// Destination is the uuid of the RelayDestination, DestinationName its name
	Destination     string `json:"destination"`
	DestinationName string `json:"%destination"`
	// AgentInfo adds the relay agent information option (82) to the requests
	AgentInfo string `json:"agent_info"`
	// CarpDependOn is a CARP virtual IP: the relay only runs while it is master
	CarpDependOn string `json:"carp_depend_on"`
	// Status is green (running), red (not running) or grey (disabled), read only
	Status string `json:"status"`
}

// RelayDestinations are the relay destinations
func (opn *DhcpApi) RelayDestinations() *Collection[RelayDestination] {
	return newCollection[RelayDestination](opn, collectionSpec{"dhcrelay", "settings", "dest", "destination", "dhcrelay destination", false})
}

// Relays are the relays
func (opn *DhcpApi) Relays() *Collection[Relay] {
	return newCollection[Relay](opn, collectionSpec{"dhcrelay", "settings", "relay", "relay", "dhcrelay relay", true})
}

// RelayReconfigure applies the saved relays: (re)starts the enabled relays and stops the others
func (opn *DhcpApi) RelayReconfigure() error {
	return opn.reconfigure(opn.EndpointForPluginControllerMethod("dhcrelay", "service", "reconfigure"), "dhcrelay")
}
