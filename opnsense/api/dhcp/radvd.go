package dhcp

// Router advertisements (Services > Router Advertisements, api/radvd): one entry per interface configures the
// IPv6 router advertisements radvd sends there. Changes take effect with the reconfigure of RadvdService.
//
// Quirks (26.7): new entries are enabled by default; the interface is unique (one entry per interface);
// MinRtrAdvInterval may be at most 0.75 * MaxRtrAdvInterval; the radvd service counts as always enabled, so its
// reconfigure and start always run radvd with whatever the entries (and the interfaces' tracking) configure

// RadvdEntry is the router advertisement configuration of one interface (radvd/settings search_entry). The JSON
// names are the API's (radvd option names); lists are comma separated
type RadvdEntry struct {
	Base
	Enabled   string `json:"enabled"`
	Interface string `json:"interface"`
	// Base6Interface is the interface whose prefix is advertised (constructor), empty for the interface itself
	Base6Interface string `json:"Base6Interface"`
	// Mode is router, unmanaged, managed, assist or stateless
	Mode                 string `json:"mode"`
	DeprecatePrefix      string `json:"DeprecatePrefix"` // "", on, off
	RemoveAdvOnExit      string `json:"RemoveAdvOnExit"` // "", on, off
	RemoveRoute          string `json:"RemoveRoute"`     // "", on, off
	Routes               string `json:"routes"`
	RDNSS                string `json:"RDNSS"`
	DNSSL                string `json:"DNSSL"`
	Dns                  string `json:"dns"`
	MinRtrAdvInterval    string `json:"MinRtrAdvInterval"`
	MaxRtrAdvInterval    string `json:"MaxRtrAdvInterval"`
	AdvDNSSLLifetime     string `json:"AdvDNSSLLifetime"`
	AdvDefaultLifetime   string `json:"AdvDefaultLifetime"`
	AdvLinkMTU           string `json:"AdvLinkMTU"`
	AdvPreferredLifetime string `json:"AdvPreferredLifetime"`
	AdvRASrcAddress      string `json:"AdvRASrcAddress"`
	AdvRDNSSLifetime     string `json:"AdvRDNSSLifetime"`
	AdvRouteLifetime     string `json:"AdvRouteLifetime"`
	AdvValidLifetime     string `json:"AdvValidLifetime"`
	AdvDefaultPreference string `json:"AdvDefaultPreference"` // low, medium, high
	Nat64prefix          string `json:"nat64prefix"`
	AdvCurHopLimit       string `json:"AdvCurHopLimit"`
}

// RadvdEntries are the router advertisement entries
func (opn *DhcpApi) RadvdEntries() *Collection[RadvdEntry] {
	return newCollection[RadvdEntry](opn, collectionSpec{"radvd", "settings", "entry", "entries", "radvd entry", true})
}

// RadvdService is the radvd service
var RadvdService = Service{"radvd", "radvd"}
