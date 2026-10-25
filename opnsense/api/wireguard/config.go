package wireguard

import (
	"errors"
	"strings"
)

// DefaultAllowedIps is what the peer generator routes through the tunnel when the instance stores no default:
// everything
const DefaultAllowedIps = "0.0.0.0/0,::/0"

// ClientConfig is the wg-quick configuration of a peer (the remote side), as the peer generator of VPN > WireGuard
// builds it in the browser. OPNsense has no API that renders it, all values come from the API: the instance
// (client/get_server_info), the peer and its key pair (server/key_pair)
type ClientConfig struct {
	// PrivateKey is the peer's private key, Address its tunnel address(es)
	PrivateKey string
	Address    string
	// Dns and Mtu are the DNS servers and the MTU the peer uses, "" for none
	Dns string
	Mtu string
	// ServerPublicKey is the public key of the instance, PresharedKey the peer's pre-shared key ("" for none)
	ServerPublicKey string
	PresharedKey    string
	// Endpoint is host:port of the instance, AllowedIps the networks routed through the tunnel
	Endpoint   string
	AllowedIps string
	// Keepalive is the persistent keepalive interval in seconds, "" for none
	Keepalive string
}

// Validate checks that the configuration is complete
func (c ClientConfig) Validate() error {
	var missing []string
	for _, field := range []struct{ name, value string }{
		{"private key", c.PrivateKey}, {"instance public key", c.ServerPublicKey}, {"endpoint", c.Endpoint},
		{"allowed IPs", c.AllowedIps},
	} {
		if strings.TrimSpace(field.value) == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return errors.New("the peer configuration lacks: " + strings.Join(missing, ", "))
	}
	return nil
}

// String renders the configuration like the peer generator: [Interface] and [Peer], optional lines left out,
// lists with ", "
func (c ClientConfig) String() string {
	var lines = []string{"[Interface]", "PrivateKey = " + c.PrivateKey}
	var add = func(key string, value string) {
		if value = strings.TrimSpace(value); value != "" {
			lines = append(lines, key+" = "+value)
		}
	}
	add("Address", listText(c.Address))
	add("DNS", listText(c.Dns))
	add("MTU", c.Mtu)
	lines = append(lines, "", "[Peer]", "PublicKey = "+c.ServerPublicKey)
	add("PresharedKey", c.PresharedKey)
	add("Endpoint", c.Endpoint)
	add("AllowedIPs", listText(c.AllowedIps))
	add("PersistentKeepalive", c.Keepalive)
	return strings.Join(lines, "\n") + "\n"
}

// listText renders a comma separated list as "a, b"
func listText(list string) string {
	var elements []string
	for _, element := range strings.Split(list, ",") {
		if element = strings.TrimSpace(element); element != "" {
			elements = append(elements, element)
		}
	}
	return strings.Join(elements, ", ")
}
