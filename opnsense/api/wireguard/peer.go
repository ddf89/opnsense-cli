package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Peer is a remote WireGuard peer of VPN > WireGuard > Peers (api/wireguard/client), as search_client returns it.
// Lists are comma separated, flags "0"/"1".
//
// Quirks (OPNsense 26.7): search returns the pre-shared key in clear text; set_client without servers unlinks the
// peer from all instances (PeerUpdate always sends them); toggle_client flips the state whatever is asked
type Peer struct {
	Uuid      string `json:"uuid"`
	Enabled   string `json:"enabled"`
	Name      string `json:"name"`
	PublicKey string `json:"pubkey"`
	Psk       string `json:"psk"`
	// TunnelAddress are the allowed IPs of the peer (networks routed to it)
	TunnelAddress string `json:"tunneladdress"`
	// ServerAddress and ServerPort are the endpoint of the peer, empty for peers that connect to us
	ServerAddress string `json:"serveraddress"`
	ServerPort    string `json:"serverport"`
	Keepalive     string `json:"keepalive"`
	// Servers are the uuids of the instances the peer belongs to, ServerNames their names
	Servers     string `json:"servers"`
	ServerNames string `json:"%servers"`
	// PrivateKey is only stored by newer OPNsense versions (peer generator with "store private key"), never by 26.7
	PrivateKey string `json:"privkey"`
}

// PeerFields holds a partial peer for PeerCreate / PeerUpdate keyed by the API field name (see PeerFieldNames)
type PeerFields map[string]string

// PeerFieldNames are the writable fields of a peer
var PeerFieldNames = []string{"enabled", "name", "pubkey", "psk", "tunneladdress", "serveraddress", "serverport",
	"keepalive", "servers"}

// PeerSecretFields are the fields holding secrets, which must not be shown
var PeerSecretFields = []string{"psk", "privkey"}

func peerName(uuid string) string {
	return "wireguard peer " + uuid
}

func checkPeerFields(fields PeerFields) error {
	for name := range fields {
		if !slices.Contains(PeerFieldNames, name) {
			return fmt.Errorf("unknown wireguard peer field %q", name)
		}
	}
	return nil
}

// InstanceUuids returns the uuids of the instances of the peer
func (p Peer) InstanceUuids() []string {
	var uuids []string
	for _, uuid := range strings.Split(p.Servers, ",") {
		if uuid = strings.TrimSpace(uuid); uuid != "" {
			uuids = append(uuids, uuid)
		}
	}
	return uuids
}

// PeerListRaw returns the peers where any column contains searchPhrase ("" for all) in API order, with the raw
// rows (which contain the pre-shared keys)
func (opn *WireguardApi) PeerListRaw(searchPhrase string) ([]json.RawMessage, []Peer, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("client", "search_client"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var peers = make([]Peer, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &peers[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected wireguard peer from OPNsense: %w", err)
		}
	}
	return rows, peers, nil
}

// PeerList returns the peers, searchPhrase is a substring match over all columns ("" for all)
func (opn *WireguardApi) PeerList(searchPhrase string) ([]Peer, error) {
	var _, peers, err = opn.PeerListRaw(searchPhrase)
	return peers, err
}

// PeerGet returns the peer with the given uuid or a *NotFoundError (get_client answers unknown uuids with [])
func (opn *WireguardApi) PeerGet(uuid string) (Peer, error) {
	if uuid == "" {
		return Peer{}, errors.New("uuid must not be empty")
	}
	var peers, err = opn.PeerList("")
	if err != nil {
		return Peer{}, err
	}
	for _, peer := range peers {
		if strings.EqualFold(peer.Uuid, uuid) {
			return peer, nil
		}
	}
	return Peer{}, &coreapi.NotFoundError{Name: peerName(uuid)}
}

// PeerGetByName returns the only peer with this name (case-insensitive), *NotFoundError when there is none,
// *TooManyFoundError when there are several
func (opn *WireguardApi) PeerGetByName(name string) (Peer, error) {
	if name == "" {
		return Peer{}, errors.New("cannot look up a wireguard peer by an empty name")
	}
	var peers, err = opn.PeerList(name)
	if err != nil {
		return Peer{}, err
	}
	var matches = coreapi.Filter(peers, func(peer Peer) bool { return strings.EqualFold(peer.Name, name) })
	switch len(matches) {
	case 0:
		return Peer{}, &coreapi.NotFoundError{Name: fmt.Sprintf("wireguard peer %q", name)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid
		}
		return Peer{}, tooManyByName("wireguard peer", name, uuids)
	}
}

// PeerCreate adds a peer and returns its uuid; servers (instance uuids, comma separated) links it to instances.
// Duplicate names are not checked, a public key may only be used once per endpoint
func (opn *WireguardApi) PeerCreate(fields PeerFields) (string, error) {
	if err := checkPeerFields(fields); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("client", "add_client"), map[string]PeerFields{"client": fields})
}

// PeerUpdate sends only the given fields to the peer with this uuid, the others are kept. The current instances
// are always sent unless servers is given: set_client without them unlinks the peer from every instance.
// Returns *NotFoundError when the uuid does not exist (checked first, set_client would create it)
func (opn *WireguardApi) PeerUpdate(uuid string, fields PeerFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := checkPeerFields(fields); err != nil {
		return err
	}
	var peer, err = opn.PeerGet(uuid)
	if err != nil {
		return err
	}
	return opn.peerSet(peer, fields)
}

func (opn *WireguardApi) peerSet(peer Peer, fields PeerFields) error {
	var body = map[string]string{"servers": peer.Servers}
	for name, value := range fields {
		body[name] = value
	}
	var endpoint = fmt.Sprintf("%s/%s", opn.endpoint("client", "set_client"), peer.Uuid)
	return opn.mutateSet(endpoint, "client", peerName(peer.Uuid), body)
}

// PeerRemove deletes the peer with this uuid (OPNsense unlinks it from its instances), *NotFoundError when it does
// not exist
func (opn *WireguardApi) PeerRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a wireguard peer by uuid %q", uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("client", "del_client"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: peerName(uuid), Err: err}
	}
	return err
}

// PeerSetEnabled enables or disables the peer with this uuid and returns whether its state changed (through
// set_client, see InstanceSetEnabled)
func (opn *WireguardApi) PeerSetEnabled(uuid string, enabled bool) (bool, error) {
	var peer, err = opn.PeerGet(uuid)
	if err != nil {
		return false, err
	}
	if !toggleChanged(peer.Enabled, enabled) {
		return false, nil
	}
	return true, opn.peerSet(peer, PeerFields{"enabled": flag(enabled)})
}
