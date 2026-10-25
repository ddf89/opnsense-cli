package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Instance is a local WireGuard interface of VPN > WireGuard > Instances (api/wireguard/server), as search_server
// returns it. Lists are comma separated, flags "0"/"1".
//
// Quirks (OPNsense 26.7): search returns the private key in clear text; toggle_server flips the state whatever is
// asked (see SetEnabled); set_server on an unknown well-formed uuid creates the instance
type Instance struct {
	Uuid    string `json:"uuid"`
	Enabled string `json:"enabled"`
	Name    string `json:"name"`
	// Number is the instance number, the device is wg<Number> (assigned by OPNsense)
	Number        string `json:"instance"`
	PublicKey     string `json:"pubkey"`
	PrivateKey    string `json:"privkey"`
	Port          string `json:"port"`
	Mtu           string `json:"mtu"`
	Dns           string `json:"dns"`
	TunnelAddress string `json:"tunneladdress"`
	DisableRoutes string `json:"disableroutes"`
	Gateway       string `json:"gateway"`
	CarpDependOn  string `json:"carp_depend_on"`
	// Peers are the uuids of the peers of this instance, PeerNames their names (", " separated)
	Peers     string `json:"peers"`
	PeerNames string `json:"%peers"`
	Debug     string `json:"debug"`
	// Interface is the device name (wg0), computed by OPNsense
	Interface string `json:"interface"`
	// Endpoint and PeerDns are the defaults of the peer generator (the address clients connect to, the DNS servers
	// they get)
	Endpoint string `json:"endpoint"`
	PeerDns  string `json:"peer_dns"`
}

// InstanceFields holds a partial instance for InstanceCreate / InstanceUpdate keyed by the API field name (see
// InstanceFieldNames). Only the given keys are sent, OPNsense keeps the other fields (or uses its defaults on add)
type InstanceFields map[string]string

// InstanceFieldNames are the writable fields of an instance
var InstanceFieldNames = []string{"enabled", "name", "pubkey", "privkey", "port", "mtu", "dns", "tunneladdress",
	"disableroutes", "gateway", "carp_depend_on", "peers", "debug", "endpoint", "peer_dns"}

// InstanceSecretFields are the fields holding secrets, which must not be shown
var InstanceSecretFields = []string{"privkey"}

func instanceName(uuid string) string {
	return "wireguard instance " + uuid
}

func checkInstanceFields(fields InstanceFields) error {
	for name := range fields {
		if !slices.Contains(InstanceFieldNames, name) {
			return fmt.Errorf("unknown wireguard instance field %q", name)
		}
	}
	return nil
}

// InstanceListRaw returns the instances where any column contains searchPhrase ("" for all) in API order, with
// the raw rows (which contain the private keys)
func (opn *WireguardApi) InstanceListRaw(searchPhrase string) ([]json.RawMessage, []Instance, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("server", "search_server"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var instances = make([]Instance, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &instances[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected wireguard instance from OPNsense: %w", err)
		}
	}
	return rows, instances, nil
}

// InstanceList returns the instances, searchPhrase is a substring match over all columns ("" for all)
func (opn *WireguardApi) InstanceList(searchPhrase string) ([]Instance, error) {
	var _, instances, err = opn.InstanceListRaw(searchPhrase)
	return instances, err
}

// InstanceGet returns the instance with the given uuid or a *NotFoundError (get_server answers unknown uuids with [])
func (opn *WireguardApi) InstanceGet(uuid string) (Instance, error) {
	if uuid == "" {
		return Instance{}, errors.New("uuid must not be empty")
	}
	var instances, err = opn.InstanceList("")
	if err != nil {
		return Instance{}, err
	}
	for _, instance := range instances {
		if strings.EqualFold(instance.Uuid, uuid) {
			return instance, nil
		}
	}
	return Instance{}, &coreapi.NotFoundError{Name: instanceName(uuid)}
}

// InstanceGetByName returns the only instance with this name (case-insensitive), *NotFoundError when there is
// none, *TooManyFoundError when there are several
func (opn *WireguardApi) InstanceGetByName(name string) (Instance, error) {
	if name == "" {
		return Instance{}, errors.New("cannot look up a wireguard instance by an empty name")
	}
	var instances, err = opn.InstanceList(name)
	if err != nil {
		return Instance{}, err
	}
	var matches = coreapi.Filter(instances, func(instance Instance) bool { return strings.EqualFold(instance.Name, name) })
	switch len(matches) {
	case 0:
		return Instance{}, &coreapi.NotFoundError{Name: fmt.Sprintf("wireguard instance %q", name)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid
		}
		return Instance{}, tooManyByName("wireguard instance", name, uuids)
	}
}

// InstanceOptions returns the option lists of a new instance (get_server), e.g. carp_depend_on (the CARP
// addresses)
func (opn *WireguardApi) InstanceOptions() (map[string][]Option, error) {
	var options, err = opn.formOptions(opn.endpoint("server", "get_server"), "server")
	if err == nil && options == nil {
		return nil, errors.New("unexpected answer from wireguard/server/get_server")
	}
	return options, err
}

// InstanceCreate adds an instance and returns its uuid. A private key is required (see KeyPair); OPNsense does
// not derive the public key, give it too (PublicKeyOf). Duplicate names are not checked
func (opn *WireguardApi) InstanceCreate(fields InstanceFields) (string, error) {
	if err := checkInstanceFields(fields); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("server", "add_server"), map[string]InstanceFields{"server": fields})
}

// InstanceUpdate sends only the given fields to the instance with this uuid, the others are kept. Returns
// *NotFoundError when the uuid does not exist (checked first, set_server would create it)
func (opn *WireguardApi) InstanceUpdate(uuid string, fields InstanceFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := checkInstanceFields(fields); err != nil {
		return err
	}
	if _, err := opn.InstanceGet(uuid); err != nil {
		return err
	}
	return opn.mutateSet(fmt.Sprintf("%s/%s", opn.endpoint("server", "set_server"), uuid), "server", instanceName(uuid), fields)
}

// InstanceRemove deletes the instance with this uuid, *NotFoundError when it does not exist. Its peers are kept,
// they are no longer linked to it. A running instance keeps running until the service is reconfigured
func (opn *WireguardApi) InstanceRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a wireguard instance by uuid %q", uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("server", "del_server"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: instanceName(uuid), Err: err}
	}
	return err
}

// InstanceSetEnabled enables or disables the instance with this uuid and returns whether its state changed. It
// uses set_server, because toggle_server ignores the requested state and always flips it. Like every change it
// takes effect with ServiceReconfigure
func (opn *WireguardApi) InstanceSetEnabled(uuid string, enabled bool) (bool, error) {
	var instance, err = opn.InstanceGet(uuid)
	if err != nil {
		return false, err
	}
	if !toggleChanged(instance.Enabled, enabled) {
		return false, nil
	}
	var endpoint = fmt.Sprintf("%s/%s", opn.endpoint("server", "set_server"), instance.Uuid)
	return true, opn.mutateSet(endpoint, "server", instanceName(uuid), map[string]string{"enabled": flag(enabled)})
}

func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// ServerInfo is what the peer generator loads for an instance (client/get_server_info)
type ServerInfo struct {
	// Endpoint and PeerDns are the stored peer generator defaults of the instance
	Endpoint string `json:"endpoint"`
	PeerDns  string `json:"peer_dns"`
	// AllowedIps is the stored default of newer OPNsense versions (26.7 has none: "")
	AllowedIps string `json:"allowed_ips"`
	Mtu        string `json:"mtu"`
	PublicKey  string `json:"pubkey"`
	// Address is the next free tunnel address of each address family of the instance, e.g. 10.0.0.3/32,fd00::2/128
	Address string `json:"address"`
}

// InstanceServerInfo returns the peer generator information of the instance with this uuid
func (opn *WireguardApi) InstanceServerInfo(uuid string) (ServerInfo, error) {
	if uuid == "" {
		return ServerInfo{}, errors.New("uuid must not be empty")
	}
	var answer struct {
		ServerInfo
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", fmt.Sprintf("%s/%s", opn.endpoint("client", "get_server_info"), uuid), nil, &answer); err != nil {
		return ServerInfo{}, err
	}
	if answer.Status != "ok" {
		return ServerInfo{}, &coreapi.NotFoundError{Name: instanceName(uuid)}
	}
	return answer.ServerInfo, nil
}
