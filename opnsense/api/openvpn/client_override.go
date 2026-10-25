package openvpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// ClientOverride is an OpenVPN client specific override (VPN > OpenVPN > Client Specific Overrides,
// api/openvpn/client_overwrites/*, model node Overwrites.Overwrite, body key "cso").
//
// OpenVPN applies every enabled override whose CommonName equals the client's common name exactly (case-sensitive)
// and whose Servers contain the server (an empty Servers applies to all servers); several matching overrides are
// merged in config order, later ones winning per field.
// List fields are comma separated strings, e.g. LocalNetworks "10.0.0.0/24,fd00::/64"
type ClientOverride struct {
	Uuid    string `json:"uuid,omitempty"`
	Enabled string `json:"enabled"` // "1" / "0"
	// Servers are the server instances (uuids, or the vpnid of legacy servers) it applies to, empty for all
	Servers string `json:"servers"`
	// ServersLabel is the display text of Servers, e.g. "office (1194 / UDP)", only in search rows (absent when Servers is empty)
	ServersLabel string `json:"%servers,omitempty"`
	CommonName   string `json:"common_name"`
	Block        string `json:"block"`      // "1": refuse the client
	PushReset    string `json:"push_reset"` // "1": do not inherit the global push options
	// TunnelNetwork / TunnelNetworkV6 are the client's tunnel address with prefix length (IPv4 / IPv6)
	TunnelNetwork   string `json:"tunnel_network"`
	TunnelNetworkV6 string `json:"tunnel_networkv6"`
	LocalNetworks   string `json:"local_networks"`  // pushed to the client (push route)
	RemoteNetworks  string `json:"remote_networks"` // behind the client (iroute)
	RouteGateway    string `json:"route_gateway"`
	// RedirectGateway are option keys: local, autolocal, def1, bypass-dhcp, bypass-dns, block-local, ipv6, !ipv4
	RedirectGateway string `json:"redirect_gateway"`
	// RedirectGatewayLabel is the display text of RedirectGateway, only in search rows
	RedirectGatewayLabel string `json:"%redirect_gateway,omitempty"`
	RegisterDns          string `json:"register_dns"`
	DnsDomain            string `json:"dns_domain"`
	DnsDomainSearch      string `json:"dns_domain_search"`
	DnsServers           string `json:"dns_servers"`
	NtpServers           string `json:"ntp_servers"`
	WinsServers          string `json:"wins_servers"`
	Description          string `json:"description"`
}

// ClientOverrideFields holds a partial override for ClientOverrideUpdate, keyed by the API field name (see
// ClientOverrideFieldNames). Only the given keys are sent, OPNsense keeps all other fields. An empty value clears a field
type ClientOverrideFields map[string]string

// ClientOverrideFieldNames are the writable fields of a client specific override
var ClientOverrideFieldNames = []string{
	"enabled", "servers", "common_name", "block", "push_reset", "tunnel_network", "tunnel_networkv6",
	"local_networks", "remote_networks", "route_gateway", "redirect_gateway", "register_dns", "dns_domain",
	"dns_domain_search", "dns_servers", "ntp_servers", "wins_servers", "description",
}

// ClientOverrideRedirectGatewayOptions are the keys redirect_gateway accepts
var ClientOverrideRedirectGatewayOptions = []string{
	"local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4",
}

// Fields returns all writable fields of o, empty flags as "0" and an empty Enabled as "1" (the model default)
func (o ClientOverride) Fields() ClientOverrideFields {
	var enabled = o.Enabled
	if enabled == "" {
		enabled = "1"
	}
	return ClientOverrideFields{
		"enabled":           enabled,
		"servers":           o.Servers,
		"common_name":       o.CommonName,
		"block":             clientOverrideFlag(o.Block),
		"push_reset":        clientOverrideFlag(o.PushReset),
		"tunnel_network":    o.TunnelNetwork,
		"tunnel_networkv6":  o.TunnelNetworkV6,
		"local_networks":    o.LocalNetworks,
		"remote_networks":   o.RemoteNetworks,
		"route_gateway":     o.RouteGateway,
		"redirect_gateway":  o.RedirectGateway,
		"register_dns":      clientOverrideFlag(o.RegisterDns),
		"dns_domain":        o.DnsDomain,
		"dns_domain_search": o.DnsDomainSearch,
		"dns_servers":       o.DnsServers,
		"ntp_servers":       o.NtpServers,
		"wins_servers":      o.WinsServers,
		"description":       o.Description,
	}
}

func clientOverrideFlag(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

// ServerList returns Servers as a list of uuids (vpnids for legacy servers), empty for all servers
func (o ClientOverride) ServerList() []string {
	return clientOverrideSplit(o.Servers)
}

// SameServers tells whether o applies to exactly the given servers (order and duplicates do not matter)
func (o ClientOverride) SameServers(servers string) bool {
	var a, b = clientOverrideSet(o.Servers), clientOverrideSet(servers)
	return slices.Equal(a, b)
}

func clientOverrideSplit(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

func clientOverrideSet(value string) []string {
	var elements = clientOverrideSplit(value)
	for i := range elements {
		elements[i] = strings.ToLower(elements[i])
	}
	sort.Strings(elements)
	return slices.Compact(elements)
}

func (opn *OpenVPNApi) clientOverrideEndpoint(method string) string {
	return opn.endpoint("client_overwrites", method)
}

// ClientOverrideList returns all client specific overrides in API order, searchPhrase is a substring match over all
// columns ("" for all)
func (opn *OpenVPNApi) ClientOverrideList(searchPhrase string) ([]ClientOverride, error) {
	return coreapi.Search[ClientOverride](opn.OPNsense, opn.clientOverrideEndpoint("search"), searchPhrase)
}

// ClientOverrideListRaw returns the search rows both raw (for JSON output) and decoded, in the same (API) order
func (opn *OpenVPNApi) ClientOverrideListRaw(searchPhrase string) ([]json.RawMessage, []ClientOverride, error) {
	var endpoint = opn.clientOverrideEndpoint("search")
	var raws, err = coreapi.Search[json.RawMessage](opn.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var overrides = make([]ClientOverride, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &overrides[i]); err != nil {
			return nil, nil, fmt.Errorf("could not decode a row of %s: %w", endpoint, err)
		}
	}
	return raws, overrides, nil
}

// ClientOverrideGet returns the override with the given uuid or a *NotFoundError
func (opn *OpenVPNApi) ClientOverrideGet(uuid string) (ClientOverride, error) {
	var overrides, err = opn.ClientOverrideList("")
	if err != nil {
		return ClientOverride{}, err
	}
	for _, override := range overrides {
		if strings.EqualFold(override.Uuid, uuid) {
			return override, nil
		}
	}
	return ClientOverride{}, clientOverrideNotFound(uuid, nil)
}

func clientOverrideNotFound(name string, err error) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("openvpn client specific override %s", name), Err: err}
}

// ClientOverrideFindByCommonName returns the overrides whose common name equals commonName exactly (OpenVPN matches it
// case-sensitively), for all servers
func (opn *OpenVPNApi) ClientOverrideFindByCommonName(commonName string) ([]ClientOverride, error) {
	if commonName == "" {
		return nil, errors.New("common name must not be empty")
	}
	// searchPhrase is a substring match over all columns, compare exactly
	var overrides, err = opn.ClientOverrideList(commonName)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(overrides, func(o ClientOverride) bool { return o.CommonName == commonName }), nil
}

// ClientOverrideFindByKey returns the overrides with the natural key of o: the same common name (exact) and the same
// set of servers
func (opn *OpenVPNApi) ClientOverrideFindByKey(commonName string, servers string) ([]ClientOverride, error) {
	var overrides, err = opn.ClientOverrideFindByCommonName(commonName)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(overrides, func(o ClientOverride) bool { return o.SameServers(servers) }), nil
}

// ClientOverrideCreate adds a new override and returns its uuid. Duplicates are not checked, see
// ClientOverrideCreateOrUpdate
func (opn *OpenVPNApi) ClientOverrideCreate(override ClientOverride) (string, error) {
	var body = map[string]ClientOverrideFields{"cso": override.Fields()}
	return opn.Mutate(opn.clientOverrideEndpoint("add"), body)
}

// ClientOverrideUpdate sends only the given fields to the override with the given uuid, all other fields are kept.
// Returns *NotFoundError when the uuid does not exist (checked first: set/<uuid> would create it),
// *ValidationError when OPNsense rejects the change
func (opn *OpenVPNApi) ClientOverrideUpdate(uuid string, fields ClientOverrideFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	for name := range fields {
		if !slices.Contains(ClientOverrideFieldNames, name) {
			return fmt.Errorf("unknown openvpn client specific override field %q", name)
		}
	}
	// set/<uuid> creates the override when a well-formed uuid does not exist, so make sure it does
	var existing, err = opn.ClientOverrideGet(uuid)
	if err != nil {
		return err
	}
	return opn.clientOverrideSet(existing.Uuid, fields)
}

// clientOverrideSet sends fields to set/<uuid> without checking that uuid exists
func (opn *OpenVPNApi) clientOverrideSet(uuid string, fields ClientOverrideFields) error {
	var body = map[string]ClientOverrideFields{"cso": fields}
	var _, err = opn.Mutate(opn.clientOverrideEndpoint("set")+"/"+uuid, body)
	// a malformed uuid is answered with a plain {"result":"failed"} without validation messages
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return clientOverrideNotFound(uuid, err)
	}
	return err
}

// ClientOverrideCreateOrUpdate creates override, or when override.Uuid is set / an override with the same common name
// and servers exists, overwrites that one with all fields of override (fields left empty are cleared).
// Returns the uuid and whether an existing override was replaced. Several overrides with the same key are a
// *TooManyFoundError, an override.Uuid which does not exist a *NotFoundError
func (opn *OpenVPNApi) ClientOverrideCreateOrUpdate(override ClientOverride) (string, bool, error) {
	if override.Uuid != "" {
		return override.Uuid, true, opn.ClientOverrideUpdate(override.Uuid, override.Fields())
	}

	var existing, err = opn.ClientOverrideFindByKey(override.CommonName, override.Servers)
	if err != nil {
		return "", false, err
	}
	switch len(existing) {
	case 0:
		var created, createErr = opn.ClientOverrideCreate(override)
		return created, false, createErr
	case 1:
		// just found by the search, no need to check for existence again
		return existing[0].Uuid, true, opn.clientOverrideSet(existing[0].Uuid, override.Fields())
	default:
		var uuids = make([]string, len(existing))
		for i, match := range existing {
			uuids[i] = match.Uuid
		}
		sort.Strings(uuids)
		return "", false, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d openvpn client specific overrides for %s with the same servers (uuids: %s)",
			len(existing), override.CommonName, strings.Join(uuids, ", "))}
	}
}

// ClientOverridesForServer returns the overrides that name the server instance id (uuid) in their servers.
// OPNsense removes instances overrides refer to, leaving them with a dangling reference
func (opn *OpenVPNApi) ClientOverridesForServer(id string) ([]ClientOverride, error) {
	if id == "" {
		return nil, errors.New("server id must not be empty")
	}
	var overrides, err = opn.ClientOverrideList("")
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(overrides, func(override ClientOverride) bool {
		return slices.ContainsFunc(override.ServerList(), func(server string) bool { return strings.EqualFold(server, id) })
	}), nil
}

// ClientOverrideRemove deletes the override with the given uuid, returns *NotFoundError when it does not exist
func (opn *OpenVPNApi) ClientOverrideRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	var _, err = opn.Mutate(opn.clientOverrideEndpoint("del")+"/"+uuid, nil)
	if coreapi.IsNotFound(err) {
		return clientOverrideNotFound(uuid, err)
	}
	return err
}

// ClientOverrideSetEnabled enables or disables the override uuid and returns whether its state changed
func (opn *OpenVPNApi) ClientOverrideSetEnabled(uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("uuid must not be empty")
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	// toggle/<uuid>/<0|1> answers {"result":"Enabled"|"Disabled","changed":bool}, an unknown uuid {"result":"failed"}.
	// Without the state it would flip it, GET is a no-op answering failed
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.clientOverrideEndpoint("toggle"), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed", "not found":
		return false, clientOverrideNotFound(uuid, nil)
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// ClientOverrideServer is a server instance an override can apply to
type ClientOverrideServer struct {
	// Id is the instance uuid, or the vpnid of a legacy server
	Id string
	// Label is OPNsense's display text "description (port / PROTO)"
	Label string
}

// Description returns the label without the " (port / PROTO)" suffix OPNsense appends
func (s ClientOverrideServer) Description() string {
	// a server without description is labelled " (1194 / UDP)"
	if i := strings.LastIndex(s.Label, " ("); i >= 0 && strings.HasSuffix(s.Label, ")") && strings.Contains(s.Label[i:], " / ") {
		return s.Label[:i]
	}
	return s.Label
}

// ClientOverrideServers returns the server instances an override can apply to (the option list of the servers field
// of client_overwrites/get), sorted by label like OPNsense
func (opn *OpenVPNApi) ClientOverrideServers() ([]ClientOverrideServer, error) {
	var container struct {
		Cso struct {
			// an option map {"<uuid>":{"value":"<label>","selected":0}}, or [] when there are no servers
			Servers json.RawMessage `json:"servers"`
		} `json:"cso"`
	}
	var endpoint = opn.clientOverrideEndpoint("get")
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	var raw = strings.TrimSpace(string(container.Cso.Servers))
	if raw == "" || raw == "[]" || raw == "null" {
		if raw == "" {
			return nil, fmt.Errorf("unexpected answer from %s: no servers option list", endpoint)
		}
		return nil, nil
	}
	var options map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(container.Cso.Servers, &options); err != nil {
		return nil, fmt.Errorf("could not decode the servers options of %s: %w", endpoint, err)
	}
	var servers = make([]ClientOverrideServer, 0, len(options))
	for id, option := range options {
		servers = append(servers, ClientOverrideServer{Id: id, Label: option.Value})
	}
	sort.Slice(servers, func(i, j int) bool {
		var a, b = strings.ToLower(servers[i].Label), strings.ToLower(servers[j].Label)
		if a != b {
			return a < b
		}
		return servers[i].Id < servers[j].Id
	})
	return servers, nil
}
