package unbound

import (
	"encoding/json"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/internal/dnsmodel"
)

// Access lists, query forwarding / DNS over TLS servers, DNSBL policies and host override aliases of
// Services > Unbound DNS (api/unbound/settings/*_acl, *_forward, *_dot, *_dnsbl, *_host_alias). Changes are only
// saved, ServiceReconfigure applies them (ServiceDnsbl for the blocklists)

// Patch maps API field names (the JSON names of the record types) to new values; fields not in it are kept
type Patch = dnsmodel.Patch

// SettingsOption is one choice of an option field: Key is stored and sent, Value is the display name
type SettingsOption = dnsmodel.Option

var (
	aclKind       = dnsmodel.Kind{Module: "unbound", Controller: "settings", Method: "acl", Container: "acl", Name: "access list"}
	forwardKind   = dnsmodel.Kind{Module: "unbound", Controller: "settings", Method: "forward", Container: "dot", Name: "forward"}
	dotKind       = dnsmodel.Kind{Module: "unbound", Controller: "settings", Method: "dot", Container: "dot", Name: "DNS over TLS server"}
	blocklistKind = dnsmodel.Kind{Module: "unbound", Controller: "settings", Method: "dnsbl", Container: "blocklist", Name: "blocklist"}
	aliasKind     = dnsmodel.Kind{Module: "unbound", Controller: "settings", Method: "host_alias", Container: "alias", Name: "host alias"}
)

// Acl is an access list: which networks may query Unbound
type Acl struct {
	Uuid string `json:"uuid,omitempty"`
	// Enabled is "1" (default) or "0"
	Enabled string `json:"enabled,omitempty"`
	Name    string `json:"name,omitempty"`
	// Action is allow (default), deny, refuse, allow_snoop, deny_non_local or refuse_non_local
	Action string `json:"action,omitempty"`
	// Networks is a comma separated list of networks in CIDR notation
	Networks    string `json:"networks,omitempty"`
	Description string `json:"description,omitempty"`
}

// Forward is a query forwarding target: Type "forward" (plain DNS) or "dot" (DNS over TLS). Both are stored in
// the same list, the API has separate endpoints per type
type Forward struct {
	Uuid    string `json:"uuid,omitempty"`
	Enabled string `json:"enabled,omitempty"`
	// Type is "forward" or "dot"; it is set by the endpoint, not by this field
	Type string `json:"type,omitempty"`
	// Domain to forward, empty for all queries
	Domain string `json:"domain,omitempty"`
	Server string `json:"server,omitempty"`
	Port   string `json:"port,omitempty"`
	// Verify is the name to verify the TLS certificate of a DNS over TLS server against
	Verify             string `json:"verify,omitempty"`
	ForwardTcpUpstream string `json:"forward_tcp_upstream,omitempty"`
	ForwardFirst       string `json:"forward_first,omitempty"`
	Description        string `json:"description,omitempty"`
}

// Blocklist is a DNSBL policy (26.7): which lists apply to which source networks and how blocked names are answered
type Blocklist struct {
	Uuid    string `json:"uuid,omitempty"`
	Enabled string `json:"enabled,omitempty"`
	// Type is the comma separated list of predefined lists (keys like ag, hgz002, see BlocklistTypes)
	Type string `json:"type,omitempty"`
	// Lists are URLs of additional blocklists, Allowlists / Blocklists domains (regular expressions allowed) to
	// always allow / block, Wildcards domains blocked with all their subdomains; all comma separated
	Lists      string `json:"lists,omitempty"`
	Allowlists string `json:"allowlists,omitempty"`
	Blocklists string `json:"blocklists,omitempty"`
	Wildcards  string `json:"wildcards,omitempty"`
	// SourceNets are the client networks the policy applies to, empty for all
	SourceNets string `json:"source_nets,omitempty"`
	// Address answers blocked A queries (default 0.0.0.0), Nxdomain answers NXDOMAIN instead
	Address  string `json:"address,omitempty"`
	Nxdomain string `json:"nxdomain,omitempty"`
	// CacheTtl is how long a downloaded list is kept, seconds (default 72000)
	CacheTtl    string `json:"cache_ttl,omitempty"`
	Description string `json:"description,omitempty"`
}

// HostAlias is another name for a host override: it answers with the records of the host override Host (a uuid)
type HostAlias struct {
	Uuid    string `json:"uuid,omitempty"`
	Enabled string `json:"enabled,omitempty"`
	// Host is the uuid of the host override
	Host        string `json:"host,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Description string `json:"description,omitempty"`
}

// FQDN is hostname.domain, or the domain alone for an alias without host name
func (alias HostAlias) FQDN() string {
	var domain = strings.TrimSuffix(alias.Domain, ".")
	if alias.Hostname == "" {
		return domain
	}
	return alias.Hostname + "." + domain
}

// --- access lists

// AclList returns the access lists where any column contains searchPhrase ("" for all)
func (opn *UnboundApi) AclList(searchPhrase string) ([]Acl, error) {
	return dnsmodel.Search[Acl](opn.OPNsense, aclKind, searchPhrase)
}

// AclGet returns the access list with the given uuid or a *coreapi.NotFoundError
func (opn *UnboundApi) AclGet(uuid string) (Acl, error) {
	return dnsmodel.Get[Acl](opn.OPNsense, aclKind, uuid)
}

// AclCreate adds an access list and returns its uuid
func (opn *UnboundApi) AclCreate(acl Acl) (string, error) {
	return dnsmodel.Create(opn.OPNsense, aclKind, acl)
}

// AclUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid
func (opn *UnboundApi) AclUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, aclKind, uuid, patch)
}

// AclRemove deletes an access list
func (opn *UnboundApi) AclRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, aclKind, uuid)
}

// AclDefaultAction returns the action for networks no access list matches: allow, deny or refuse
func (opn *UnboundApi) AclDefaultAction() (string, error) {
	var settings, err = opn.settings("unbound.acls", "acl")
	if err != nil {
		return "", err
	}
	return settings.Values["default_action"], nil
}

// AclSetDefaultAction changes the action for networks no access list matches: allow, deny or refuse
func (opn *UnboundApi) AclSetDefaultAction(action string) error {
	return opn.SettingsSet(Patch{"acls.default_action": action})
}

// --- forwarding

func forwardKindOf(forwardType string) (dnsmodel.Kind, error) {
	switch forwardType {
	case "forward":
		return forwardKind, nil
	case "dot":
		return dotKind, nil
	}
	return dnsmodel.Kind{}, fmt.Errorf("unknown forward type %q, must be forward or dot", forwardType)
}

// ForwardList returns the forwarding targets of both types (forward first, then dot) where any column contains
// searchPhrase ("" for all)
func (opn *UnboundApi) ForwardList(searchPhrase string) ([]Forward, error) {
	var forwards, err = dnsmodel.Search[Forward](opn.OPNsense, forwardKind, searchPhrase)
	if err != nil {
		return nil, err
	}
	dots, err := dnsmodel.Search[Forward](opn.OPNsense, dotKind, searchPhrase)
	if err != nil {
		return nil, err
	}
	return append(forwards, dots...), nil
}

// ForwardGet returns the forwarding target with the given uuid (of any type) or a *coreapi.NotFoundError
func (opn *UnboundApi) ForwardGet(uuid string) (Forward, error) {
	var forwards, err = opn.ForwardList("")
	if err != nil {
		return Forward{}, err
	}
	for _, forward := range forwards {
		if forward.Uuid == uuid {
			return forward, nil
		}
	}
	return Forward{}, &coreapi.NotFoundError{Name: "forward " + uuid}
}

// ForwardCreate adds a forwarding target of forward.Type (forward or dot) and returns its uuid
func (opn *UnboundApi) ForwardCreate(forward Forward) (string, error) {
	var kind, err = forwardKindOf(forward.Type)
	if err != nil {
		return "", err
	}
	forward.Type = ""
	return dnsmodel.Create(opn.OPNsense, kind, forward)
}

// ForwardUpdate changes the fields of patch. forwardType (forward or dot) is the type the entry gets: the
// endpoint of each type stores its own type, so updating with the other type converts the entry.
// *coreapi.NotFoundError for an unknown uuid
func (opn *UnboundApi) ForwardUpdate(uuid string, forwardType string, patch Patch) error {
	var kind, err = forwardKindOf(forwardType)
	if err != nil {
		return err
	}
	if _, err := opn.ForwardGet(uuid); err != nil {
		return err
	}
	var fields = Patch{}
	for name, value := range patch {
		if name != "type" {
			fields[name] = value
		}
	}
	// the existence check of dnsmodel.Update only searches entries of the same type
	_, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.settingsEndpoint("set_"+kind.Method), uuid), map[string]any{kind.Container: fields})
	return err
}

// ForwardRemove deletes a forwarding target of any type
func (opn *UnboundApi) ForwardRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, forwardKind, uuid)
}

// UseSystemNameservers tells whether queries without a forwarding target go to the system's DNS servers
// (Query Forwarding > Use System Nameservers) instead of being resolved recursively
func (opn *UnboundApi) UseSystemNameservers() (bool, error) {
	var settings, err = opn.settings("unbound.forwarding")
	if err != nil {
		return false, err
	}
	return settings.Values["enabled"] == "1", nil
}

// SetUseSystemNameservers changes Query Forwarding > Use System Nameservers
func (opn *UnboundApi) SetUseSystemNameservers(use bool) error {
	var value = "0"
	if use {
		value = "1"
	}
	return opn.SettingsSet(Patch{"forwarding.enabled": value})
}

// SystemNameservers returns the system's DNS servers (System > Settings > General and the DHCP / PPP ones)
func (opn *UnboundApi) SystemNameservers() ([]string, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_nameservers"), nil, &raw); err != nil {
		return nil, err
	}
	var nameservers []string
	if err := json.Unmarshal(raw, &nameservers); err != nil {
		var failure struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &failure) == nil && failure.Message != "" {
			return nil, fmt.Errorf("listing the system nameservers failed: %s", failure.Message)
		}
		return nil, fmt.Errorf("unexpected answer from get_nameservers: %s", raw)
	}
	return nameservers, nil
}

// --- blocklists

// BlocklistList returns the DNSBL policies where any column contains searchPhrase ("" for all)
func (opn *UnboundApi) BlocklistList(searchPhrase string) ([]Blocklist, error) {
	return dnsmodel.Search[Blocklist](opn.OPNsense, blocklistKind, searchPhrase)
}

// BlocklistGet returns the policy with the given uuid or a *coreapi.NotFoundError
func (opn *UnboundApi) BlocklistGet(uuid string) (Blocklist, error) {
	return dnsmodel.Get[Blocklist](opn.OPNsense, blocklistKind, uuid)
}

// BlocklistCreate adds a policy and returns its uuid, a description is required
func (opn *UnboundApi) BlocklistCreate(blocklist Blocklist) (string, error) {
	return dnsmodel.Create(opn.OPNsense, blocklistKind, blocklist)
}

// BlocklistUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid
func (opn *UnboundApi) BlocklistUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, blocklistKind, uuid, patch)
}

// BlocklistRemove deletes a policy
func (opn *UnboundApi) BlocklistRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, blocklistKind, uuid)
}

// BlocklistTypes returns the predefined lists a policy can use: Key like hgz002, Value the name, Group the provider
func (opn *UnboundApi) BlocklistTypes() ([]SettingsOption, error) {
	var answer struct {
		Blocklist map[string]json.RawMessage `json:"blocklist"`
	}
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_dnsbl"), nil, &answer); err != nil {
		return nil, err
	}
	var raw, found = answer.Blocklist["type"]
	if !found {
		return nil, fmt.Errorf("unexpected answer from get_dnsbl: no type field")
	}
	return dnsmodel.ParseOptionList(raw), nil
}

// BlocklistAddDomain adds domain to the allowlist (allow true) or blocklist of the policy and applies just this
// change to the running Unbound (no list download). A domain on the other list is moved
func (opn *UnboundApi) BlocklistAddDomain(uuid string, domain string, allow bool) error {
	if _, err := opn.BlocklistGet(uuid); err != nil {
		return err
	}
	var listType = "blocklists"
	if allow {
		listType = "allowlists"
	}
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.settingsEndpoint("update_blocklist"),
		map[string]string{"domain": domain, "type": listType, "uuid": uuid}, &answer); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(answer.Status), "ok") {
		// "failed" also when the domain is on the list already
		return fmt.Errorf("adding %s to the %s of blocklist %s failed (is it on the list already?): status %q", domain, listType, uuid, answer.Status)
	}
	return nil
}

// BlocklistTestResult is the answer of a blocklist test: Action is Pass or Block, Policy the matching policy
type BlocklistTestResult struct {
	Action string         `json:"action"`
	Policy map[string]any `json:"policy"`
}

// BlocklistTest checks whether a query for domain from source (an address, "" for 127.0.0.1) is blocked by the
// loaded blocklists
func (opn *UnboundApi) BlocklistTest(domain string, source string) (BlocklistTestResult, error) {
	var body = map[string]string{"domain": domain}
	if source != "" {
		body["src"] = source
	}
	var answer struct {
		Status string `json:"status"`
		BlocklistTestResult
	}
	if err := opn.DoJSON("POST", opn.EndpointForPluginControllerMethod("unbound", "diagnostics", "test_blocklist"), body, &answer); err != nil {
		return BlocklistTestResult{}, err
	}
	if !strings.EqualFold(answer.Status, "ok") {
		return BlocklistTestResult{}, fmt.Errorf("the blocklist test failed (status %q), are blocklists loaded? Run the blocklist update first", answer.Status)
	}
	return answer.BlocklistTestResult, nil
}

// --- host aliases

// HostAliasList returns the aliases where any column contains searchPhrase ("" for all)
func (opn *UnboundApi) HostAliasList(searchPhrase string) ([]HostAlias, error) {
	return dnsmodel.Search[HostAlias](opn.OPNsense, aliasKind, searchPhrase)
}

// HostAliasGet returns the alias with the given uuid or a *coreapi.NotFoundError
func (opn *UnboundApi) HostAliasGet(uuid string) (HostAlias, error) {
	return dnsmodel.Get[HostAlias](opn.OPNsense, aliasKind, uuid)
}

// HostAliasCreate adds an alias and returns its uuid; Host (the host override uuid) and a hostname or domain are
// required
func (opn *UnboundApi) HostAliasCreate(alias HostAlias) (string, error) {
	return dnsmodel.Create(opn.OPNsense, aliasKind, alias)
}

// HostAliasUpdate changes the fields of patch, *coreapi.NotFoundError for an unknown uuid
func (opn *UnboundApi) HostAliasUpdate(uuid string, patch Patch) error {
	return dnsmodel.Update(opn.OPNsense, aliasKind, uuid, patch)
}

// HostAliasRemove deletes an alias. Removing a host override removes its aliases too
func (opn *UnboundApi) HostAliasRemove(uuid string) error {
	return dnsmodel.Remove(opn.OPNsense, aliasKind, uuid)
}
