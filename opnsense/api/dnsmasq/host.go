package dnsmasq

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Host is a Dnsmasq host override / DHCP reservation (api/dnsmasq/settings/*_host).
// List fields (Ip, Cnames, Hwaddr, Aliases) are comma separated strings, e.g. Ip "10.1.1.1,fd00::1"
type Host struct {
	Uuid        string `json:"uuid,omitempty"`
	Host        string `json:"host"`
	Domain      string `json:"domain"`
	Local       string `json:"local"` // "1": domain is local, only answered from hosts/DHCP
	Ip          string `json:"ip"`
	Cnames      string `json:"cnames"`
	ClientId    string `json:"client_id"`
	Hwaddr      string `json:"hwaddr"`
	LeaseTime   string `json:"lease_time"`
	Ignore      string `json:"ignore"`            // "1": ignore DHCP requests of this client
	SetTag      string `json:"set_tag,omitempty"` // tag uuid when writing, search rows return the tag name
	Description string `json:"descr"`
	Comments    string `json:"comments"`
	Aliases     string `json:"aliases"`
}

// HostFields holds a partial host for HostUpdate, keyed by the API field name (see HostFieldNames).
// Only the given keys are sent, OPNsense keeps all other fields. An empty value clears the field
type HostFields map[string]string

// HostFieldNames are the writable fields of a host
var HostFieldNames = []string{
	"host", "domain", "local", "ip", "cnames", "client_id", "hwaddr", "lease_time",
	"ignore", "set_tag", "descr", "comments", "aliases",
}

// FQDN returns host.domain, or only host when there is no domain
func (h Host) FQDN() string {
	if h.Domain == "" {
		return h.Host
	}
	return fmt.Sprintf("%s.%s", h.Host, h.Domain)
}

// Fields returns all writable fields of h, set_tag only when it is set
func (h Host) Fields() HostFields {
	var fields = HostFields{
		"host":       h.Host,
		"domain":     h.Domain,
		"local":      boolOrZero(h.Local),
		"ip":         h.Ip,
		"cnames":     h.Cnames,
		"client_id":  h.ClientId,
		"hwaddr":     h.Hwaddr,
		"lease_time": h.LeaseTime,
		"ignore":     boolOrZero(h.Ignore),
		"descr":      h.Description,
		"comments":   h.Comments,
		"aliases":    h.Aliases,
	}
	if h.SetTag != "" {
		fields["set_tag"] = h.SetTag
	}
	return fields
}

func boolOrZero(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

// HostList returns all hosts, searchPhrase is a substring match over all columns ("" for all)
func (opn *DnsmasqApi) HostList(searchPhrase string) ([]Host, error) {
	return coreapi.Search[Host](opn.OPNsense, opn.settingsEndpoint("search_host"), searchPhrase)
}

// HostGet returns the host with the given uuid or a *NotFoundError
func (opn *DnsmasqApi) HostGet(uuid string) (Host, error) {
	var hosts, err = opn.HostList("")
	if err != nil {
		return Host{}, err
	}
	for _, host := range hosts {
		if host.Uuid == uuid {
			return host, nil
		}
	}
	return Host{}, &coreapi.NotFoundError{Name: fmt.Sprintf("dnsmasq host %s", uuid)}
}

// HostFindByFQDN returns all hosts whose hostname and domain match exactly (case-insensitive).
// An empty domain only matches hosts without a domain
func (opn *DnsmasqApi) HostFindByFQDN(hostname string, domain string) ([]Host, error) {
	if hostname == "" {
		return nil, errors.New("hostname must not be empty")
	}
	// searchPhrase is a substring match and not FQDN aware, so narrow down by hostname and compare exactly
	var hosts, err = opn.HostList(hostname)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(hosts, func(host Host) bool {
		return strings.EqualFold(host.Host, hostname) && strings.EqualFold(host.Domain, domain)
	}), nil
}

// HostGetByFQDN returns the single host matching hostname and domain exactly (see HostFindByFQDN).
// Returns *NotFoundError when there is none, *TooManyFoundError (naming the candidate uuids) when there are duplicates
func (opn *DnsmasqApi) HostGetByFQDN(hostname string, domain string) (Host, error) {
	var matches, err = opn.HostFindByFQDN(hostname, domain)
	if err != nil {
		return Host{}, err
	}

	var fqdn = Host{Host: hostname, Domain: domain}.FQDN()
	switch len(matches) {
	case 0:
		return Host{}, &coreapi.NotFoundError{Name: fmt.Sprintf("dnsmasq host %s", fqdn)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, match.Uuid)
		}
		sort.Strings(uuids)
		return Host{}, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("%d dnsmasq hosts named %s (uuids: %s)", len(matches), fqdn, strings.Join(uuids, ", ")),
		}
	}
}

// HostCreate adds a new host and returns its uuid. Duplicates are not checked, see HostCreateOrUpdate
func (opn *DnsmasqApi) HostCreate(host Host) (string, error) {
	var body = map[string]HostFields{"host": host.Fields()}
	return opn.Mutate(opn.settingsEndpoint("add_host"), body)
}

// HostUpdate sends only the given fields to the host with the given uuid, all other fields are kept.
// Returns *NotFoundError when the uuid does not exist (checked first, set_host would create it),
// *ValidationError when OPNsense rejects the change
func (opn *DnsmasqApi) HostUpdate(uuid string, fields HostFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	for name := range fields {
		if !slices.Contains(HostFieldNames, name) {
			return fmt.Errorf("unknown dnsmasq host field %q", name)
		}
	}

	// set_host creates the entry when a well-formed uuid does not exist (yet), so make sure it does
	if _, err := opn.HostGet(uuid); err != nil {
		return err
	}
	return opn.hostSet(uuid, fields)
}

// hostSet sends fields to set_host/uuid without checking that uuid exists
func (opn *DnsmasqApi) hostSet(uuid string, fields HostFields) error {
	var body = map[string]HostFields{"host": fields}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.settingsEndpoint("set_host"), uuid), body)

	// set_host answers a malformed uuid with a plain {"result":"failed"} without any validation messages
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("dnsmasq host %s", uuid), Err: err}
	}
	return err
}

// HostCreateOrUpdate creates host, or when host.Uuid is set / a host with the same FQDN exists, overwrites that entry
// with all fields of host (fields left empty are cleared, set_tag is only changed when set).
// Returns the uuid and whether an existing entry was updated. Duplicate FQDNs return a *TooManyFoundError,
// a host.Uuid which does not exist a *NotFoundError
func (opn *DnsmasqApi) HostCreateOrUpdate(host Host) (string, bool, error) {
	if host.Uuid != "" {
		return host.Uuid, true, opn.HostUpdate(host.Uuid, host.Fields())
	}

	var existing, err = opn.HostGetByFQDN(host.Host, host.Domain)
	if coreapi.IsNotFound(err) {
		var created, createErr = opn.HostCreate(host)
		return created, false, createErr
	}
	if err != nil {
		return "", false, err
	}
	// just found by the search, no need to check for existence again
	return existing.Uuid, true, opn.hostSet(existing.Uuid, host.Fields())
}

// HostRemove deletes the host with the given uuid, returns *NotFoundError when it does not exist
func (opn *DnsmasqApi) HostRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.settingsEndpoint("del_host"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("dnsmasq host %s", uuid), Err: err}
	}
	return err
}
