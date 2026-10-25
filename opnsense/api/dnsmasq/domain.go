package dnsmasq

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strings"
)

// DomainOverride forwards queries for Domain (and its subdomains) to the upstream server Ip#Port,
// which renders as dnsmasq "server=/Domain/Ip#Port@Srcip". Without an Ip, dnsmasq answers the domain locally only
type DomainOverride struct {
	Uuid string `json:"uuid,omitempty"`
	// Sequence orders the generated server lines, 1-99999 (OPNsense defaults to 1)
	Sequence string `json:"sequence,omitempty"`
	Domain   string `json:"domain"`
	// Ip is the upstream DNS server (IPv4 or IPv6), empty to answer the domain locally
	Ip string `json:"ip"`
	// Port of the upstream server, empty for the default (53)
	Port string `json:"port"`
	// Srcip is the source IP address used for queries to the upstream server
	Srcip string `json:"srcip"`
	// Ipset is a firewall alias name the resolved addresses are added to, empty for none
	Ipset       string `json:"ipset,omitempty"`
	Description string `json:"descr"`
}

// DomainOverrideFields are the fields to change with DomainOverrideUpdate. Only non nil fields are sent,
// OPNsense keeps all others (set_domain is a partial merge). Use a pointer to "" to clear a field
type DomainOverrideFields struct {
	Sequence    *string `json:"sequence,omitempty"`
	Domain      *string `json:"domain,omitempty"`
	Ip          *string `json:"ip,omitempty"`
	Port        *string `json:"port,omitempty"`
	Srcip       *string `json:"srcip,omitempty"`
	Ipset       *string `json:"ipset,omitempty"`
	Description *string `json:"descr,omitempty"`
}

// DomainOverrideList returns all domain overrides, searchPhrase is a substring match over all columns ("" for all)
func (opn *DnsmasqApi) DomainOverrideList(searchPhrase string) ([]DomainOverride, error) {
	return coreapi.Search[DomainOverride](opn.OPNsense, opn.settingsEndpoint("search_domain"), searchPhrase)
}

// DomainOverrideGet returns the domain override with the given uuid or a *NotFoundError
func (opn *DnsmasqApi) DomainOverrideGet(uuid string) (DomainOverride, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.settingsEndpoint("get_domain/"+uuid), nil, &raw); err != nil {
		return DomainOverride{}, err
	}

	// unknown uuids are answered with an empty array
	var container struct {
		DomainOverride *struct {
			DomainOverride
			// get_* returns option fields as {"<key>":{"value":"..","selected":1}}
			Ipset json.RawMessage `json:"ipset"`
		} `json:"domainoverride"`
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return DomainOverride{}, &coreapi.NotFoundError{Name: fmt.Sprintf("domain override %s", uuid)}
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return DomainOverride{}, err
	}
	if container.DomainOverride == nil {
		return DomainOverride{}, &coreapi.NotFoundError{Name: fmt.Sprintf("domain override %s", uuid)}
	}

	var domainOverride = container.DomainOverride.DomainOverride
	domainOverride.Uuid = uuid
	domainOverride.Ipset = domainOverrideSelectedOption(container.DomainOverride.Ipset)
	return domainOverride, nil
}

// DomainOverrideFindAll returns all domain overrides for domain (exact, case-insensitive match, trailing dot ignored).
// An ip != "" additionally filters on the upstream server ip. Returns an empty list when nothing matches
func (opn *DnsmasqApi) DomainOverrideFindAll(domain string, ip string) ([]DomainOverride, error) {
	var domainOverrides, err = opn.DomainOverrideList(domainOverrideNormalizeDomain(domain))
	if err != nil {
		return nil, err
	}

	return coreapi.Filter(domainOverrides, func(d DomainOverride) bool {
		return domainOverrideNormalizeDomain(d.Domain) == domainOverrideNormalizeDomain(domain) && (ip == "" || domainOverrideSameIp(d.Ip, ip))
	}), nil
}

// DomainOverrideFind returns the single domain override for domain (and ip, when not empty).
// Returns *NotFoundError if there is none and *TooManyFoundError if the lookup is ambiguous, e.g. a domain forwarded to several servers
func (opn *DnsmasqApi) DomainOverrideFind(domain string, ip string) (DomainOverride, error) {
	var matches, err = opn.DomainOverrideFindAll(domain, ip)
	if err != nil {
		return DomainOverride{}, err
	}

	var name = domain
	if ip != "" {
		name = fmt.Sprintf("%s (ip %s)", domain, ip)
	}
	switch len(matches) {
	case 0:
		return DomainOverride{}, &coreapi.NotFoundError{Name: fmt.Sprintf("domain override %s", name)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, fmt.Sprintf("%s (ip %q)", match.Uuid, match.Ip))
		}
		return DomainOverride{}, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("domain override %s, %d candidates: %s", name, len(matches), strings.Join(uuids, ", ")),
		}
	}
}

// DomainOverrideCreate adds a domain override and returns its uuid. Uuid is ignored, an empty Sequence uses the OPNsense default
func (opn *DnsmasqApi) DomainOverrideCreate(domainOverride DomainOverride) (string, error) {
	domainOverride.Uuid = ""
	var container = map[string]any{"domainoverride": domainOverride}
	return opn.Mutate(opn.settingsEndpoint("add_domain"), container)
}

// DomainOverrideCreateOrUpdate updates the entry with the same domain AND ip (an empty ip matches only entries without ip),
// otherwise creates a new one, so one domain can be forwarded to several servers. Returns the uuid and whether it was created.
// On update every field is sent except an empty Sequence or Ipset, which are kept
func (opn *DnsmasqApi) DomainOverrideCreateOrUpdate(domainOverride DomainOverride) (string, bool, error) {
	var candidates, err = opn.DomainOverrideFindAll(domainOverride.Domain, "")
	if err != nil {
		return "", false, err
	}
	var matches = coreapi.Filter(candidates, func(d DomainOverride) bool {
		return domainOverrideSameIp(d.Ip, domainOverride.Ip)
	})

	switch len(matches) {
	case 0:
		var uuid, createErr = opn.DomainOverrideCreate(domainOverride)
		return uuid, true, createErr
	case 1:
		var fields = DomainOverrideFields{
			Domain:      &domainOverride.Domain,
			Ip:          &domainOverride.Ip,
			Port:        &domainOverride.Port,
			Srcip:       &domainOverride.Srcip,
			Description: &domainOverride.Description,
		}
		if domainOverride.Sequence != "" {
			fields.Sequence = &domainOverride.Sequence
		}
		if domainOverride.Ipset != "" {
			fields.Ipset = &domainOverride.Ipset
		}
		// just found by the search, no need to check for existence again
		return matches[0].Uuid, false, opn.domainOverrideSet(matches[0].Uuid, fields)
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, match.Uuid)
		}
		return "", false, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("domain override %s (ip %q), %d candidates: %s", domainOverride.Domain, domainOverride.Ip, len(matches), strings.Join(uuids, ", ")),
		}
	}
}

// DomainOverrideUpdate changes only the non nil fields of the domain override uuid.
// Returns *NotFoundError when the uuid does not exist (checked first, set_domain would create it)
func (opn *DnsmasqApi) DomainOverrideUpdate(uuid string, fields DomainOverrideFields) error {
	if uuid == "" {
		return errors.New("cannot update a domain override without uuid")
	}
	// set_domain creates the entry when a well-formed uuid does not exist (yet), so make sure it does
	if _, err := opn.DomainOverrideGet(uuid); err != nil {
		return err
	}
	return opn.domainOverrideSet(uuid, fields)
}

// domainOverrideSet sends fields to set_domain/uuid without checking that uuid exists
func (opn *DnsmasqApi) domainOverrideSet(uuid string, fields DomainOverrideFields) error {
	var container = map[string]any{"domainoverride": fields}
	var _, err = opn.Mutate(opn.settingsEndpoint("set_domain/"+uuid), container)

	// set_domain answers malformed uuids with a bare {"result":"failed"}
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("domain override %s", uuid)}
	}
	return err
}

// DomainOverrideRemove deletes the domain override uuid, returns *NotFoundError if it does not exist
func (opn *DnsmasqApi) DomainOverrideRemove(uuid string) error {
	var _, err = opn.Mutate(opn.settingsEndpoint("del_domain/"+uuid), map[string]any{})
	return err
}

// domainOverrideSameIp compares two ip addresses semantically (e.g. "fd00::1" equals "FD00:0::1"), falling back to string comparison
func domainOverrideSameIp(a string, b string) bool {
	var ipA, ipB = net.ParseIP(a), net.ParseIP(b)
	if ipA != nil && ipB != nil {
		return ipA.Equal(ipB)
	}
	return strings.EqualFold(a, b)
}

func domainOverrideNormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// domainOverrideSelectedOption returns the selected key of an OPNsense option map, or the plain string value
func domainOverrideSelectedOption(raw json.RawMessage) string {
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain
	}

	var options map[string]struct {
		Selected any `json:"selected"`
	}
	if err := json.Unmarshal(raw, &options); err != nil {
		return ""
	}
	var selected = make([]string, 0)
	for key, option := range options {
		if fmt.Sprint(option.Selected) == "1" {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return strings.Join(selected, ",")
}
