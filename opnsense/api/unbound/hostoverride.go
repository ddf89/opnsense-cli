package unbound

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
)

//goland:noinspection GoNameStartsWithPackageName
type UnboundApi struct {
	*coreapi.OPNsense
}

// HostOverride is an Unbound host override. Fields tagged with omitempty are not sent when empty,
// so OPNsense applies its defaults on create and keeps the current value on update
type HostOverride struct {
	// 0 for disabled, 1 for enabled, empty for the OPNsense default (enabled)
	Enabled string `json:"enabled,omitempty"`
	Host    string `json:"hostname"`
	Domain  string `json:"domain"`
	// IP address for A / AAAA records, unused for MX and TXT
	Ip string `json:"server"`
	// A, AAAA, MX or TXT, empty for the OPNsense default (A)
	Rr          string `json:"rr,omitempty"`
	Mxprio      string `json:"mxprio"`           // 10, 20
	Mx          string `json:"mx"`               // mail.domain.tld ...
	Ttl         string `json:"ttl"`              // seconds, empty for the Unbound default
	Txtdata     string `json:"txtdata"`          // the TXT record content
	Addptr      string `json:"addptr,omitempty"` // 1 to also create a PTR record (OPNsense default), 0 to not
	Description string `json:"description"`      // any arbitrary text
	Uuid        string `json:"uuid"`
}

type hostOverrideContainer struct {
	HostOverride HostOverride `json:"host"`
}

func (opn *UnboundApi) settingsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("unbound", "settings", method)
}

// HostOverrideCreateOrUpdate updates the entry with the given uuid (*coreapi.NotFoundError if it does not exist).
// Without uuid, it updates the entry with the same FQDN (and record type, if set) or creates a new one if there is none
func (opn *UnboundApi) HostOverrideCreateOrUpdate(hostOverride HostOverride) (string, error) {
	if hostOverride.Uuid != "" {
		return opn.HostOverrideUpdate(hostOverride)
	}

	// no uuid given use host / domain based search
	var existing, err = opn.HostOverrideGetByFQDNAndRr(hostOverride.Host, hostOverride.Domain, hostOverride.Rr)
	if coreapi.IsNotFound(err) {
		return opn.HostOverrideCreate(hostOverride)
	}
	if err != nil {
		return "", err
	}
	// just found by the search, no need to check for existence again
	hostOverride.Uuid = existing.Uuid
	return opn.hostOverrideSet(hostOverride)
}

// HostOverrideUpdate replaces the entry identified by hostOverride.Uuid and returns its uuid.
// Returns *coreapi.NotFoundError when the uuid does not exist (checked first, set_host_override would create it)
func (opn *UnboundApi) HostOverrideUpdate(hostOverride HostOverride) (string, error) {
	if hostOverride.Uuid == "" {
		return "", errors.New("cannot update a host override without uuid")
	}
	// set_host_override creates the entry when a well-formed uuid does not exist (yet), so make sure it does
	if _, err := opn.HostOverrideGet(hostOverride.Uuid); err != nil {
		return "", err
	}
	return opn.hostOverrideSet(hostOverride)
}

// hostOverrideSet sends hostOverride to set_host_override/<uuid> without checking that the uuid exists
func (opn *UnboundApi) hostOverrideSet(hostOverride HostOverride) (string, error) {
	var endpoint = fmt.Sprintf("%s/%s", opn.settingsEndpoint("set_host_override"), hostOverride.Uuid)
	if _, err := opn.Mutate(endpoint, hostOverrideContainer{HostOverride: hostOverride}); err != nil {
		// OPNsense answers a malformed uuid with {"result":"failed"} without any validation messages
		var validationErr *coreapi.ValidationError
		if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("host override %s", hostOverride.Uuid), Err: err}
		}
		return "", err
	}
	// set_host_override does not answer with the uuid
	return hostOverride.Uuid, nil
}

// HostOverrideCreate creates a new entry and returns its uuid
func (opn *UnboundApi) HostOverrideCreate(hostOverride HostOverride) (string, error) {
	return opn.Mutate(opn.settingsEndpoint("add_host_override"), hostOverrideContainer{HostOverride: hostOverride})
}

// HostOverrideSearch returns all entries where any column contains searchPhrase, use "" for all entries
func (opn *UnboundApi) HostOverrideSearch(searchPhrase string) ([]HostOverride, error) {
	return coreapi.Search[HostOverride](opn.OPNsense, opn.settingsEndpoint("search_host_override"), searchPhrase)
}

func (opn *UnboundApi) HostOverrideList() ([]HostOverride, error) {
	return opn.HostOverrideSearch("")
}

// HostOverrideGet returns the entry with the given uuid
func (opn *UnboundApi) HostOverrideGet(uuid string) (HostOverride, error) {
	// get_host_override/<uuid> answers with option lists instead of plain values, so we filter the search result
	var hostOverrides, err = opn.HostOverrideList()
	if err != nil {
		return HostOverride{}, err
	}

	var matching = coreapi.Filter(hostOverrides, func(override HostOverride) bool {
		return override.Uuid == uuid
	})
	if len(matching) == 0 {
		return HostOverride{}, &coreapi.NotFoundError{Name: fmt.Sprintf("host override %s", uuid)}
	}
	return matching[0], nil
}

// HostOverrideFindByFQDN returns all entries with exactly the given host and domain (case-insensitive).
// rr limits the result to one record type, use "" for all types
func (opn *UnboundApi) HostOverrideFindByFQDN(host string, domain string, rr string) ([]HostOverride, error) {
	// searchPhrase is a substring match over all columns and does not support searching for FQDN,
	// so we search for the host (or the domain) and filter the result
	var searchPhrase = host
	if searchPhrase == "" {
		searchPhrase = domain
	}
	var hostOverrides, err = opn.HostOverrideSearch(searchPhrase)
	if err != nil {
		return nil, err
	}

	var trimmedDomain = strings.TrimSuffix(domain, ".")
	return coreapi.Filter(hostOverrides, func(override HostOverride) bool {
		return strings.EqualFold(override.Host, host) &&
			strings.EqualFold(strings.TrimSuffix(override.Domain, "."), trimmedDomain) &&
			(rr == "" || strings.EqualFold(override.Rr, rr))
	}), nil
}

// HostOverrideGetByFQDNAndRr returns the only entry matching host, domain and rr (use "" for any record type).
// Returns *coreapi.NotFoundError if there is none and *coreapi.TooManyFoundError if there is more than one
func (opn *UnboundApi) HostOverrideGetByFQDNAndRr(host string, domain string, rr string) (HostOverride, error) {
	var matching, err = opn.HostOverrideFindByFQDN(host, domain, rr)
	if err != nil {
		return HostOverride{}, err
	}

	var name = fmt.Sprintf("host override %s.%s", host, domain)
	if rr != "" {
		name = fmt.Sprintf("%s (%s)", name, rr)
	}

	if len(matching) > 1 {
		var uuids = make([]string, 0, len(matching))
		for _, override := range matching {
			uuids = append(uuids, fmt.Sprintf("%s (%s)", override.Uuid, override.Rr))
		}
		return HostOverride{}, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("%s matches %s", name, strings.Join(uuids, ", ")),
		}
	}
	if len(matching) == 0 {
		return HostOverride{}, &coreapi.NotFoundError{Name: name}
	}
	return matching[0], nil
}

// HostEntryGetByFQDN returns the only entry with exactly the given host and domain, regardless of the record type
func (opn *UnboundApi) HostEntryGetByFQDN(host string, domain string) (HostOverride, error) {
	return opn.HostOverrideGetByFQDNAndRr(host, domain, "")
}

// HostEntryRemove deletes the entry with the given uuid, returns *coreapi.NotFoundError if it does not exist
func (opn *UnboundApi) HostEntryRemove(uuid string) error {
	if uuid == "" {
		return errors.New("cannot remove a host override without uuid")
	}

	var endpoint = fmt.Sprintf("%s/%s", opn.settingsEndpoint("del_host_override"), uuid)
	if _, err := opn.Mutate(endpoint, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("host override %s", uuid), Err: err}
		}
		return err
	}
	return nil
}

func (opn *UnboundApi) HostEntryExists(host string, domain string) (bool, error) {
	if _, err := opn.HostEntryGetByFQDN(host, domain); err != nil {
		if coreapi.IsNotFound(err) {
			return false, nil
		}
		return true, err
	}
	// else found something
	return true, nil
}
