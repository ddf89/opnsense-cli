package firewall

import (
	"errors"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
)

// The GeoIP settings of Firewall > Aliases (the "GeoIP settings" tab). Behaviour of OPNsense 26.7 this relies on:
//   - the source URL is alias.geoip.url of the alias model; firewall/alias/set with only {"alias":{"geoip":{...}}}
//     changes it and keeps every alias (setNodes only touches the given nodes, verified live)
//   - the updater reads the URL from /usr/local/etc/filter_geoip.conf, which only alias reconfigure (apply)
//     writes: a new URL is used by downloads after the next apply. With an empty URL a business subscription
//     falls back to the subscription mirror
//   - get_geo_ip adds the statistics of the last download (alias.stats); without one only usages and
//     address_count are there. timestamp is the date of the database files for zip sources (MaxMind), the time
//     of the download for gz sources (ipinfo)
//   - update/geoip answers "ok" whatever the download did, only the statistics tell whether it worked

// AliasGeoIP are the GeoIP settings and the statistics of the last download, as get_geo_ip returns them
type AliasGeoIP struct {
	// Url is the download URL of the GeoIP database; it usually contains a license key
	Url string `json:"url"`
	// Usages is the number of geoip aliases
	Usages int `json:"usages"`
	// Subscription is only set when a firmware mirror is configured: whether it is the business mirror (which
	// is the source when Url is empty)
	Subscription *bool `json:"subscription,omitempty"`
	// AddressCount and FileCount are the networks and country files of the last download
	AddressCount int `json:"address_count"`
	FileCount    int `json:"file_count"`
	// Timestamp is the date of the downloaded data, "" when there is none
	Timestamp         string `json:"timestamp"`
	LocationsFilename string `json:"locations_filename"`
	// AddressSources are the files of the archive the IPv4 and IPv6 networks came from
	AddressSources struct {
		IPv4 string `json:"IPv4"`
		IPv6 string `json:"IPv6"`
	} `json:"address_sources"`
}

// AliasGeoIPGet returns the GeoIP settings with the statistics of the last download
func (opn *FirewallApi) AliasGeoIPGet() (AliasGeoIP, error) {
	var container struct {
		Alias struct {
			GeoIP *AliasGeoIP `json:"geoip"`
		} `json:"alias"`
	}
	if err := opn.DoJSON("GET", opn.aliasEndpoint("get_geo_ip"), nil, &container); err != nil {
		return AliasGeoIP{}, err
	}
	if container.Alias.GeoIP == nil {
		return AliasGeoIP{}, errors.New(`unexpected answer from get_geo_ip: no "alias.geoip"`)
	}
	return *container.Alias.GeoIP, nil
}

// AliasGeoIPSetUrl changes the download URL of the GeoIP database ("" for none), the aliases are not touched. It
// is used after the next AliasReconfigure. A rejected URL is a *ValidationError keyed "url"
func (opn *FirewallApi) AliasGeoIPSetUrl(url string) error {
	var body = map[string]any{"alias": map[string]any{"geoip": map[string]string{"url": url}}}
	var _, err = opn.Mutate(opn.aliasEndpoint("set"), body)
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var stripped = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		stripped[strings.TrimPrefix(field, "alias.geoip.")] = message
	}
	return &coreapi.ValidationError{Validations: stripped}
}

// AliasGeoIPUpdate downloads the GeoIP database from the URL of the last AliasReconfigure and returns the new
// statistics. OPNsense does not report download errors (they go to the system log): an AddressCount of 0 means
// nothing usable was downloaded
func (opn *FirewallApi) AliasGeoIPUpdate() (AliasGeoIP, error) {
	if err := opn.AliasUpdateTables("geoip"); err != nil {
		return AliasGeoIP{}, err
	}
	return opn.AliasGeoIPGet()
}
