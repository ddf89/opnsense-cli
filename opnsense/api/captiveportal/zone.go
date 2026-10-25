package captiveportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Zone is a captive portal zone of Services > Captive Portal > Administration (api/captiveportal/settings), as
// search_zones returns it. Lists are comma separated, flags "0"/"1".
//
// A zone only has an effect when it is enabled AND the configuration is applied (ServiceReconfigure): then the
// firewall redirects the clients on its interfaces to the portal. Interfaces must be enabled interfaces with a
// static address (OPNsense offers lan by default, never DHCP interfaces like a typical wan)
type Zone struct {
	Uuid    string `json:"uuid"`
	Enabled string `json:"enabled"`
	// ZoneId is the zone number 0-19, assigned by OPNsense
	ZoneId string `json:"zoneid"`
	// Interfaces are interface keys (lan, opt1), InterfaceNames their descriptions
	Interfaces     string `json:"interfaces"`
	InterfaceNames string `json:"%interfaces"`
	DisableRules   string `json:"disableRules"`
	// AuthServers are names of authentication servers ("Local Database", a voucher server), empty: no login
	AuthServers              string `json:"authservers"`
	Roaming                  string `json:"roaming"`
	AlwaysSendAccountingReqs string `json:"alwaysSendAccountingReqs"`
	// AuthEnforceGroup is a group gid
	AuthEnforceGroup string `json:"authEnforceGroup"`
	// IdleTimeout and HardTimeout are minutes, 0 for none
	IdleTimeout      string `json:"idletimeout"`
	HardTimeout      string `json:"hardtimeout"`
	ConcurrentLogins string `json:"concurrentlogins"`
	// Certificate is the refid of the certificate for the https portal, ServerName its host name
	Certificate         string `json:"certificate"`
	ServerName          string `json:"servername"`
	AllowedAddresses    string `json:"allowedAddresses"`
	AllowedMACAddresses string `json:"allowedMACAddresses"`
	ExtendedPreAuthData string `json:"extendedPreAuthData"`
	// Template is the uuid of a custom template, "" for the default portal page
	Template    string `json:"template"`
	Description string `json:"description"`
}

// ZoneFields holds a partial zone for ZoneCreate / ZoneUpdate keyed by the API field name (see ZoneFieldNames)
type ZoneFields map[string]string

// ZoneFieldNames are the writable fields of a zone
var ZoneFieldNames = []string{"enabled", "interfaces", "disableRules", "authservers", "roaming", "alwaysSendAccountingReqs",
	"authEnforceGroup", "idletimeout", "hardtimeout", "concurrentlogins", "certificate", "servername", "allowedAddresses",
	"allowedMACAddresses", "extendedPreAuthData", "template", "description"}

func zoneName(uuid string) string {
	return "captive portal zone " + uuid
}

func checkZoneFields(fields ZoneFields) error {
	for name := range fields {
		if !slices.Contains(ZoneFieldNames, name) {
			return fmt.Errorf("unknown captive portal zone field %q", name)
		}
	}
	return nil
}

// ZoneListRaw returns the zones where any column contains searchPhrase ("" for all) in API order, with the raw rows
func (opn *CaptivePortalApi) ZoneListRaw(searchPhrase string) ([]json.RawMessage, []Zone, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("settings", "search_zones"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var zones = make([]Zone, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &zones[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected captive portal zone from OPNsense: %w", err)
		}
	}
	return rows, zones, nil
}

// ZoneList returns the zones, searchPhrase is a substring match over all columns ("" for all)
func (opn *CaptivePortalApi) ZoneList(searchPhrase string) ([]Zone, error) {
	var _, zones, err = opn.ZoneListRaw(searchPhrase)
	return zones, err
}

// ZoneGet returns the zone with the given uuid or a *NotFoundError (get_zone answers unknown uuids with [])
func (opn *CaptivePortalApi) ZoneGet(uuid string) (Zone, error) {
	if uuid == "" {
		return Zone{}, errors.New("uuid must not be empty")
	}
	var zones, err = opn.ZoneList("")
	if err != nil {
		return Zone{}, err
	}
	for _, zone := range zones {
		if strings.EqualFold(zone.Uuid, uuid) {
			return zone, nil
		}
	}
	return Zone{}, &coreapi.NotFoundError{Name: zoneName(uuid)}
}

// ZoneGetByDescription returns the only zone with this description (case-insensitive), *NotFoundError when there
// is none, *TooManyFoundError when there are several
func (opn *CaptivePortalApi) ZoneGetByDescription(description string) (Zone, error) {
	if description == "" {
		return Zone{}, errors.New("cannot look up a captive portal zone by an empty description")
	}
	var zones, err = opn.ZoneList(description)
	if err != nil {
		return Zone{}, err
	}
	var matches = coreapi.Filter(zones, func(zone Zone) bool { return strings.EqualFold(zone.Description, description) })
	switch len(matches) {
	case 0:
		return Zone{}, &coreapi.NotFoundError{Name: fmt.Sprintf("captive portal zone %q", description)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid
		}
		sort.Strings(uuids)
		return Zone{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d captive portal zones with description %q (uuids: %s)",
			len(matches), description, strings.Join(uuids, ", "))}
	}
}

// ZoneOptions returns the option lists of a new zone (get_zone) by API field name: interfaces (the eligible
// interfaces), authservers, authEnforceGroup (groups by gid), certificate (refid) and template (uuid)
func (opn *CaptivePortalApi) ZoneOptions() (map[string][]Option, error) {
	var endpoint = opn.endpoint("settings", "get_zone")
	var answer struct {
		Zone map[string]json.RawMessage `json:"zone"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	if answer.Zone == nil {
		return nil, fmt.Errorf("unexpected answer from %s", endpoint)
	}
	var options = map[string][]Option{}
	for name, raw := range answer.Zone {
		var trimmed = bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}
		var parsed, err = parseOptionObject(trimmed)
		if err != nil {
			return nil, fmt.Errorf("could not decode %s field %s: %w", endpoint, name, err)
		}
		options[name] = parsed
	}
	return options, nil
}

// ZoneCreate adds a zone and returns its uuid. Zones are enabled by default, send "enabled":"0" to add one without
// effect. Duplicate descriptions are not checked
func (opn *CaptivePortalApi) ZoneCreate(fields ZoneFields) (string, error) {
	if err := checkZoneFields(fields); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("settings", "add_zone"), map[string]ZoneFields{"zone": fields})
}

// ZoneUpdate sends only the given fields to the zone with this uuid, the others are kept. Returns *NotFoundError
// when the uuid does not exist (checked first, set_zone would create it)
func (opn *CaptivePortalApi) ZoneUpdate(uuid string, fields ZoneFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := checkZoneFields(fields); err != nil {
		return err
	}
	if _, err := opn.ZoneGet(uuid); err != nil {
		return err
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("settings", "set_zone"), uuid), map[string]ZoneFields{"zone": fields})
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: zoneName(uuid), Err: err}
	}
	return err
}

// ZoneRemove deletes the zone with this uuid, *NotFoundError when it does not exist. An active zone keeps working
// until the configuration is applied
func (opn *CaptivePortalApi) ZoneRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a captive portal zone by uuid %q", uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("settings", "del_zone"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: zoneName(uuid), Err: err}
	}
	return err
}

// ZoneSetEnabled enables or disables the zone with this uuid (toggle_zone/<uuid>/<0|1>) and returns whether its
// state changed. Like every change it takes effect with ServiceReconfigure
func (opn *CaptivePortalApi) ZoneSetEnabled(uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("uuid must not be empty")
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.endpoint("settings", "toggle_zone"), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		if (result.Result == "Enabled") != enabled {
			return false, fmt.Errorf("toggle_zone answered %q", result.Result)
		}
		return result.Changed, nil
	case "failed": // unknown uuid
		return false, &coreapi.NotFoundError{Name: zoneName(uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}
