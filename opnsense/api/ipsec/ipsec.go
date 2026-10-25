// Package ipsec wraps the IPsec API of OPNsense 26.7 behind VPN > IPsec (api/ipsec/...): the swanctl
// connections with their local and remote authentication rounds and children (connections), address pools
// (pools), virtual tunnel interfaces (vti), manual SPD entries (manual_spd), pre-shared keys (pre_shared_keys),
// key pairs (key_pairs), the mobile and advanced settings (settings), the service, and the status pages:
// sessions, SAD, SPD and leases.
//
// The configuration records are handled generically as Record (a search row) and written with Fields (only the
// given API fields are sent). Every resource has a list of writable field names, unknown names are refused.
//
// Quirks (OPNsense 26.7, verified live): set_* creates a record for an unknown well-formed uuid and answers a
// malformed one with a bare "failed", so updates check existence first; get_connection/<unknown> answers a fresh
// default record, the other get_* answer []; deleting a connection deletes its locals, remotes and children, but
// deleting a key pair, pool or child does not check whether a connection, round or manual SPD entry uses it;
// search rows of pre-shared keys and key pairs contain the keys in clear text (see SecretFields)
package ipsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// IPsecApi is the IPsec API on an OPNsense connection
//
//goland:noinspection GoNameStartsWithPackageName
type IPsecApi struct {
	*coreapi.OPNsense
}

func (opn *IPsecApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("ipsec", controller, method)
}

// uuidPattern matches the v4 uuids OPNsense generates, set_* refuses anything else with a bare "failed"
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUuid tells whether s looks like a record uuid
func IsUuid(s string) bool {
	return uuidPattern.MatchString(s)
}

// Record is one row of a search endpoint: every value as a string (numbers in their JSON spelling, booleans as
// "1"/"0", null as "", lists comma joined). Option fields hold the option key(s), their display text is in
// Display (OPNsense sends it as "%field")
type Record struct {
	values map[string]string
	raw    json.RawMessage
}

// NewRecord builds a record from values, e.g. for tests
func NewRecord(values map[string]string) Record {
	var raw, _ = json.Marshal(values)
	return Record{values: values, raw: raw}
}

func (r *Record) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	r.values = make(map[string]string, len(fields))
	for name, value := range fields {
		r.values[name] = recordValue(value)
	}
	r.raw = append(json.RawMessage(nil), data...)
	return nil
}

func (r Record) MarshalJSON() ([]byte, error) {
	if r.raw == nil {
		return []byte("{}"), nil
	}
	return r.raw, nil
}

// recordValue renders one JSON value as text
func recordValue(raw json.RawMessage) string {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	switch trimmed[0] {
	case '"':
		var s string
		_ = json.Unmarshal(trimmed, &s)
		return s
	case 'n':
		return ""
	case 't':
		return "1"
	case 'f':
		return "0"
	case '[':
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return string(trimmed)
		}
		var elements = make([]string, 0, len(list))
		for _, element := range list {
			elements = append(elements, recordValue(element))
		}
		return strings.Join(elements, ",")
	default: // numbers, objects
		return string(trimmed)
	}
}

// Uuid returns the uuid of a configuration record
func (r Record) Uuid() string {
	return r.values["uuid"]
}

// Value returns the value of a field, "" when it is missing
func (r Record) Value(field string) string {
	return r.values[field]
}

// Has tells whether the row contains the field
func (r Record) Has(field string) bool {
	var _, found = r.values[field]
	return found
}

// Display returns the display text OPNsense sends for an option field ("%field"), else the value
func (r Record) Display(field string) string {
	if display, found := r.values["%"+field]; found && display != "" {
		return display
	}
	return r.values[field]
}

// Enabled tells whether the enabled field of a configuration record is set
func (r Record) Enabled() bool {
	return r.values["enabled"] == "1"
}

// Values returns a copy of all values
func (r Record) Values() map[string]string {
	var values = make(map[string]string, len(r.values))
	for name, value := range r.values {
		values[name] = value
	}
	return values
}

// Raw returns the row as OPNsense sent it
func (r Record) Raw() json.RawMessage {
	return r.raw
}

// Fields holds a partial record for the Create / Update functions keyed by the API field name. Only the given
// keys are sent, OPNsense keeps all other fields (or uses its defaults on create). An empty value clears a field
type Fields map[string]string

// resource describes one configuration list of the IPsec API
type resource struct {
	controller string // api/ipsec/<controller>
	search     string
	get        string
	add        string
	set        string
	del        string
	toggle     string   // "" when the list has no enabled flag
	container  string   // the key of the record in get/add/set bodies, e.g. "connection"
	noun       string   // for messages, e.g. "ipsec connection"
	fields     []string // the writable fields
}

func (res resource) endpoint(opn *IPsecApi, method string) string {
	return opn.endpoint(res.controller, method)
}

func (res resource) name(uuid string) string {
	return fmt.Sprintf("%s %s", res.noun, uuid)
}

func (res resource) checkFields(fields Fields) error {
	for name := range fields {
		if !slices.Contains(res.fields, name) {
			return fmt.Errorf("unknown %s field %q", res.noun, name)
		}
	}
	return nil
}

// list returns the rows of the search endpoint, query are additional parameters (e.g. connection=<uuid>)
func (opn *IPsecApi) list(res resource, searchPhrase string, query url.Values) ([]Record, error) {
	var params = url.Values{}
	for name, values := range query {
		params[name] = values
	}
	if searchPhrase != "" {
		params.Set("searchPhrase", searchPhrase)
	}
	var endpoint = res.endpoint(opn, res.search)
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	var container struct {
		Rows []Record `json:"rows"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	if container.Rows == nil {
		container.Rows = []Record{}
	}
	return container.Rows, nil
}

// getRecord returns the row with this uuid or a *NotFoundError (get_* can not tell unknown uuids)
func (opn *IPsecApi) getRecord(res resource, uuid string) (Record, error) {
	if uuid == "" {
		return Record{}, fmt.Errorf("cannot look up an %s without uuid", res.noun)
	}
	var records, err = opn.list(res, "", nil)
	if err != nil {
		return Record{}, err
	}
	for _, record := range records {
		if strings.EqualFold(record.Uuid(), uuid) {
			return record, nil
		}
	}
	return Record{}, &coreapi.NotFoundError{Name: res.name(uuid)}
}

// form returns the get answer for a new record ("") or the record with this uuid
func (opn *IPsecApi) form(res resource, uuid string, query url.Values) (Form, error) {
	var endpoint = res.endpoint(opn, res.get)
	if uuid != "" {
		endpoint += "/" + uuid
	}
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var form, err = opn.getForm(endpoint, res.container)
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, &coreapi.NotFoundError{Name: res.name(uuid)}
	}
	return form, nil
}

// create adds a record and returns its uuid
func (opn *IPsecApi) create(res resource, fields Fields) (string, error) {
	if err := res.checkFields(fields); err != nil {
		return "", err
	}
	return opn.Mutate(res.endpoint(opn, res.add), map[string]Fields{res.container: fields})
}

// update sends fields to an existing record. The existence is checked first, set_* would create the record
func (opn *IPsecApi) update(res resource, uuid string, fields Fields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := res.checkFields(fields); err != nil {
		return err
	}
	if _, err := opn.getRecord(res, uuid); err != nil {
		return err
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", res.endpoint(opn, res.set), uuid), map[string]Fields{res.container: fields})
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		// a bare "failed": the uuid is malformed
		return &coreapi.NotFoundError{Name: res.name(uuid), Err: err}
	}
	return err
}

// remove deletes a record
func (opn *IPsecApi) remove(res resource, uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return fmt.Errorf("cannot remove an %s by uuid %q", res.noun, uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", res.endpoint(opn, res.del), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: res.name(uuid), Err: err}
	}
	return err
}

// setEnabled sets the enabled flag and returns whether it changed
func (opn *IPsecApi) setEnabled(res resource, uuid string, enabled bool) (bool, error) {
	if res.toggle == "" {
		return false, fmt.Errorf("an %s can not be enabled or disabled", res.noun)
	}
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return false, fmt.Errorf("cannot toggle an %s by uuid %q", res.noun, uuid)
	}
	// toggle_*/<uuid>/<0|1> sets the state, without it toggle flips it
	var endpoint = fmt.Sprintf("%s/%s/%s", res.endpoint(opn, res.toggle), uuid, map[bool]string{true: "1", false: "0"}[enabled])
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed": // unknown uuid
		return false, &coreapi.NotFoundError{Name: res.name(uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// byName returns the records whose field equals name (case-insensitive), sorted by uuid
func byName(records []Record, field string, name string) []Record {
	var matches = coreapi.Filter(records, func(record Record) bool {
		return strings.EqualFold(record.Value(field), name)
	})
	sort.Slice(matches, func(i, j int) bool { return matches[i].Uuid() < matches[j].Uuid() })
	return matches
}

// oneByName returns the only record whose field equals name, a *NotFoundError or a *TooManyFoundError
func (opn *IPsecApi) oneByName(res resource, field string, what string, name string) (Record, error) {
	if name == "" {
		return Record{}, fmt.Errorf("cannot look up an %s by an empty %s", res.noun, what)
	}
	var records, err = opn.list(res, name, nil)
	if err != nil {
		return Record{}, err
	}
	var matches = byName(records, field, name)
	switch len(matches) {
	case 0:
		return Record{}, &coreapi.NotFoundError{Name: fmt.Sprintf("%s with %s %q", res.noun, what, name)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid()
		}
		return Record{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d %ss with %s %q (uuids: %s)",
			len(matches), res.noun, what, name, strings.Join(uuids, ", "))}
	}
}
