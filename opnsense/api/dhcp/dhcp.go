// Package dhcp wraps the OPNsense DHCP services that have an MVC API: the Kea DHCP server (api/kea: DHCPv4,
// DHCPv6, leases, control agent, DDNS, service), the DHCP relay (api/dhcrelay) and the router advertisements
// daemon (api/radvd).
//
// The records of these modules (subnets, reservations, relays, ...) all follow the same MVC pattern, so they are
// exposed as a generic Collection: List / Get decode the search rows into a typed struct, Rows returns them as flat
// Row maps, Create / Update / Remove change them. Fields to send are given as Fields with the API field names,
// nested containers with a dot ("option_data.routers").
//
// Quirks of OPNsense 26.7 handled here: set_* on an unknown but well-formed uuid creates the record (Update checks
// first), get_* on an unknown uuid answers [] (lookups use the search endpoints), deletes of a record still
// referenced answer HTTP 500 with the referring records, mutations answer {"result":"failed"} with validations.
package dhcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// DhcpApi wraps api/kea, api/dhcrelay and api/radvd
//
//goland:noinspection GoNameStartsWithPackageName
type DhcpApi struct {
	*coreapi.OPNsense
}

// Fields are the fields to send to an add / set endpoint, keyed by the API field name; fields of a nested
// container are named with a dot ("option_data.routers"). Only the given fields are sent, set keeps the others.
// Lists are comma separated except where noted (Kea pools are newline separated)
type Fields map[string]string

// nested turns the dotted names into nested objects: {"option_data.routers": "x"} -> {"option_data": {"routers": "x"}}
func (fields Fields) nested() map[string]any {
	var result = map[string]any{}
	for name, value := range fields {
		var target = result
		var parts = strings.Split(name, ".")
		for _, part := range parts[:len(parts)-1] {
			var child, exists = target[part].(map[string]any)
			if !exists {
				child = map[string]any{}
				target[part] = child
			}
			target = child
		}
		target[parts[len(parts)-1]] = value
	}
	return result
}

// Row is a search row as flat map: the API field names (nested ones with a dot, "option_data.routers") and the
// display values OPNsense adds for option and relation fields ("%subnet" is the subnet of the related uuid in
// "subnet"). Numbers and booleans are rendered as text, lists of strings comma separated
type Row map[string]string

// Uuid returns the uuid of the row
func (row Row) Uuid() string {
	return row["uuid"]
}

// Display returns the display value OPNsense sent for an option or relation field ("%"+name), else its value
func (row Row) Display(name string) string {
	if display, exists := row["%"+name]; exists {
		return display
	}
	return row[name]
}

// decodeRow decodes one search row into a Row
func decodeRow(raw json.RawMessage) (Row, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var row = make(Row, len(fields))
	for name, value := range fields {
		row[name] = flexText(value)
	}
	return row, nil
}

// flexText renders a JSON value as text: strings as they are, null as "", true/false as 1/0, lists of plain values
// comma separated, everything else as compact JSON
func flexText(raw json.RawMessage) string {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	switch trimmed[0] {
	case '"':
		var text string
		if json.Unmarshal(trimmed, &text) == nil {
			return text
		}
	case 'n':
		return ""
	case 't':
		return "1"
	case 'f':
		return "0"
	case '[':
		var list []json.RawMessage
		if json.Unmarshal(trimmed, &list) == nil {
			var texts = make([]string, 0, len(list))
			for _, element := range list {
				if element = bytes.TrimSpace(element); len(element) > 0 && (element[0] == '[' || element[0] == '{') {
					return string(trimmed)
				}
				texts = append(texts, flexText(element))
			}
			return strings.Join(texts, ",")
		}
	}
	return string(trimmed)
}

// Text is a string that also accepts JSON numbers, booleans (1/0) and null (""), for rows that mix them
type Text string

func (t *Text) UnmarshalJSON(data []byte) error {
	*t = Text(flexText(data))
	return nil
}

// Option is one choice of an option field of a get* answer: Key is what is stored and sent, Description what the
// GUI shows
type Option struct {
	Key         string
	Description string
	Selected    bool
}

// FormField is one field of a get* answer: Value is the plain value or, for option fields, the selected keys
// comma joined; Options are the choices of an option field (nil for plain fields)
type FormField struct {
	Value   string
	Options []Option
}

// IsOption tells whether the field is an option field (a select in the GUI)
func (f FormField) IsOption() bool {
	return f.Options != nil
}

// Form is a get* answer flattened like a Row: the fields by API name, nested ones with a dot
type Form map[string]FormField

// Value returns the value of a field, "" for unknown fields
func (f Form) Value(name string) string {
	return f[name].Value
}

// Fields returns the values of all fields that can be written back (without the "%" display fields)
func (f Form) Fields() Fields {
	var fields = make(Fields, len(f))
	for name, field := range f {
		if !strings.Contains(name, "%") {
			fields[name] = field.Value
		}
	}
	return fields
}

// parseForm flattens the record object of a get* answer. Option fields come as an object keyed by the option key
// ({"lan":{"value":"LAN","selected":1}}) or, when PHP sees the keys 0..n as a list, as a JSON array whose indexes
// are the keys; relation fields without choices as []. Other objects are nested containers (option_data)
func parseForm(raw json.RawMessage) (Form, error) {
	var form = Form{}
	return form, parseFormInto(form, "", raw)
}

func parseFormInto(form Form, prefix string, raw json.RawMessage) error {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("not an object: %.60s", raw)
	}
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return err
		}
		var name = prefix + fmt.Sprint(keyToken)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("field %s: %w", name, err)
		}
		var trimmed = bytes.TrimSpace(value)
		switch {
		case len(trimmed) > 0 && trimmed[0] == '[':
			var options, listErr = parseOptionList(trimmed)
			if listErr != nil {
				return fmt.Errorf("field %s: %w", name, listErr)
			}
			form[name] = optionField(options)
		case len(trimmed) > 0 && trimmed[0] == '{':
			if options, isOptions := parseOptionObject(trimmed); isOptions {
				form[name] = optionField(options)
			} else if err := parseFormInto(form, name+".", trimmed); err != nil {
				return err
			}
		default:
			form[name] = FormField{Value: flexText(trimmed)}
		}
	}
	return nil
}

// formOption is an option as get* renders it: {"value":"description","selected":0|1[,"optgroup":"..."]}
type formOption struct {
	Value    *string `json:"value"`
	Selected any     `json:"selected"`
}

func (o formOption) selected() bool {
	switch selected := o.Selected.(type) {
	case bool:
		return selected
	case float64:
		return selected != 0
	case string:
		return selected != "" && selected != "0"
	}
	return false
}

// parseOptionObject decodes an option map keeping the order of the keys; isOptions is false when raw is a nested
// container instead (a value that is not an option)
func parseOptionObject(raw []byte) ([]Option, bool) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil {
		return nil, false
	}
	var options = []Option{}
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		var option formOption
		if err := json.Unmarshal(value, &option); err != nil || option.Value == nil || option.Selected == nil {
			return nil, false
		}
		options = append(options, Option{Key: fmt.Sprint(keyToken), Description: *option.Value, Selected: option.selected()})
	}
	return options, true
}

func parseOptionList(raw []byte) ([]Option, error) {
	var list []formOption
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var options = make([]Option, 0, len(list))
	for i, option := range list {
		var description string
		if option.Value != nil {
			description = *option.Value
		}
		options = append(options, Option{Key: fmt.Sprint(i), Description: description, Selected: option.selected()})
	}
	return options, nil
}

func optionField(options []Option) FormField {
	var selected []string
	for _, option := range options {
		if option.Selected && option.Key != "" {
			selected = append(selected, option.Key)
		}
	}
	return FormField{Value: strings.Join(selected, ","), Options: options}
}

// getForm GETs a get* endpoint and returns the object below container, nil when OPNsense answers [] (unknown uuid)
func (opn *DhcpApi) getForm(endpoint string, container string) (Form, error) {
	var answer json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(answer); len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, nil
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(answer, &wrapper); err != nil {
		return nil, fmt.Errorf("could not decode %s: %w", endpoint, err)
	}
	var record, found = wrapper[container]
	if !found {
		return nil, fmt.Errorf("unexpected answer from %s: no %q object", endpoint, container)
	}
	var form, err = parseForm(record)
	if err != nil {
		return nil, fmt.Errorf("could not decode %s: %w", endpoint, err)
	}
	return form, nil
}

// --- collections

// Record is implemented by every record type of a Collection
type Record interface {
	RecordUuid() string
}

// Base holds the uuid every record has
type Base struct {
	Uuid string `json:"uuid"`
}

// RecordUuid returns the uuid of the record
func (b Base) RecordUuid() string {
	return b.Uuid
}

// collectionSpec names the endpoints of one record type: <module>/<controller>/search_<item>, get_<item>,
// add_<item>, set_<item>, del_<item> and toggle_<item>, with the record below container in bodies and get answers
type collectionSpec struct {
	module     string
	controller string
	item       string
	container  string
	what       string
	toggle     bool
}

// Collection gives access to one record type, e.g. the Kea DHCPv4 subnets. T is the typed record List and Get return
type Collection[T Record] struct {
	opn  *DhcpApi
	spec collectionSpec
}

func newCollection[T Record](opn *DhcpApi, spec collectionSpec) *Collection[T] {
	return &Collection[T]{opn: opn, spec: spec}
}

func (c *Collection[T]) endpoint(method string) string {
	return c.opn.EndpointForPluginControllerMethod(c.spec.module, c.spec.controller, method+"_"+c.spec.item)
}

// What names the record type in messages, e.g. "kea dhcpv4 subnet"
func (c *Collection[T]) What() string {
	return c.spec.what
}

// Container is the name of the record object in bodies and validation messages ("subnet4" for "subnet4.subnet")
func (c *Collection[T]) Container() string {
	return c.spec.container
}

// CanToggle tells whether the records have an enabled flag with a toggle endpoint (SetEnabled)
func (c *Collection[T]) CanToggle() bool {
	return c.spec.toggle
}

func (c *Collection[T]) name(uuid string) string {
	return c.spec.what + " " + uuid
}

// Rows returns the rows where any column contains searchPhrase ("" for all) in API order, as Row and as the raw
// JSON objects OPNsense sent
func (c *Collection[T]) Rows(searchPhrase string) ([]Row, []json.RawMessage, error) {
	var raws, err = coreapi.Search[json.RawMessage](c.opn.OPNsense, c.endpoint("search"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var rows = make([]Row, len(raws))
	for i, raw := range raws {
		if rows[i], err = decodeRow(raw); err != nil {
			return nil, nil, fmt.Errorf("unexpected %s from OPNsense: %w", c.spec.what, err)
		}
	}
	return rows, raws, nil
}

// List returns the records where any column contains searchPhrase ("" for all) in API order
func (c *Collection[T]) List(searchPhrase string) ([]T, error) {
	var raws, err = coreapi.Search[json.RawMessage](c.opn.OPNsense, c.endpoint("search"), searchPhrase)
	if err != nil {
		return nil, err
	}
	var records = make([]T, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &records[i]); err != nil {
			return nil, fmt.Errorf("unexpected %s from OPNsense: %w", c.spec.what, err)
		}
	}
	return records, nil
}

// Get returns the record with this uuid or a *NotFoundError (get_* answers unknown uuids with [], so this searches)
func (c *Collection[T]) Get(uuid string) (T, error) {
	var zero T
	if uuid == "" {
		return zero, fmt.Errorf("cannot look up a %s without uuid", c.spec.what)
	}
	var records, err = c.List("")
	if err != nil {
		return zero, err
	}
	for _, record := range records {
		if strings.EqualFold(record.RecordUuid(), uuid) {
			return record, nil
		}
	}
	return zero, &coreapi.NotFoundError{Name: c.name(uuid)}
}

// Defaults returns the fields of a new record as OPNsense would create it (get_<item> without uuid)
func (c *Collection[T]) Defaults() (Fields, error) {
	var form, err = c.Form("")
	if err != nil {
		return nil, err
	}
	return form.Fields(), nil
}

// Form returns the get_<item> answer: for "" the defaults of a new record, else the record (*NotFoundError when
// it does not exist). Option and relation fields list every choice
func (c *Collection[T]) Form(uuid string) (Form, error) {
	var endpoint = c.endpoint("get")
	if uuid != "" {
		endpoint += "/" + uuid
	}
	var form, err = c.opn.getForm(endpoint, c.spec.container)
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, &coreapi.NotFoundError{Name: c.name(uuid)}
	}
	return form, nil
}

// Create adds a record from fields (the others get the OPNsense defaults) and returns its uuid. Duplicates are not
// checked beyond the unique constraints of the model
func (c *Collection[T]) Create(fields Fields) (string, error) {
	if len(fields) == 0 {
		return "", fmt.Errorf("cannot add a %s without fields", c.spec.what)
	}
	return c.opn.Mutate(c.endpoint("add"), map[string]any{c.spec.container: fields.nested()})
}

// Update sends only the given fields to the record with this uuid, OPNsense keeps the others. Returns
// *NotFoundError when the uuid does not exist (checked first: set_* would create the record), *ValidationError when
// OPNsense refuses the change
func (c *Collection[T]) Update(uuid string, fields Fields) error {
	if uuid == "" {
		return fmt.Errorf("cannot update a %s without uuid", c.spec.what)
	}
	if len(fields) == 0 {
		return fmt.Errorf("nothing to change for %s", c.name(uuid))
	}
	if _, err := c.Get(uuid); err != nil {
		return err
	}
	var _, err = c.opn.Mutate(c.endpoint("set")+"/"+uuid, map[string]any{c.spec.container: fields.nested()})
	// a malformed uuid is answered with a bare {"result":"failed"}
	var validation *coreapi.ValidationError
	if errors.As(err, &validation) && len(validation.Validations) == 0 {
		return &coreapi.NotFoundError{Name: c.name(uuid), Err: err}
	}
	return err
}

// Remove deletes the record with this uuid. Returns *NotFoundError when it does not exist; a record other records
// refer to (a subnet with reservations, a relay destination in use) is refused, the error names the referring records
func (c *Collection[T]) Remove(uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return fmt.Errorf("cannot remove a %s by uuid %q", c.spec.what, uuid)
	}
	if _, err := c.opn.Mutate(c.endpoint("del")+"/"+uuid, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: c.name(uuid), Err: err}
		}
		return inUseError(fmt.Sprintf("cannot remove %s, it is in use by", c.name(uuid)), err)
	}
	return nil
}

// SetEnabled enables or disables the record with this uuid and returns whether its state changed. Only for record
// types with an enabled flag (CanToggle)
func (c *Collection[T]) SetEnabled(uuid string, enabled bool) (bool, error) {
	if !c.spec.toggle {
		return false, fmt.Errorf("a %s can not be enabled or disabled", c.spec.what)
	}
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return false, fmt.Errorf("cannot toggle a %s by uuid %q", c.spec.what, uuid)
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	// toggle_<item>/<uuid>/<0|1> sets the state, without the state it flips it
	var endpoint = fmt.Sprintf("%s/%s/%s", c.endpoint("toggle"), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := c.opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed": // unknown uuid
		return false, &coreapi.NotFoundError{Name: c.name(uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// inUseError turns the HTTP 500 answer of a delete refused because of references
// ({"errorMessage":"dhcp4 - r1 {dhcp4.reservations.reservation.<uuid>}\n","errorTitle":"Item ... in use by:"})
// into "<what>: <references>"
func inUseError(what string, err error) error {
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
		return fmt.Errorf("%s: %s", what, strings.Join(strings.Fields(httpErr.Message), " "))
	}
	return err
}

// --- settings

// SettingsSpec names a settings model with get / set endpoints, e.g. Kea DHCPv4 (api/kea/dhcpv4/get)
type SettingsSpec struct {
	module     string
	controller string
	container  string
	what       string
}

// Container is the name of the settings object in bodies and validation messages ("dhcpv4" for
// "dhcpv4.general.valid_lifetime")
func (s SettingsSpec) Container() string {
	return s.container
}

// What names the settings in messages, e.g. "kea dhcpv4 settings"
func (s SettingsSpec) What() string {
	return s.what
}

// SettingsGet returns the settings flattened by section ("general.enabled", "lexpire.max_reclaim_time"), option
// fields with their choices (e.g. the interfaces)
func (opn *DhcpApi) SettingsGet(spec SettingsSpec) (Form, error) {
	var form, err = opn.getForm(opn.EndpointForPluginControllerMethod(spec.module, spec.controller, "get"), spec.container)
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, fmt.Errorf("unexpected empty answer for the %s", spec.what)
	}
	return form, nil
}

// SettingsSet changes only the given settings (a partial merge), named like SettingsGet returns them. They take
// effect with the reconfigure of the service
func (opn *DhcpApi) SettingsSet(spec SettingsSpec, fields Fields) error {
	if len(fields) == 0 {
		return fmt.Errorf("nothing to change in the %s", spec.what)
	}
	var _, err = opn.Mutate(opn.EndpointForPluginControllerMethod(spec.module, spec.controller, "set"),
		map[string]any{spec.container: fields.nested()})
	return err
}

// --- services

// Service is a service with status, start, stop, restart and reconfigure (api/<module>/service/...)
type Service struct {
	module string
	what   string
}

// ServiceStatus returns the state of the service: running, stopped, disabled or unknown
func (opn *DhcpApi) ServiceStatus(service Service) (string, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.EndpointForPluginControllerMethod(service.module, "service", "status"), nil, &container); err != nil {
		return "", err
	}
	if container.Status == "" {
		return "", fmt.Errorf("unexpected answer from the %s status: no status given", service.what)
	}
	return container.Status, nil
}

// ServiceStart starts the service
func (opn *DhcpApi) ServiceStart(service Service) error {
	return opn.serviceAction(service, "start")
}

// ServiceStop stops the service
func (opn *DhcpApi) ServiceStop(service Service) error {
	return opn.serviceAction(service, "stop")
}

// ServiceRestart restarts the service
func (opn *DhcpApi) ServiceRestart(service Service) error {
	return opn.serviceAction(service, "restart")
}

// ServiceReconfigure applies the saved configuration: regenerates the configuration and (re)starts the service when
// it is enabled, stops it otherwise. OPNsense answers {"status":"ok"} or {"status":"failed","status_msg":"..."}
func (opn *DhcpApi) ServiceReconfigure(service Service) error {
	return opn.reconfigure(opn.EndpointForPluginControllerMethod(service.module, "service", "reconfigure"), service.what)
}

func (opn *DhcpApi) reconfigure(endpoint string, what string) error {
	var container struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET answers {"status":"failed"} without doing anything
	if err := opn.DoJSON("POST", endpoint, nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		if container.StatusMsg != "" {
			return fmt.Errorf("%s reconfigure failed: %s", what, container.StatusMsg)
		}
		return fmt.Errorf("%s reconfigure failed: status %q", what, container.Status)
	}
	return nil
}

// serviceAction POSTs start/stop/restart, OPNsense passes the configd result through as {"response":"OK"}
func (opn *DhcpApi) serviceAction(service Service, action string) error {
	var container struct {
		Response any `json:"response"`
	}
	// a GET is silently ignored and answers {"response":[]}
	if err := opn.DoJSON("POST", opn.EndpointForPluginControllerMethod(service.module, "service", action), nil, &container); err != nil {
		return err
	}
	if response, isString := container.Response.(string); !isString || strings.TrimSpace(response) != "OK" {
		return fmt.Errorf("%s %s failed: unexpected response %v", service.what, action, container.Response)
	}
	return nil
}
