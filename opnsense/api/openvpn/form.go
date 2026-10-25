package openvpn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Option is one choice of an option field in a get* answer, e.g. a CA of the trust store (Key is its refid,
// Description its descr) or a protocol (Key "udp", Description "UDP")
type Option struct {
	Key         string
	Description string
	Selected    bool
}

// FormField is one field of a get* answer: a plain value, or the options of an option field
type FormField struct {
	// Value is the plain value, for option fields the selected keys (without the empty "none" key), comma joined
	Value string
	// Options are the choices of an option field in API order, nil for plain fields
	Options []Option
}

// IsOption tells whether the field is an option field (a select in the GUI)
func (f FormField) IsOption() bool {
	return f.Options != nil
}

// Form is a get* answer: the fields of one record (or of a new record with the defaults) by API field name
type Form map[string]FormField

// Value returns the plain value or the selected option keys of a field, "" for unknown fields
func (f Form) Value(name string) string {
	return f[name].Value
}

// Values returns the values of all fields, like the record would be written back with set*
func (f Form) Values() map[string]string {
	var values = make(map[string]string, len(f))
	for name, field := range f {
		values[name] = field.Value
	}
	return values
}

// formOption is an option as get* renders it: {"value":"description","selected":0|1[,"optgroup":"..."]}
type formOption struct {
	Value    string `json:"value"`
	Selected any    `json:"selected"`
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

// parseForm decodes the record object of a get* answer (the value of {"instance": {...}}).
// Option fields come as an object keyed by the option key, or - when PHP sees the keys 0..n as a list - as a JSON
// array whose indexes are the keys (e.g. verb, strictusercn)
func parseForm(raw json.RawMessage) (Form, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var form = make(Form, len(fields))
	for name, value := range fields {
		var field, err = parseFormField(value)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}
		form[name] = field
	}
	return form, nil
}

func parseFormField(raw json.RawMessage) (FormField, error) {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return FormField{}, nil
	}
	switch trimmed[0] {
	case '{':
		var options, err = parseOptionObject(trimmed)
		if err != nil {
			return FormField{}, err
		}
		return optionField(options), nil
	case '[':
		var list []formOption
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return FormField{}, err
		}
		var options = make([]Option, len(list))
		for i, option := range list {
			options[i] = Option{Key: fmt.Sprint(i), Description: option.Value, Selected: option.selected()}
		}
		return optionField(options), nil
	case '"':
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return FormField{}, err
		}
		return FormField{Value: value}, nil
	case 'n':
		return FormField{}, nil
	default: // numbers and booleans, not used by the OpenVPN models
		return FormField{Value: string(trimmed)}, nil
	}
}

// parseOptionObject decodes an option object keeping the order of the keys
func parseOptionObject(raw []byte) ([]Option, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil { // {
		return nil, err
	}
	var options = []Option{}
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		var option formOption
		if err := decoder.Decode(&option); err != nil {
			return nil, fmt.Errorf("option %q: %w", key, err)
		}
		options = append(options, Option{Key: key, Description: option.Value, Selected: option.selected()})
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

// getForm GETs a get* endpoint and returns the record below container ("instance", "statickey").
// Unknown uuids are answered with an empty list [], returned as nil
func (opn *OpenVPNApi) getForm(endpoint string, container string) (Form, error) {
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
		return nil, nil
	}
	var form, err = parseForm(record)
	if err != nil {
		return nil, fmt.Errorf("could not decode %s: %w", endpoint, err)
	}
	return form, nil
}
