package wireguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// WireguardApi wraps the WireGuard API of OPNsense core (VPN > WireGuard, api/wireguard): instances (server
// controller), peers (client controller), the general enable switch, the service and the wg status (diagnostics)
//
//goland:noinspection GoNameStartsWithPackageName
type WireguardApi struct {
	*coreapi.OPNsense
}

func (opn *WireguardApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("wireguard", controller, method)
}

// Option is one choice of an option field in a get_* answer, e.g. a CARP address (Key its id, Description its
// display name)
type Option struct {
	Key         string
	Description string
	Selected    bool
}

// formOption is an option as get_* renders it: {"value":"description","selected":0|1}
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

// formOptions GETs a get_* endpoint and returns the options of every option field of the record below
// container, in API order. Plain fields are left out. An unknown uuid is answered with [], returned as nil
func (opn *WireguardApi) formOptions(endpoint string, container string) (map[string][]Option, error) {
	var answer json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(answer); len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, nil
	}
	var wrapper map[string]map[string]json.RawMessage
	if err := json.Unmarshal(answer, &wrapper); err != nil {
		return nil, fmt.Errorf("could not decode %s: %w", endpoint, err)
	}
	var record, found = wrapper[container]
	if !found {
		return nil, nil
	}
	var options = map[string][]Option{}
	for name, raw := range record {
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

// toggleChanged tells whether setting enabled changes a record whose enabled field is current. The enabled flag
// is always changed through set_*: the toggle_server / toggle_client endpoints of 26.7 take no state argument and
// always flip the flag (toggle_server/<uuid>/0 enables a disabled instance)
func toggleChanged(current string, enabled bool) bool {
	return (current == "1") != enabled
}

// mutateSet posts fields below container to a set_* endpoint. A bare {"result":"failed"} (malformed uuid) is
// returned as *NotFoundError
func (opn *WireguardApi) mutateSet(endpoint string, container string, name string, fields map[string]string) error {
	var _, err = opn.Mutate(endpoint, map[string]map[string]string{container: fields})
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: name, Err: err}
	}
	return err
}

// tooManyByName returns the *TooManyFoundError for several records with the same name
func tooManyByName(what string, name string, uuids []string) error {
	return &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d %ss named %q (uuids: %s)", len(uuids), what, name, strings.Join(uuids, ", "))}
}

// searchRows keeps the rows where any non-secret column contains phrase (case-insensitive, "" keeps all). It
// replaces OPNsense's searchPhrase, which also matches the private and pre-shared keys and so would let a search
// probe their content
func searchRows(rows []json.RawMessage, phrase string, secrets []string) []json.RawMessage {
	if phrase == "" {
		return rows
	}
	phrase = strings.ToLower(phrase)
	var matching = make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		var columns map[string]any
		if json.Unmarshal(row, &columns) != nil {
			continue
		}
		for name, value := range columns {
			if slices.Contains(secrets, name) {
				continue
			}
			if text := fmt.Sprint(value); strings.Contains(strings.ToLower(text), phrase) {
				matching = append(matching, row)
				break
			}
		}
	}
	return matching
}
