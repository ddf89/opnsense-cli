// Package dnsmodel holds the mechanics shared by the dnsmasq and unbound packages: the item endpoints of an
// ApiMutableModelControllerBase (search_x, add_x, set_x/<uuid>, del_x/<uuid>, toggle_x/<uuid>) and the
// flattening of a model's settings (get / set)
package dnsmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Kind describes the items of one ArrayField of a settings controller
type Kind struct {
	// Module and Controller of the endpoints, e.g. dnsmasq / settings
	Module     string
	Controller string
	// Method is the endpoint suffix: search_<Method>, add_<Method>, set_<Method>/<uuid>, ...
	Method string
	// Container is the JSON key the item is wrapped in for add / set, e.g. "range" for {"range":{...}}
	Container string
	// Name is used in messages, e.g. "DHCP range"
	Name string
}

// Patch maps API field names (the JSON names of the record types) to their new values. Fields not in the patch
// are kept, set_* is a partial merge
type Patch map[string]string

func (k Kind) endpoint(opn *coreapi.OPNsense, action string) string {
	return opn.EndpointForPluginControllerMethod(k.Module, k.Controller, action+"_"+k.Method)
}

// SearchEndpoint is the URL of search_<Method>
func (k Kind) SearchEndpoint(opn *coreapi.OPNsense) string {
	return k.endpoint(opn, "search")
}

// Search returns the rows where any column contains searchPhrase ("" for all) in API order
func Search[T any](opn *coreapi.OPNsense, k Kind, searchPhrase string) ([]T, error) {
	return coreapi.Search[T](opn, k.SearchEndpoint(opn), searchPhrase)
}

// Get returns the row with the given uuid from the search result (get_* answers unknown uuids with an empty
// default record), *coreapi.NotFoundError when there is none
func Get[T any](opn *coreapi.OPNsense, k Kind, uuid string) (T, error) {
	var zero T
	if uuid == "" {
		return zero, fmt.Errorf("cannot look up a %s without uuid", k.Name)
	}
	var raws, err = Search[json.RawMessage](opn, k, "")
	if err != nil {
		return zero, err
	}
	for _, raw := range raws {
		var id struct {
			Uuid string `json:"uuid"`
		}
		if json.Unmarshal(raw, &id) == nil && id.Uuid == uuid {
			var item T
			if err := json.Unmarshal(raw, &item); err != nil {
				return zero, fmt.Errorf("unexpected %s from OPNsense: %w", k.Name, err)
			}
			return item, nil
		}
	}
	return zero, &coreapi.NotFoundError{Name: fmt.Sprintf("%s %s", k.Name, uuid)}
}

// Exists checks via search that uuid exists, *coreapi.NotFoundError when not
func Exists(opn *coreapi.OPNsense, k Kind, uuid string) error {
	var _, err = Get[json.RawMessage](opn, k, uuid)
	return err
}

// Create adds an item and returns its uuid. item is any JSON object (a record struct or a Patch)
func Create(opn *coreapi.OPNsense, k Kind, item any) (string, error) {
	var uuid, err = opn.Mutate(k.endpoint(opn, "add"), map[string]any{k.Container: item})
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("OPNsense saved the %s but answered without uuid", k.Name)
	}
	return uuid, nil
}

// Update changes the fields of patch, the others are kept. The uuid is checked first: set_* creates an item for
// an unknown well-formed uuid. An empty patch sends nothing
func Update(opn *coreapi.OPNsense, k Kind, uuid string, patch Patch) error {
	if uuid == "" {
		return fmt.Errorf("cannot update a %s without uuid", k.Name)
	}
	if err := Exists(opn, k, uuid); err != nil {
		return err
	}
	if len(patch) == 0 {
		return nil
	}
	return set(opn, k, uuid, patch)
}

// Replace is Update with a complete record: every field of item is sent
func Replace(opn *coreapi.OPNsense, k Kind, uuid string, item any) error {
	if uuid == "" {
		return fmt.Errorf("cannot replace a %s without uuid", k.Name)
	}
	if err := Exists(opn, k, uuid); err != nil {
		return err
	}
	return set(opn, k, uuid, item)
}

func set(opn *coreapi.OPNsense, k Kind, uuid string, item any) error {
	var endpoint = k.endpoint(opn, "set") + "/" + url.PathEscape(uuid)
	if _, err := opn.Mutate(endpoint, map[string]any{k.Container: item}); err != nil {
		// a uuid deleted since the check (or a malformed one) is answered with a bare "failed"
		var validationErr *coreapi.ValidationError
		if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("%s %s", k.Name, uuid), Err: err}
		}
		return err
	}
	return nil
}

// Remove deletes the item, *coreapi.NotFoundError when it does not exist
func Remove(opn *coreapi.OPNsense, k Kind, uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/") {
		return fmt.Errorf("cannot remove a %s by uuid %q", k.Name, uuid)
	}
	if _, err := opn.Mutate(k.endpoint(opn, "del")+"/"+uuid, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("%s %s", k.Name, uuid), Err: err}
		}
		return inUse(k, uuid, err)
	}
	return nil
}

// inUse rewrites the 500 answer of a safe delete ("Item in use by ...") into a readable error
func inUse(k Kind, uuid string, err error) error {
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 && httpErr.Message != "" {
		// one line per user like "dnsmasq - <description> {dnsmasq.dhcp_ranges.<uuid>}"
		var users []string
		for _, line := range strings.Split(httpErr.Message, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				users = append(users, line)
			}
		}
		return fmt.Errorf("cannot remove the %s %s, it is in use by: %s", k.Name, uuid, strings.Join(users, "; "))
	}
	return err
}

// --- settings

// Option is one choice of an option field: Key is what is stored and sent, Value the display name
type Option struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Group    string `json:"group,omitempty"`
	Selected bool   `json:"selected"`
}

// Settings are the plain (non array) fields of a model: API name (nested ones dotted like "dhcp.domain") to value,
// option fields as the comma separated selected keys, with their choices in Options
type Settings struct {
	Values  map[string]string
	Options map[string][]Option
}

// GetSettings reads endpoint (a settings controller's get) and flattens the sections below root (e.g. "dnsmasq"
// or "unbound.general"); skip lists child names (relative to root) of array fields that are not settings
func GetSettings(opn *coreapi.OPNsense, endpoint string, root string, skip ...string) (Settings, error) {
	var raw map[string]json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return Settings{}, err
	}
	var node json.RawMessage
	var path = strings.Split(root, ".")
	var current = raw
	for i, name := range path {
		var child, found = current[name]
		if !found {
			return Settings{}, fmt.Errorf("unexpected answer from %s: no %s", endpoint, strings.Join(path[:i+1], "."))
		}
		if i == len(path)-1 {
			node = child
			break
		}
		current = nil
		if err := json.Unmarshal(child, &current); err != nil {
			return Settings{}, fmt.Errorf("unexpected answer from %s: %s is not an object", endpoint, strings.Join(path[:i+1], "."))
		}
	}

	var settings = Settings{Values: map[string]string{}, Options: map[string][]Option{}}
	var skipped = map[string]bool{}
	for _, name := range skip {
		skipped[name] = true
	}
	if err := flatten(node, "", skipped, &settings); err != nil {
		return Settings{}, fmt.Errorf("unexpected answer from %s: %w", endpoint, err)
	}
	return settings, nil
}

// optionEntry is one choice in a get_* answer: {"value":"LAN","selected":1} (optgroup for grouped choices)
type optionEntry struct {
	Value    *string `json:"value"`
	Selected *int    `json:"selected"`
	Optgroup string  `json:"optgroup"`
}

func (e optionEntry) isOption() bool {
	return e.Value != nil && e.Selected != nil
}

func flatten(node json.RawMessage, prefix string, skip map[string]bool, settings *Settings) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(node, &object); err != nil {
		return fmt.Errorf("%s is not an object", strings.TrimSuffix(prefix, "."))
	}
	for name, value := range object {
		var key = prefix + name
		if skip[key] || strings.HasPrefix(name, "%") {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil {
			settings.Values[key] = text
			continue
		}
		if options, isOptions := parseOptions(value); isOptions {
			settings.Options[key] = options
			var selected []string
			for _, option := range options {
				if option.Selected && option.Key != "" {
					selected = append(selected, option.Key)
				}
			}
			settings.Values[key] = strings.Join(selected, ",")
			continue
		}
		var section map[string]json.RawMessage
		if json.Unmarshal(value, &section) == nil {
			if err := flatten(value, key+".", skip, settings); err != nil {
				return err
			}
		}
		// anything else (an empty array field []) is not a setting
	}
	return nil
}

// parseOptions decodes an option field: {"key":{"value":..,"selected":..}} or, when the keys are 0..n, a list
func parseOptions(value json.RawMessage) ([]Option, bool) {
	var entries map[string]optionEntry
	if json.Unmarshal(value, &entries) == nil && len(entries) > 0 {
		var options = make([]Option, 0, len(entries))
		for key, entry := range entries {
			if !entry.isOption() {
				return nil, false
			}
			options = append(options, Option{Key: key, Value: *entry.Value, Group: entry.Optgroup, Selected: *entry.Selected == 1})
		}
		// JSON objects are unordered once decoded, keep a stable order: by key, numbers numerically
		sort.Slice(options, func(i, j int) bool { return keyLess(options[i].Key, options[j].Key) })
		return options, true
	}
	var list []optionEntry
	if json.Unmarshal(value, &list) == nil && len(list) > 0 {
		var options = make([]Option, 0, len(list))
		for i, entry := range list {
			if !entry.isOption() {
				return nil, false
			}
			options = append(options, Option{Key: fmt.Sprint(i), Value: *entry.Value, Group: entry.Optgroup, Selected: *entry.Selected == 1})
		}
		return options, true
	}
	return nil, false
}

func keyLess(a string, b string) bool {
	var numberA, errA = strconv.Atoi(a)
	var numberB, errB = strconv.Atoi(b)
	if errA == nil && errB == nil {
		return numberA < numberB
	}
	return a < b
}

// SetSettings posts patch (dotted API names below root) to endpoint as nested objects, e.g. "dhcp.domain" below
// "dnsmasq" becomes {"dnsmasq":{"dhcp":{"domain":..}}}. OPNsense answers {"result":"saved"} or validations
func SetSettings(opn *coreapi.OPNsense, endpoint string, root string, patch Patch) error {
	if len(patch) == 0 {
		return errors.New("nothing to change")
	}
	var body = map[string]any{}
	for name, value := range patch {
		var current = body
		var path = strings.Split(root+"."+name, ".")
		for _, part := range path[:len(path)-1] {
			var child, ok = current[part].(map[string]any)
			if !ok {
				child = map[string]any{}
				current[part] = child
			}
			current = child
		}
		current[path[len(path)-1]] = value
	}
	_, err := opn.Mutate(endpoint, body)
	return err
}

// ParseOptionList decodes the option map of a get_<item> answer field, e.g. the DHCP option codes
func ParseOptionList(value json.RawMessage) []Option {
	var options, _ = parseOptions(value)
	return options
}
