// Package ddclient wraps the API of the os-ddclient plugin (Services > Dynamic DNS, api/dyndns): the DDNS
// accounts with their current address, the general settings (including the backend) and the service.
//
// Behaviour of the API this package relies on (os-ddclient 1.33 on OPNsense 26.7, verified live):
//   - the plugin may not be installed: its endpoints then answer HTTP 404 (see IsNotInstalled)
//   - accounts/search_item returns the account passwords in clear text, get_item does not; this package removes
//     them from everything it returns (Account.PasswordSet tells whether one is stored)
//   - search_item has no protocol column, get_item has it
//   - set_item is a partial merge; an empty password is ignored (a password can be changed, never cleared)
//   - set_item on an unknown well-formed uuid tries to create the record, updates check existence first
//   - the default check ip method of the model (web_dyndns) is not a valid choice, add needs checkip
//   - the services offered depend on the backend (general.backend): an unknown service is refused with "A service
//     type is required."
//   - the native backend gets its services from configd (cached for an hour): when that answers nothing, get_item
//     sends the service choices as [] (an empty PHP array) instead of an object (seen on 26.7.9_1); option fields
//     given as [] or null decode as no choices
//   - only enabled accounts are written to the configuration on reconfigure; force_refresh needs the native backend
//     and an enabled service, it stops the service, resets the cached state of the accounts and starts the service
package ddclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// PluginName is the package name of the plugin
const PluginName = "os-ddclient"

// DdclientApi wraps api/dyndns
//
//goland:noinspection GoNameStartsWithPackageName
type DdclientApi struct {
	*coreapi.OPNsense
}

func (opn *DdclientApi) endpoint(controller string, method string, params ...string) string {
	var endpoint = opn.EndpointForPluginControllerMethod("dyndns", controller, method)
	for _, param := range params {
		endpoint += "/" + param
	}
	return endpoint
}

// IsNotInstalled tells whether err is the HTTP 404 OPNsense answers for the endpoints of a plugin that is not
// installed
func IsNotInstalled(err error) bool {
	var httpErr *coreapi.HttpError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
}

// errNoChanges is returned by updates without any field to change
var errNoChanges = errors.New("nothing to change")

// validateUuid refuses empty uuids and lists
func validateUuid(uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/ ") {
		return fmt.Errorf("invalid account uuid %q", uuid)
	}
	return nil
}

// Option is one choice of an option field
type Option struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Selected bool   `json:"selected"`
}

// optionMap is an option field of a get answer: {"key":{"value":"name","selected":0|1},...}; OPNsense sends an
// option field without choices as [] (PHP has no empty object), it decodes as an empty map like null
type optionMap map[string]optionChoice

type optionChoice struct {
	Value    string `json:"value"`
	Selected any    `json:"selected"`
}

// UnmarshalJSON decodes an option field, [] and null as no choices
func (m *optionMap) UnmarshalJSON(data []byte) error {
	var trimmed = bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*m = nil
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil || len(list) != 0 {
			return fmt.Errorf("an option field must be an object or [], got %.40s", trimmed)
		}
		*m = optionMap{}
		return nil
	}
	var choices map[string]optionChoice
	if err := json.Unmarshal(trimmed, &choices); err != nil {
		return err
	}
	*m = choices
	return nil
}

// options returns the choices sorted by key (JSON objects carry no order)
func (m optionMap) options() []Option {
	var options = make([]Option, 0, len(m))
	for key, option := range m {
		var selected = fmt.Sprint(option.Selected)
		options = append(options, Option{Key: key, Name: option.Value, Selected: selected == "1" || selected == "true"})
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Key < options[j].Key })
	return options
}

// selected returns the selected keys comma separated
func (m optionMap) selected() string {
	var keys []string
	for _, option := range m.options() {
		if option.Selected && option.Key != "" {
			keys = append(keys, option.Key)
		}
	}
	return strings.Join(keys, ",")
}
