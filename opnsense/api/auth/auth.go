package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// AuthApi wraps the OPNsense API behind System > Access (api/auth/user, api/auth/group, api/auth/priv): users with
// their API keys, groups and privileges. The authentication servers (system_authservers.php) have no API
//
//goland:noinspection GoNameStartsWithPackageName
type AuthApi struct {
	*coreapi.OPNsense
}

func (opn *AuthApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("auth", controller, method)
}

// Option is one choice of an option field as OPNsense lists it in a get answer: Key is what is stored and sent,
// Value the display name
type Option struct {
	Key      string
	Value    string
	Selected bool
}

// decodeOptions decodes an OPNsense option map {"<key>":{"value":"..","selected":0|1},...} keeping its order. PHP
// sends a map with the keys 0..n-1 (e.g. the user ids of group members) as a JSON list, the index is the key then
func decodeOptions(raw json.RawMessage) ([]Option, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	type option struct {
		Value    string `json:"value"`
		Selected any    `json:"selected"`
	}
	var options = make([]Option, 0)
	switch token {
	case json.Delim('{'):
		for decoder.More() {
			var keyToken, keyErr = decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			var choice option
			if err := decoder.Decode(&choice); err != nil {
				return nil, err
			}
			var key, _ = keyToken.(string)
			options = append(options, Option{Key: key, Value: choice.Value, Selected: selected(choice.Selected)})
		}
	case json.Delim('['):
		for index := 0; decoder.More(); index++ {
			var choice option
			if err := decoder.Decode(&choice); err != nil {
				return nil, err
			}
			options = append(options, Option{Key: strconv.Itoa(index), Value: choice.Value, Selected: selected(choice.Selected)})
		}
	default:
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	return options, nil
}

// selected reads the selected flag, OPNsense sends 0/1 (older versions true/false or "1")
func selected(value any) bool {
	var text = fmt.Sprint(value)
	return text == "1" || text == "true"
}

// splitList splits a comma separated API list, "" is the empty list
func splitList(value string) []string {
	var result = make([]string, 0)
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

// searchAll reads a search endpoint built on searchRecordsetBase (search_api_key, priv/search): they ignore
// ?searchPhrase= on GET, so they are always read completely and filtered by the caller
func searchAll[T any](opn *AuthApi, endpoint string) ([]T, error) {
	return coreapi.Search[T](opn.OPNsense, endpoint, "")
}

// mutate POSTs a model change and maps "not found"
func (opn *AuthApi) mutate(endpoint string, what string, body any) (string, error) {
	var uuid, err = opn.Mutate(endpoint, body)
	if coreapi.IsNotFound(err) {
		return "", &coreapi.NotFoundError{Name: what, Err: err}
	}
	return uuid, err
}
