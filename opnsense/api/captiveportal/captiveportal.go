package captiveportal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	coreapi "opnsense-cli/opnsense/api"
)

// CaptivePortalApi wraps the captive portal API of OPNsense core (Services > Captive Portal, api/captiveportal):
// zones (settings controller), templates, sessions, vouchers and the service. The client facing access controller
// (logon / logoff of the portal page) is not wrapped
//
//goland:noinspection GoNameStartsWithPackageName
type CaptivePortalApi struct {
	*coreapi.OPNsense
}

func (opn *CaptivePortalApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("captiveportal", controller, method)
}

// Option is one choice of an option field in get_zone, e.g. an interface (Key "lan", Description "LAN")
type Option struct {
	Key         string
	Description string
	Selected    bool
}

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

// parseOptionObject decodes an option object of a get_* answer keeping the order of the keys
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

// Value is a JSON scalar of the configd backed endpoints (sessions, vouchers), which send numbers, strings or null
// for the same field; it holds the text ("" for null)
type Value string

func (v *Value) UnmarshalJSON(data []byte) error {
	var trimmed = bytes.TrimSpace(data)
	switch {
	case len(trimmed) == 0 || string(trimmed) == "null":
		*v = ""
	case trimmed[0] == '"':
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return err
		}
		*v = Value(text)
	case trimmed[0] == '[' || trimmed[0] == '{':
		return fmt.Errorf("unexpected JSON %s for a value", trimmed)
	default:
		var number json.Number
		if err := json.Unmarshal(trimmed, &number); err == nil {
			if integer, intErr := number.Int64(); intErr == nil {
				*v = Value(strconv.FormatInt(integer, 10))
			} else {
				*v = Value(number.String())
			}
			return nil
		}
		*v = Value(trimmed) // true / false
	}
	return nil
}

// Int returns the value as a whole number (fractions cut off), 0 when it is none
func (v Value) Int() int64 {
	if integer, err := strconv.ParseInt(string(v), 10, 64); err == nil {
		return integer
	}
	if float, err := strconv.ParseFloat(string(v), 64); err == nil {
		return int64(float)
	}
	return 0
}
