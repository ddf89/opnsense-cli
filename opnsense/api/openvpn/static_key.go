package openvpn

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// StaticKey is a TLS static key of VPN > OpenVPN > Instances > Static Keys, used by instances (Instance.TlsKey)
// for tls-auth / tls-crypt / tls-crypt-v2. Key is the key file content (multiple lines)
type StaticKey struct {
	Uuid            string `json:"uuid,omitempty"`
	Description     string `json:"description"`
	Mode            string `json:"mode"`            // auth, crypt (default) or crypt-v2
	ModeDescription string `json:"%mode,omitempty"` // only in search rows
	Key             string `json:"key"`
}

// StaticKeyFields holds a partial static key for StaticKeyUpdate: "description", "mode" and/or "key"
type StaticKeyFields map[string]string

// StaticKeyFieldNames are the writable fields of a static key
var StaticKeyFieldNames = []string{"description", "mode", "key"}

// StaticKeyModes are the modes of a static key, in GUI order
var StaticKeyModes = []string{"auth", "crypt", "crypt-v2"}

// KeyTypes are the key types GenerateKey can generate
var KeyTypes = []string{"secret", "auth-token", "tls-auth", "tls-crypt", "tls-crypt-v2-server"}

// keyTypeOfMode is the key type the GUI generates for a static key mode
var keyTypeOfMode = map[string]string{"auth": "tls-auth", "crypt": "tls-crypt", "crypt-v2": "tls-crypt-v2-server"}

// StaticKeyPattern is the mask OPNsense checks keys against
var StaticKeyPattern = regexp.MustCompile(`(?i)^[0-9a-z#\-=+/\r\n\s]*$`)

// KeyTypeForMode returns the key type GenerateKey needs for a static key mode (like the GUI's generate button)
func KeyTypeForMode(mode string) (string, error) {
	var keyType, known = keyTypeOfMode[mode]
	if !known {
		return "", fmt.Errorf("unknown static key mode %q, valid are: %s", mode, strings.Join(StaticKeyModes, ", "))
	}
	return keyType, nil
}

func staticKeyName(uuid string) string {
	return fmt.Sprintf("openvpn static key %s", uuid)
}

// StaticKeyList returns all static keys, searchPhrase is a substring match ("" for all)
func (opn *OpenVPNApi) StaticKeyList(searchPhrase string) ([]StaticKey, error) {
	return coreapi.Search[StaticKey](opn.OPNsense, opn.endpoint("instances", "search_static_key"), searchPhrase)
}

// StaticKeyGet returns the static key with this uuid or a *NotFoundError
func (opn *OpenVPNApi) StaticKeyGet(uuid string) (StaticKey, error) {
	var keys, err = opn.StaticKeyList("")
	if err != nil {
		return StaticKey{}, err
	}
	for _, key := range keys {
		if strings.EqualFold(key.Uuid, uuid) {
			return key, nil
		}
	}
	return StaticKey{}, &coreapi.NotFoundError{Name: staticKeyName(uuid)}
}

// StaticKeyGetByDescription returns the only static key with this description (case-insensitive).
// Returns *NotFoundError when there is none, *TooManyFoundError (naming the uuids) when there are several
func (opn *OpenVPNApi) StaticKeyGetByDescription(description string) (StaticKey, error) {
	if description == "" {
		return StaticKey{}, errors.New("cannot look up a static key by an empty description")
	}
	var keys, err = opn.StaticKeyList(description)
	if err != nil {
		return StaticKey{}, err
	}
	var matches = coreapi.Filter(keys, func(key StaticKey) bool {
		return strings.EqualFold(key.Description, description)
	})
	var name = fmt.Sprintf("openvpn static key with description %q", description)
	switch len(matches) {
	case 0:
		return StaticKey{}, &coreapi.NotFoundError{Name: name}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid
		}
		sort.Strings(uuids)
		return StaticKey{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d openvpn static keys with description %q (uuids: %s)",
			len(matches), description, strings.Join(uuids, ", "))}
	}
}

// StaticKeyCreate adds a static key and returns its uuid. Description and Key are required, an empty Mode is
// OPNsense's default crypt. Duplicates are not checked
func (opn *OpenVPNApi) StaticKeyCreate(key StaticKey) (string, error) {
	var fields = StaticKeyFields{"description": key.Description, "key": key.Key}
	if key.Mode != "" {
		fields["mode"] = key.Mode
	}
	return opn.Mutate(opn.endpoint("instances", "add_static_key"), map[string]StaticKeyFields{"statickey": fields})
}

// StaticKeyUpdate sends only the given fields to the static key with this uuid, the others are kept.
// Returns *NotFoundError when the uuid does not exist (checked first, set_static_key would create it),
// *ValidationError when OPNsense rejects it
func (opn *OpenVPNApi) StaticKeyUpdate(uuid string, fields StaticKeyFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	for name := range fields {
		if !slices.Contains(StaticKeyFieldNames, name) {
			return fmt.Errorf("unknown openvpn static key field %q", name)
		}
	}
	if _, err := opn.StaticKeyGet(uuid); err != nil {
		return err
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("instances", "set_static_key"), uuid),
		map[string]StaticKeyFields{"statickey": fields})
	// set_static_key creates the key for a well-formed unknown uuid (hence the check above) and answers a
	// malformed one with a bare {"result":"failed"}
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: staticKeyName(uuid), Err: err}
	}
	return err
}

// StaticKeyRemove deletes the static key with this uuid, returns *NotFoundError when it does not exist.
// OPNsense deletes keys still used by instances (leaving a dangling Instance.TlsKey), see InstancesUsingStaticKey
func (opn *OpenVPNApi) StaticKeyRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("instances", "del_static_key"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: staticKeyName(uuid), Err: err}
	}
	return err
}

// InstancesUsingStaticKey returns the instances whose tls_key is the static key with this uuid
func (opn *OpenVPNApi) InstancesUsingStaticKey(uuid string) ([]Instance, error) {
	var instances, err = opn.InstanceList("")
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(instances, func(instance Instance) bool {
		return uuid != "" && strings.EqualFold(instance.TlsKey, uuid)
	}), nil
}

// GenerateKey lets OPNsense generate a new key of keyType (see KeyTypes, KeyTypeForMode) with openvpn --genkey
// and returns the key file content
func (opn *OpenVPNApi) GenerateKey(keyType string) (string, error) {
	if !slices.Contains(KeyTypes, keyType) {
		return "", fmt.Errorf("unknown key type %q, valid are: %s", keyType, strings.Join(KeyTypes, ", "))
	}
	var result struct {
		Result  string `json:"result"`
		Key     string `json:"key"`
		Message string `json:"message"`
	}
	var endpoint = fmt.Sprintf("%s/%s", opn.endpoint("instances", "gen_key"), keyType)
	if err := opn.DoJSON("GET", endpoint, nil, &result); err != nil {
		return "", err
	}
	if result.Result != "ok" || strings.TrimSpace(result.Key) == "" {
		var reason = result.Message
		if reason == "" {
			reason = fmt.Sprintf("result %q", result.Result)
		}
		return "", fmt.Errorf("generating a %s key failed: %s", keyType, reason)
	}
	return result.Key, nil
}
