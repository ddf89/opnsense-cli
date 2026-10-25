package system

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
)

// Tunable is a System > Settings > Tunables entry (api/core/tunables/*_item).
//
// There are two kinds of rows:
//   - entries stored in the configuration (custom tunables and overrides of built-ins) with a regular uuid
//   - built-in OPNsense defaults which are not configured, their uuid is md5(tunable) (32 hex chars, no dashes)
//     and their Value is the current runtime value as gathered by OPNsense, not a configured value
//
// An empty Value of a configured entry means "use DefaultValue"; custom tunables without default are then skipped
type Tunable struct {
	Uuid        string `json:"uuid,omitempty"`
	Tunable     string `json:"tunable"`
	Value       string `json:"value"`
	Description string `json:"descr"`
	// DefaultValue is the OPNsense built-in default, empty for custom tunables (read-only)
	DefaultValue string `json:"default_value,omitempty"`
	// Type as reported by sysctl(8): "w" runtime writable, "t" boot-time (loader) tunable, "r" read-only,
	// "" not known to the running kernel (read-only)
	Type string `json:"type,omitempty"`
}

// TunableFields holds a partial tunable for TunableUpdate, keyed by the API field name ("tunable", "value", "descr").
// Only the given keys are sent, OPNsense keeps all other fields
type TunableFields map[string]string

// TunableFieldNames are the writable fields of a tunable
var TunableFieldNames = []string{"tunable", "value", "descr"}

// tunableNamePattern matches sysctl / loader variable names like kern.ipc.maxsockbuf or hint.uart.0.at.
// OPNsense does not validate the name at all, but every tunable ends up in /boot/loader.conf
var tunableNamePattern = regexp.MustCompile(`^[A-Za-z0-9_%-]+(\.[A-Za-z0-9_%-]+)*$`)

// IsBuiltin is true for built-in default rows which are not stored in the configuration (uuid = md5(tunable))
func (t Tunable) IsBuiltin() bool {
	return TunableIsBuiltinUuid(t.Uuid)
}

// IsChanged is true for configured entries whose value is set and differs from the built-in default
func (t Tunable) IsChanged() bool {
	return !t.IsBuiltin() && t.Value != "" && t.Value != t.DefaultValue
}

// TunableIsBuiltinUuid tells whether uuid is the md5 based key of a not configured built-in default
func TunableIsBuiltinUuid(uuid string) bool {
	return uuid != "" && !strings.Contains(uuid, "-")
}

// TunableValidate checks name and value client-side, OPNsense accepts anything (even an empty name or newlines)
// and writes it unquoted into /boot/loader.conf on apply
func TunableValidate(name string, value string) error {
	if err := tunableValidateName(name); err != nil {
		return err
	}
	return tunableValidateValue(value)
}

func tunableValidateName(name string) error {
	if !tunableNamePattern.MatchString(name) {
		return fmt.Errorf("invalid tunable name %q: expected a sysctl name like kern.ipc.maxsockbuf", name)
	}
	return nil
}

func tunableValidateValue(value string) error {
	for _, char := range value {
		if char == '"' || unicode.IsControl(char) {
			return fmt.Errorf("invalid tunable value %q: double quotes and control characters are not allowed", value)
		}
	}
	return nil
}

func (opn *SystemApi) tunableEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "tunables", method)
}

// TunableList returns configured and built-in tunables, searchPhrase is a substring match over all columns ("" for all)
func (opn *SystemApi) TunableList(searchPhrase string) ([]Tunable, error) {
	return coreapi.Search[Tunable](opn.OPNsense, opn.tunableEndpoint("search_item"), searchPhrase)
}

// TunableGet returns the tunable with the given uuid (also md5 keys of built-ins) or a *NotFoundError
func (opn *SystemApi) TunableGet(uuid string) (Tunable, error) {
	var tunables, err = opn.TunableList("")
	if err != nil {
		return Tunable{}, err
	}
	for _, tunable := range tunables {
		if tunable.Uuid == uuid {
			return tunable, nil
		}
	}
	return Tunable{}, &coreapi.NotFoundError{Name: fmt.Sprintf("tunable %s", uuid)}
}

// TunableFindByName returns all rows for exactly this tunable name (case-sensitive like sysctl).
// The API allows several configured entries for the same name, a built-in row is hidden once it is configured
func (opn *SystemApi) TunableFindByName(name string) ([]Tunable, error) {
	if name == "" {
		return nil, errors.New("tunable name must not be empty")
	}
	var tunables, err = opn.TunableList(name)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(tunables, func(tunable Tunable) bool {
		return tunable.Tunable == name
	}), nil
}

// TunableGetByName returns the single row for name, *NotFoundError when there is none,
// *TooManyFoundError (naming the candidate uuids) when it is configured more than once
func (opn *SystemApi) TunableGetByName(name string) (Tunable, error) {
	var matches, err = opn.TunableFindByName(name)
	if err != nil {
		return Tunable{}, err
	}

	switch len(matches) {
	case 0:
		return Tunable{}, &coreapi.NotFoundError{Name: fmt.Sprintf("tunable %s", name)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, match.Uuid)
		}
		sort.Strings(uuids)
		return Tunable{}, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("tunable %s is configured %d times (uuids: %s)", name, len(matches), strings.Join(uuids, ", ")),
		}
	}
}

// TunableCreate adds a configured entry and returns its uuid. Adding a built-in name overrides the built-in default.
// Duplicates are not checked, see TunableSet
func (opn *SystemApi) TunableCreate(tunable Tunable) (string, error) {
	if err := TunableValidate(tunable.Tunable, tunable.Value); err != nil {
		return "", err
	}
	var body = map[string]TunableFields{"sysctl": {
		"tunable": tunable.Tunable,
		"value":   tunable.Value,
		"descr":   tunable.Description,
	}}
	return opn.Mutate(opn.tunableEndpoint("add_item"), body)
}

// TunableUpdate sends only the given fields to the configured entry uuid, all other fields are kept.
// Built-in rows can not be updated (set_item would create an incomplete entry), override them with TunableSet.
// Returns *NotFoundError when the uuid does not exist (checked first, set_item would create a new entry)
func (opn *SystemApi) TunableUpdate(uuid string, fields TunableFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if TunableIsBuiltinUuid(uuid) {
		return fmt.Errorf("%s is a built-in default which is not configured, override it with TunableSet / TunableCreate", uuid)
	}
	for field, value := range fields {
		var err error
		switch field {
		case "tunable":
			err = tunableValidateName(value)
		case "value":
			err = tunableValidateValue(value)
		case "descr":
		default:
			err = fmt.Errorf("unknown tunable field %q", field)
		}
		if err != nil {
			return err
		}
	}

	// set_item creates a new entry for any uuid which does not exist (even malformed ones), so make sure it does
	if _, err := opn.TunableGet(uuid); err != nil {
		return err
	}
	return opn.tunableSet(uuid, fields)
}

// tunableSet sends fields to set_item/uuid without checking that uuid exists
func (opn *SystemApi) tunableSet(uuid string, fields TunableFields) error {
	var body = map[string]TunableFields{"sysctl": fields}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.tunableEndpoint("set_item"), uuid), body)

	// fallback for older versions answering an unknown uuid with a plain {"result":"failed"}
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("tunable %s", uuid), Err: err}
	}
	return err
}

// TunableSet upserts by name: a configured entry gets the new value (and description when not nil), a built-in or
// unknown name is added as configured entry. Returns the uuid of the configured entry and whether it was created.
// Several configured entries for name return a *TooManyFoundError
func (opn *SystemApi) TunableSet(name string, value string, description *string) (string, bool, error) {
	if err := TunableValidate(name, value); err != nil {
		return "", false, err
	}

	var existing, err = opn.TunableGetByName(name)
	if err != nil && !coreapi.IsNotFound(err) {
		return "", false, err
	}

	if err == nil && !existing.IsBuiltin() {
		var fields = TunableFields{"value": value}
		if description != nil {
			fields["descr"] = *description
		}
		// just found by the search, no need to check for existence again
		return existing.Uuid, false, opn.tunableSet(existing.Uuid, fields)
	}

	var tunable = Tunable{Tunable: name, Value: value}
	if description != nil {
		tunable.Description = *description
	}
	var uuid, createErr = opn.TunableCreate(tunable)
	return uuid, true, createErr
}

// TunableRemove deletes the configured entry uuid. Removing an override brings back the built-in default,
// built-in rows themselves can not be removed. Returns *NotFoundError when the uuid does not exist
func (opn *SystemApi) TunableRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if TunableIsBuiltinUuid(uuid) {
		return fmt.Errorf("%s is a built-in default which is not configured and can not be removed", uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.tunableEndpoint("del_item"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("tunable %s", uuid), Err: err}
	}
	return err
}

// TunableReconfigure applies the tunables: sysctls which differ at runtime are set and /boot/loader.conf is
// regenerated (boot-time tunables take effect after a reboot)
func (opn *SystemApi) TunableReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.tunableEndpoint("reconfigure"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("applying tunables failed: status %q", result.Status)
	}
	return nil
}
