package ids

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Settings are the general settings of Services > Intrusion Detection > Administration (api/ids/settings/get),
// keyed by their path below "general", like "enabled", "detect.Profile" or "eveLog.http.enable"
type Settings map[string]SettingsField

// SettingsField is one setting
type SettingsField struct {
	// Value is the value the way the API takes it: "1"/"0" for booleans, the selected keys comma separated for
	// option and list fields
	Value string
	// Options are the choices of an option or list field in API order, nil for plain fields
	Options []SettingsOption
}

// SettingsOption is one choice of an option field
type SettingsOption struct {
	Key      string
	Display  string
	Selected bool
}

// IsOption tells whether the field has a list of choices (it may be empty, like a relation without targets)
func (f SettingsField) IsOption() bool {
	return f.Options != nil
}

// Keys returns the sorted paths of the settings
func (s Settings) Keys() []string {
	var keys = make([]string, 0, len(s))
	for key := range s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// SettingsGet returns the general settings
func (opn *IdsApi) SettingsGet() (Settings, error) {
	var answer struct {
		Ids struct {
			General json.RawMessage `json:"general"`
		} `json:"ids"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get"), nil, &answer); err != nil {
		return nil, err
	}
	if len(answer.Ids.General) == 0 {
		return nil, errors.New("unexpected answer of ids/settings/get: no general settings")
	}
	var settings = Settings{}
	if err := flattenSettings("", answer.Ids.General, settings); err != nil {
		return nil, fmt.Errorf("unexpected answer of ids/settings/get: %w", err)
	}
	return settings, nil
}

// SettingsSet changes the given settings (path below "general" → API value), the others are kept. The settings are
// only saved, ServiceReconfigure applies them
func (opn *IdsApi) SettingsSet(values map[string]string) error {
	if len(values) == 0 {
		return errNoChanges
	}
	var general = nestSettings(values)
	_, err := opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"ids": map[string]any{"general": general}})
	return err
}

// --- the generic settings form encoding shared by the model based settings endpoints

// orderedEntry is one key of a JSON object, in document order
type orderedEntry struct {
	key   string
	value json.RawMessage
}

// orderedObject decodes a JSON object keeping the order of its keys
func orderedObject(raw json.RawMessage) ([]orderedEntry, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("want a JSON object, got %s", raw)
	}
	var entries []orderedEntry
	for decoder.More() {
		var keyToken, keyErr = decoder.Token()
		if keyErr != nil {
			return nil, keyErr
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		entries = append(entries, orderedEntry{key: fmt.Sprint(keyToken), value: value})
	}
	return entries, nil
}

// optionChoices returns the choices if raw is an option map {"key":{"value":"..","selected":0|1},...} or the [] of
// an option field without choices; ok is false for anything else
func optionChoices(raw json.RawMessage) ([]SettingsOption, bool) {
	var trimmed = bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("[]")) {
		return []SettingsOption{}, true
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var entries, err = orderedObject(trimmed)
	if err != nil || len(entries) == 0 {
		return nil, false
	}
	var options = make([]SettingsOption, 0, len(entries))
	for _, entry := range entries {
		var option struct {
			Value    *json.RawMessage `json:"value"`
			Selected *json.RawMessage `json:"selected"`
		}
		if json.Unmarshal(entry.value, &option) != nil || option.Value == nil || option.Selected == nil {
			return nil, false
		}
		var display string
		_ = json.Unmarshal(*option.Value, &display)
		var selected = strings.Trim(string(*option.Selected), `" `)
		options = append(options, SettingsOption{Key: entry.key, Display: display, Selected: selected == "1" || selected == "true"})
	}
	return options, true
}

// flattenSettings adds the fields of the settings object raw to settings, nested containers as "parent.child"
func flattenSettings(prefix string, raw json.RawMessage, settings Settings) error {
	var entries, err = orderedObject(raw)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var path = prefix + entry.key
		if options, ok := optionChoices(entry.value); ok {
			var selected []string
			for _, option := range options {
				if option.Selected && option.Key != "" {
					selected = append(selected, option.Key)
				}
			}
			settings[path] = SettingsField{Value: strings.Join(selected, ","), Options: options}
			continue
		}
		var trimmed = bytes.TrimSpace(entry.value)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			if err := flattenSettings(path+".", trimmed, settings); err != nil {
				return err
			}
			continue
		}
		var value string
		if json.Unmarshal(trimmed, &value) != nil {
			value = strings.Trim(string(trimmed), `"`) // numbers
		}
		settings[path] = SettingsField{Value: value}
	}
	return nil
}

// nestSettings turns {"a.b": "1"} into {"a": {"b": "1"}}
func nestSettings(values map[string]string) map[string]any {
	var root = map[string]any{}
	for path, value := range values {
		var node = root
		var parts = strings.Split(path, ".")
		for _, part := range parts[:len(parts)-1] {
			var child, ok = node[part].(map[string]any)
			if !ok {
				child = map[string]any{}
				node[part] = child
			}
			node = child
		}
		node[parts[len(parts)-1]] = value
	}
	return root
}
