package ddclient

import (
	"errors"
	"fmt"
)

// Backends are the keys of general.backend: ddclient (the ddclient daemon) and opnsense (the native backend,
// shown as "native")
var Backends = []string{"ddclient", "opnsense"}

// Settings are the general settings of Services > Dynamic DNS > General settings (dyndns/settings/get)
type Settings struct {
	Enabled   string // "1" or "0"
	Verbose   string
	AllowIpv6 string
	// DaemonDelay is the interval between two checks in seconds (1-86400)
	DaemonDelay string
	// Backend is ddclient or opnsense (native), BackendOptions its choices
	Backend        string
	BackendOptions []Option
}

// SettingsFields maps the API names of the general settings to their Settings values
func (s Settings) SettingsFields() map[string]string {
	return map[string]string{"enabled": s.Enabled, "verbose": s.Verbose, "allowipv6": s.AllowIpv6,
		"daemon_delay": s.DaemonDelay, "backend": s.Backend}
}

// SettingsGet returns the general settings
func (opn *DdclientApi) SettingsGet() (Settings, error) {
	var answer struct {
		Ddclient struct {
			General *struct {
				Enabled     string    `json:"enabled"`
				Verbose     string    `json:"verbose"`
				AllowIpv6   string    `json:"allowipv6"`
				DaemonDelay string    `json:"daemon_delay"`
				Backend     optionMap `json:"backend"`
			} `json:"general"`
		} `json:"ddclient"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get"), nil, &answer); err != nil {
		return Settings{}, err
	}
	var general = answer.Ddclient.General
	if general == nil {
		return Settings{}, errors.New("unexpected answer of dyndns/settings/get: no general settings")
	}
	return Settings{Enabled: general.Enabled, Verbose: general.Verbose, AllowIpv6: general.AllowIpv6,
		DaemonDelay: general.DaemonDelay, Backend: general.Backend.selected(), BackendOptions: general.Backend.options()}, nil
}

// SettingsSet changes the given general settings (API name like "enabled" or "daemon_delay" → value), the others
// are kept. They are only saved, ServiceReconfigure applies them
func (opn *DdclientApi) SettingsSet(values map[string]string) error {
	if len(values) == 0 {
		return errNoChanges
	}
	for name := range values {
		switch name {
		case "enabled", "verbose", "allowipv6", "daemon_delay", "backend":
		default:
			return fmt.Errorf("unknown ddclient setting %q", name)
		}
	}
	_, err := opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"ddclient": map[string]any{"general": values}})
	return err
}
