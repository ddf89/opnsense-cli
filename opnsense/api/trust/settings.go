package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Settings are the trust store settings of System > Trust > Settings (api/trust/settings). Booleans are "0" / "1",
// the multi-selects (CipherString, Ciphersuites, SignatureAlgorithms, Groups) are comma separated option keys,
// MinProtocol and MinProtocolDTLS one option key ("" for none). The JSON names are the API's
type Settings struct {
	// StoreIntermediateCerts adds locally defined intermediate CAs to the system trust store
	StoreIntermediateCerts string `json:"store_intermediate_certs"`
	// InstallCrls adds all configured CRLs to the system trust store
	InstallCrls string `json:"install_crls"`
	// FetchCrls schedules an hourly download of the CRLs of the distribution points of the trusted CAs
	FetchCrls string `json:"fetch_crls"`
	// EnableLegacySect enables the OpenSSL legacy providers
	EnableLegacySect string `json:"enable_legacy_sect"`
	// EnableConfigConstraints applies the OpenSSL constraints below system wide
	EnableConfigConstraints string `json:"enable_config_constraints"`
	// CipherString are the ciphers for TLSv1.2 and below (OpenSSL names, e.g. ECDHE-RSA-AES128-GCM-SHA256)
	CipherString string `json:"CipherString"`
	// Ciphersuites are the TLSv1.3 cipher suites
	Ciphersuites        string `json:"Ciphersuites"`
	SignatureAlgorithms string `json:"SignatureAlgorithms"`
	// Groups are the DH groups / curves
	Groups string `json:"groups"`
	// MinProtocol is the minimum TLS version (TLSv1 … TLSv1.3), "" for the OpenSSL default
	MinProtocol string `json:"MinProtocol"`
	// MinProtocolDTLS is the minimum DTLS version, "" disables DTLS when MinProtocol is set
	MinProtocolDTLS string `json:"MinProtocol_DTLS"`

	// Options are the choices of the option fields as OPNsense lists them, by API field name (CipherString,
	// Ciphersuites, SignatureAlgorithms, groups, MinProtocol, MinProtocol_DTLS). The choices depend on the
	// OpenSSL version of the firewall
	Options map[string][]SettingsOption `json:"-"`
}

// SettingsOption is one choice of an option field: Key is what is stored and sent, Value the display name
type SettingsOption struct {
	Key      string
	Value    string
	Selected bool
}

// SettingsFields are the settings to change with SettingsSet, only non nil fields are sent and OPNsense keeps the
// others. Multi-selects are comma separated option keys, "" clears them
type SettingsFields struct {
	StoreIntermediateCerts  *string `json:"store_intermediate_certs,omitempty"`
	InstallCrls             *string `json:"install_crls,omitempty"`
	FetchCrls               *string `json:"fetch_crls,omitempty"`
	EnableLegacySect        *string `json:"enable_legacy_sect,omitempty"`
	EnableConfigConstraints *string `json:"enable_config_constraints,omitempty"`
	CipherString            *string `json:"CipherString,omitempty"`
	Ciphersuites            *string `json:"Ciphersuites,omitempty"`
	SignatureAlgorithms     *string `json:"SignatureAlgorithms,omitempty"`
	Groups                  *string `json:"groups,omitempty"`
	MinProtocol             *string `json:"MinProtocol,omitempty"`
	MinProtocolDTLS         *string `json:"MinProtocol_DTLS,omitempty"`
}

// SettingsOptionFields are the API names of the option fields, in GUI order
var SettingsOptionFields = []string{"CipherString", "Ciphersuites", "SignatureAlgorithms", "groups", "MinProtocol", "MinProtocol_DTLS"}

// SettingsGet returns the trust settings with the choices of the option fields
func (opn *TrustApi) SettingsGet() (Settings, error) {
	var container struct {
		Trust map[string]json.RawMessage `json:"trust"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get"), nil, &container); err != nil {
		return Settings{}, err
	}
	if container.Trust == nil {
		return Settings{}, fmt.Errorf("unexpected answer from trust settings: no trust section")
	}

	var settings = Settings{Options: map[string][]SettingsOption{}}
	var plain = func(name string) string {
		var value string
		_ = json.Unmarshal(container.Trust[name], &value)
		return value
	}
	var options = func(name string) string {
		var choices, err = settingsOptions(container.Trust[name])
		if err != nil {
			return ""
		}
		settings.Options[name] = choices
		var selected = make([]string, 0)
		for _, choice := range choices {
			if choice.Selected {
				selected = append(selected, choice.Key)
			}
		}
		return strings.Join(selected, ",")
	}
	settings.StoreIntermediateCerts = plain("store_intermediate_certs")
	settings.InstallCrls = plain("install_crls")
	settings.FetchCrls = plain("fetch_crls")
	settings.EnableLegacySect = plain("enable_legacy_sect")
	settings.EnableConfigConstraints = plain("enable_config_constraints")
	settings.CipherString = options("CipherString")
	settings.Ciphersuites = options("Ciphersuites")
	settings.SignatureAlgorithms = options("SignatureAlgorithms")
	settings.Groups = options("groups")
	settings.MinProtocol = options("MinProtocol")
	settings.MinProtocolDTLS = options("MinProtocol_DTLS")
	return settings, nil
}

// SettingsSet changes only the non nil settings (trust/settings/set is a partial merge). They take effect with
// SettingsReconfigure
func (opn *TrustApi) SettingsSet(fields SettingsFields) error {
	var _, err = opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"trust": fields})
	return err
}

// SettingsReconfigure applies the saved settings: rewrites the system trust store and OpenSSL configuration and
// restarts cron (which schedules the CRL downloads)
func (opn *TrustApi) SettingsReconfigure() error {
	var container struct {
		Status string `json:"status"`
	}
	// actions must be POSTed, a GET answers {"status":"failed"} without doing anything
	if err := opn.DoJSON("POST", opn.endpoint("settings", "reconfigure"), map[string]any{}, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("trust reconfigure failed: status %q", container.Status)
	}
	return nil
}

// settingsOptions decodes an OPNsense option map {"<key>":{"value":"..","selected":0|1},...} keeping its order
func settingsOptions(raw json.RawMessage) ([]SettingsOption, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	var choices = make([]SettingsOption, 0)
	for decoder.More() {
		var keyToken, keyErr = decoder.Token()
		if keyErr != nil {
			return nil, keyErr
		}
		var option struct {
			Value    string `json:"value"`
			Selected any    `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		choices = append(choices, SettingsOption{Key: key, Value: option.Value, Selected: settingsSelected(option.Selected)})
	}
	return choices, nil
}

// settingsSelected reads the selected flag, OPNsense sends 0/1 (older versions true/false or "1")
func settingsSelected(value any) bool {
	var text = fmt.Sprint(value)
	return text == "1" || text == "true"
}
