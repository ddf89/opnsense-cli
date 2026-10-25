package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/trust"
	"strings"
)

// /system/trust/settings: the trust store and OpenSSL settings of System > Trust > Settings (api/trust/settings)

const systemTrustSettingsApplyHint = `Changes are only saved, run "/system/trust/settings apply" to rewrite the trust store and OpenSSL configuration.`

// systemTrustSettingsField maps a kebab-case argument to its API field
type systemTrustSettingsField struct {
	arg     string
	api     string // API name, for the option fields the key of Settings.Options
	options bool   // option field: values must be keys of the option map
	single  bool   // option field with one value
	value   func(s trust.Settings) string
	target  func(f *trust.SettingsFields) **string
}

var systemTrustSettingsFields = []systemTrustSettingsField{
	{"store-intermediate-certs", "store_intermediate_certs", false, false,
		func(s trust.Settings) string { return s.StoreIntermediateCerts },
		func(f *trust.SettingsFields) **string { return &f.StoreIntermediateCerts }},
	{"install-crls", "install_crls", false, false,
		func(s trust.Settings) string { return s.InstallCrls },
		func(f *trust.SettingsFields) **string { return &f.InstallCrls }},
	{"fetch-crls", "fetch_crls", false, false,
		func(s trust.Settings) string { return s.FetchCrls },
		func(f *trust.SettingsFields) **string { return &f.FetchCrls }},
	{"enable-legacy-sect", "enable_legacy_sect", false, false,
		func(s trust.Settings) string { return s.EnableLegacySect },
		func(f *trust.SettingsFields) **string { return &f.EnableLegacySect }},
	{"enable-config-constraints", "enable_config_constraints", false, false,
		func(s trust.Settings) string { return s.EnableConfigConstraints },
		func(f *trust.SettingsFields) **string { return &f.EnableConfigConstraints }},
	{"cipher-string", "CipherString", true, false,
		func(s trust.Settings) string { return s.CipherString },
		func(f *trust.SettingsFields) **string { return &f.CipherString }},
	{"ciphersuites", "Ciphersuites", true, false,
		func(s trust.Settings) string { return s.Ciphersuites },
		func(f *trust.SettingsFields) **string { return &f.Ciphersuites }},
	{"signature-algorithms", "SignatureAlgorithms", true, false,
		func(s trust.Settings) string { return s.SignatureAlgorithms },
		func(f *trust.SettingsFields) **string { return &f.SignatureAlgorithms }},
	{"groups", "groups", true, false,
		func(s trust.Settings) string { return s.Groups },
		func(f *trust.SettingsFields) **string { return &f.Groups }},
	{"min-protocol", "MinProtocol", true, true,
		func(s trust.Settings) string { return s.MinProtocol },
		func(f *trust.SettingsFields) **string { return &f.MinProtocol }},
	{"min-protocol-dtls", "MinProtocol_DTLS", true, true,
		func(s trust.Settings) string { return s.MinProtocolDTLS },
		func(f *trust.SettingsFields) **string { return &f.MinProtocolDTLS }},
}

func init() {
	var menu = Root.Menu("system/trust/settings")
	menu.Help = "trust store and OpenSSL settings (System > Trust > Settings)"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the trust settings",
			Long: `Shows the trust settings. options lists the choices of the option fields (cipher-string,
ciphersuites, signature-algorithms, groups, min-protocol, min-protocol-dtls) instead, as key, display name and
whether it is selected; they depend on the OpenSSL version of the firewall. json prints the settings as one
object with the API field names (lists comma separated).`,
			Args: []Arg{
				{Name: "options", Help: "list the choices of this option field", Values: systemTrustSettingsOptionArgs()},
				{Name: "json", Type: Bool, Help: "print the settings as one JSON object"},
			},
			Run: systemTrustSettingsPrint,
		},
		&Command{
			Name: "set",
			Help: "change the trust settings, the others are kept",
			Long: `Changes the given settings, the others are kept. The list fields take comma separated option keys
(OpenSSL names, see "print options=<field>"), an empty value clears them; min-protocol= and
min-protocol-dtls= reset to the OpenSSL default. The OpenSSL constraints (cipher-string … min-protocol-dtls)
are only used with enable-config-constraints.

  set fetch-crls install-crls
  set enable-config-constraints min-protocol=TLSv1.2 ciphersuites=TLS_AES_256_GCM_SHA384

` + systemTrustSettingsApplyHint,
			Args: []Arg{
				{Name: "store-intermediate-certs", Type: Bool, Help: "add locally defined intermediate CAs to the trust store"},
				{Name: "install-crls", Type: Bool, Help: "add all configured CRLs to the trust store"},
				{Name: "fetch-crls", Type: Bool, Help: "download the CRLs of the trusted CAs' distribution points every hour"},
				{Name: "enable-legacy-sect", Type: Bool, Help: "enable the OpenSSL legacy providers"},
				{Name: "enable-config-constraints", Type: Bool, Help: "apply the OpenSSL constraints system wide"},
				{Name: "cipher-string", Type: List, Help: "ciphers for TLSv1.2 and below", Complete: systemTrustSettingsComplete("CipherString")},
				{Name: "ciphersuites", Type: List, Help: "TLSv1.3 cipher suites", Complete: systemTrustSettingsComplete("Ciphersuites")},
				{Name: "signature-algorithms", Type: List, Help: "signature algorithms", Complete: systemTrustSettingsComplete("SignatureAlgorithms")},
				{Name: "groups", Type: List, Help: "DH groups / curves", Complete: systemTrustSettingsComplete("groups")},
				{Name: "min-protocol", Help: `minimum TLS version (e.g. TLSv1.2), "" for the OpenSSL default`, Complete: systemTrustSettingsComplete("MinProtocol")},
				{Name: "min-protocol-dtls", Help: `minimum DTLS version, "" disables DTLS when min-protocol is set`, Complete: systemTrustSettingsComplete("MinProtocol_DTLS")},
			},
			Run: systemTrustSettingsSet,
		},
		&Command{
			Name: "apply",
			Help: "apply the trust settings changes: rewrites the trust store and OpenSSL configuration, restarts cron",
			Run:  systemTrustSettingsApply,
		},
	)
}

func systemTrustSettingsOptionArgs() []string {
	var names []string
	for _, field := range systemTrustSettingsFields {
		if field.options {
			names = append(names, field.arg)
		}
	}
	return names
}

func systemTrustSettingsComplete(apiName string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = trustApi(c)
		if err != nil {
			return nil
		}
		var settings, getErr = api.SettingsGet()
		if getErr != nil {
			return nil
		}
		var keys []string
		for _, option := range settings.Options[apiName] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

func systemTrustSettingsPrint(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var settings, getErr = api.SettingsGet()
	if getErr != nil {
		return getErr
	}

	if args.Has("options") {
		var field = systemTrustSettingsFieldByArg(strings.ToLower(args.String("options")))
		if field == nil {
			return fmt.Errorf("options: must be one of %s", strings.Join(systemTrustSettingsOptionArgs(), ", "))
		}
		var rows [][]string
		for _, option := range settings.Options[field.api] {
			var key = option.Key
			if key == "" {
				key = `""`
			}
			rows = append(rows, []string{key, option.Value, YesNo(Flag(option.Selected))})
		}
		if args.Bool("json") {
			for _, option := range settings.Options[field.api] {
				if err := c.JSON(map[string]any{"key": option.Key, "value": option.Value, "selected": option.Selected}); err != nil {
					return err
				}
			}
			return nil
		}
		c.Table([]string{"KEY", "NAME", "SELECTED"}, rows)
		return nil
	}

	if args.Bool("json") {
		return c.JSON(settings)
	}
	var fields = make([][2]string, 0, len(systemTrustSettingsFields))
	for _, field := range systemTrustSettingsFields {
		var value = field.value(settings)
		if !field.options {
			value = YesNo(value)
		}
		fields = append(fields, [2]string{field.arg, value})
	}
	c.Fields(fields)
	return nil
}

func systemTrustSettingsFieldByArg(arg string) *systemTrustSettingsField {
	for i := range systemTrustSettingsFields {
		if systemTrustSettingsFields[i].arg == arg {
			return &systemTrustSettingsFields[i]
		}
	}
	return nil
}

func systemTrustSettingsSet(c *Context, args *Args) error {
	var given []systemTrustSettingsField
	var needOptions = false
	for _, field := range systemTrustSettingsFields {
		if args.Has(field.arg) {
			given = append(given, field)
			needOptions = needOptions || field.options
		}
	}
	if len(given) == 0 {
		return fmt.Errorf("set: nothing to change, give at least one setting (type \"set ?\" for help)")
	}

	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	// the choices of the option fields depend on the firewall's OpenSSL, load them to validate the values
	var current trust.Settings
	if needOptions {
		if current, err = api.SettingsGet(); err != nil {
			return err
		}
	}

	var fields trust.SettingsFields
	for _, field := range given {
		var value string
		if field.options {
			var normalized, valueErr = systemTrustSettingsOptionValue(current.Options[field.api], args.String(field.arg), field.single)
			if valueErr != nil {
				return fmt.Errorf("%s: %w", field.arg, valueErr)
			}
			value = normalized
		} else {
			value = Flag(args.Bool(field.arg))
		}
		*field.target(&fields) = &value
	}
	return api.SettingsSet(fields)
}

// systemTrustSettingsOptionValue checks the comma separated keys against the choices (case-insensitive) and
// returns them as OPNsense spells them, "" for none. single allows only one key
func systemTrustSettingsOptionValue(choices []trust.SettingsOption, value string, single bool) (string, error) {
	var keys = splitList(value)
	if single && len(keys) > 1 {
		return "", fmt.Errorf("takes one value, got %q", value)
	}
	var result = make([]string, 0, len(keys))
	for _, key := range keys {
		var found = false
		for _, choice := range choices {
			if choice.Key != "" && strings.EqualFold(choice.Key, key) {
				result = append(result, choice.Key)
				found = true
				break
			}
		}
		if !found {
			var valid = make([]string, 0, len(choices))
			for _, choice := range choices {
				if choice.Key != "" {
					valid = append(valid, choice.Key)
				}
			}
			return "", fmt.Errorf("unknown value %q, must be one of %s", key, strings.Join(valid, ", "))
		}
	}
	return strings.Join(result, ","), nil
}

func systemTrustSettingsApply(c *Context, _ *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	return api.SettingsReconfigure()
}
