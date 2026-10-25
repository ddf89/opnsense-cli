package openvpn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strconv"
	"strings"
)

// VPN > OpenVPN > Client Export (api/openvpn/export): the servers a client configuration can be exported for,
// their accounts (client certificates), the export templates, the per server presets and the download.
//
// Behaviour of OPNsense 26.7 (ExportController) this wrapper relies on:
//   - providers only lists ENABLED server instances (and legacy servers that are not disabled); accounts and
//     download do not know disabled instances either (accounts only has the "(none)" entry, download answers
//     {"result":"failed"})
//   - the vpnid of an instance is its uuid, legacy servers use their number
//   - store_presets (and validate_presets) for an unknown vpnid create a preset entry for it, so stores are only
//     sent for listed servers
//   - download POSTs the export options and STORES them as presets of the server when they differ (like the
//     GUI does), the p12 password is never stored. Without the options it does not export at all
//   - the template is not validated, an unknown one is answered with {"result":"ok"} without a file

// ExportOption* are the API names of the export options (model OPNsense/OpenVPNExport, field openvpn_export.*)
const (
	// ExportOptionHostname is the address(es) the client connects to, comma separated
	ExportOptionHostname = "hostname"
	// ExportOptionTemplate is the export type, see ExportTemplates (e.g. PlainOpenVPN)
	ExportOptionTemplate = "template"
	// ExportOptionLocalPort is the port the client connects to (the server's port unless set)
	ExportOptionLocalPort        = "local_port"
	ExportOptionRandomLocalPort  = "random_local_port"
	ExportOptionValidateServerCn = "validate_server_cn"
	// ExportOptionCryptoapi loads the client certificate from the Windows certificate store
	ExportOptionCryptoapi       = "cryptoapi"
	ExportOptionAuthNocache     = "auth_nocache"
	ExportOptionStaticChallenge = "static_challenge"
	// ExportOptionPlainConfig is custom configuration (lines) appended to the client configuration
	ExportOptionPlainConfig = "plain_config"
	// ExportOptionP12Password protects the pkcs12 file of the archive templates, it is only used by ExportDownload
	// and never stored
	ExportOptionP12Password = "p12_password"
)

// ExportPresetNames are the options stored per server, in the order of the GUI
var ExportPresetNames = []string{
	ExportOptionTemplate, ExportOptionHostname, ExportOptionLocalPort, ExportOptionRandomLocalPort,
	ExportOptionValidateServerCn, ExportOptionCryptoapi, ExportOptionAuthNocache, ExportOptionStaticChallenge,
	ExportOptionPlainConfig,
}

// exportBooleanOptions are the options with the values "1" / "0"
var exportBooleanOptions = []string{
	ExportOptionRandomLocalPort, ExportOptionValidateServerCn, ExportOptionCryptoapi, ExportOptionAuthNocache,
	ExportOptionStaticChallenge,
}

// ExportIsBoolean tells whether option takes "1" / "0"
func ExportIsBoolean(option string) bool {
	for _, name := range exportBooleanOptions {
		if name == option {
			return true
		}
	}
	return false
}

// ExportDefaultTemplate is used by ExportDownload when neither the presets nor the options have a template: the
// plain .ovpn file with inline certificates and keys
const ExportDefaultTemplate = "PlainOpenVPN"

// ExportOptions maps an ExportOption* name to its value, booleans are "1" / "0"
type ExportOptions map[string]string

// ExportServer is a server client configurations can be exported for, as listed by export/providers
type ExportServer struct {
	// Vpnid identifies the server in the export API: the uuid of an instance, the number of a legacy server
	Vpnid string
	// Name is "<description> <protocol>:<port>", the description is "server" when the server has none
	Name string
	// Mode is the authentication: "" (certificate) or server_tls_user (certificate and user) for instances, the
	// legacy servers can also be server_tls, server_user, p2p_tls, p2p_shared_key
	Mode string
	// Presets are the effective export options (ExportPresetNames): the stored preset, else the server's value
	// (e.g. local_port is the server's port), "" when neither is set. Booleans are "1" / "0" (OPNsense sends null
	// for "0")
	Presets ExportOptions
	// Raw is the provider object as OPNsense sent it
	Raw json.RawMessage
}

// Description is the name without the trailing "<protocol>:<port>"
func (s ExportServer) Description() string {
	if index := strings.LastIndex(s.Name, " "); index > 0 {
		return s.Name[:index]
	}
	return s.Name
}

// Listen is the "<protocol>:<port>" part of the name, e.g. udp:1194
func (s ExportServer) Listen() string {
	if index := strings.LastIndex(s.Name, " "); index > 0 {
		return s.Name[index+1:]
	}
	return ""
}

// ExportAccount is a client certificate of the server's CA, an export can embed it
type ExportAccount struct {
	// Certref is the refid of the certificate
	Certref     string `json:"certref"`
	Description string `json:"description"`
	// Users are the users with the certificate's common name (when it is a client certificate)
	Users []string `json:"users"`
}

// ExportTemplate is a file format a configuration can be exported as
type ExportTemplate struct {
	// Name is the template's key, e.g. PlainOpenVPN, used as the template option
	Name string `json:"name"`
	// Description is what the GUI shows, e.g. "File Only"
	Description string `json:"description"`
	// SupportedOptions are the ExportOption* names that apply to this template (besides hostname, port, template
	// and validate_server_cn, which apply to every template)
	SupportedOptions []string `json:"supportedOptions"`
}

// Supports tells whether option applies to the template
func (t ExportTemplate) Supports(option string) bool {
	for _, supported := range t.SupportedOptions {
		if supported == option {
			return true
		}
	}
	return false
}

// ExportFile is a downloaded client configuration
type ExportFile struct {
	// Filename is the name OPNsense suggests, without any path, e.g. road_warrior_alice.ovpn
	Filename string
	// Filetype is the media type, e.g. text/ovpn, application/zip
	Filetype string
	Content  []byte
	// PresetsChanged tells that OPNsense stored the given options as the server's presets
	PresetsChanged bool
}

func (opn *OpenVPNApi) exportEndpoint(method string, args ...string) string {
	var endpoint = opn.endpoint("export", method)
	for _, arg := range args {
		endpoint += "/" + url.PathEscape(arg)
	}
	return endpoint
}

// exportObject decodes a JSON object keeping the order of its keys. PHP sends an empty array as [], which is
// returned as no keys
func exportObject(data []byte) ([]string, map[string]json.RawMessage, error) {
	var values = map[string]json.RawMessage{}
	var trimmed = bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("[]")) {
		return nil, values, nil
	}

	var decoder = json.NewDecoder(bytes.NewReader(trimmed))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, fmt.Errorf("want a JSON object, got %.40q", trimmed)
	}
	var keys []string
	for decoder.More() {
		var token, err = decoder.Token()
		if err != nil {
			return nil, nil, err
		}
		var key, _ = token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, err
		}
		if _, duplicate := values[key]; !duplicate {
			keys = append(keys, key)
		}
		values[key] = value
	}
	return keys, values, nil
}

// exportGetObject GETs an endpoint answering a JSON object keyed by id
func (opn *OpenVPNApi) exportGetObject(endpoint string) ([]string, map[string]json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return nil, nil, err
	}
	var keys, values, err = exportObject(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decode response from %s: %w", endpoint, err)
	}
	return keys, values, nil
}

// exportString renders a scalar JSON value as string: null is "", booleans are "1"/"0"
func exportString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "1"
		}
		return "0"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		var encoded, _ = json.Marshal(typed)
		return string(encoded)
	}
}

// ExportServers lists the servers configurations can be exported for, in the order of OPNsense. Disabled
// instances are not listed
func (opn *OpenVPNApi) ExportServers() ([]ExportServer, error) {
	var endpoint = opn.exportEndpoint("providers")
	var keys, values, err = opn.exportGetObject(endpoint)
	if err != nil {
		return nil, err
	}

	var servers = make([]ExportServer, 0, len(keys))
	for _, key := range keys {
		var fields map[string]any
		if err := json.Unmarshal(values[key], &fields); err != nil {
			return nil, fmt.Errorf("could not decode server %s from %s: %w", key, endpoint, err)
		}
		var server = ExportServer{
			Vpnid:   exportString(fields["vpnid"]),
			Name:    exportString(fields["name"]),
			Mode:    exportString(fields["mode"]),
			Presets: ExportOptions{},
			Raw:     values[key],
		}
		if server.Vpnid == "" {
			server.Vpnid = key
		}
		for _, name := range ExportPresetNames {
			var value = exportString(fields[name])
			if value == "" && ExportIsBoolean(name) {
				value = "0"
			}
			server.Presets[name] = value
		}
		servers = append(servers, server)
	}
	return servers, nil
}

// ExportServerGet returns the exportable server vpnid (uuid or legacy number), *NotFoundError when it does not
// exist or is disabled
func (opn *OpenVPNApi) ExportServerGet(vpnid string) (ExportServer, error) {
	var servers, err = opn.ExportServers()
	if err != nil {
		return ExportServer{}, err
	}
	for _, server := range servers {
		if server.Vpnid == vpnid {
			return server, nil
		}
	}
	return ExportServer{}, exportServerNotFound(vpnid)
}

func exportServerNotFound(vpnid string) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("OpenVPN server %s (only enabled servers can be exported)", vpnid)}
}

// ExportAccounts lists the client certificates of the server's CA, in the order of OPNsense. The "(none)" entry of
// OPNsense (export without certificate) is left out, see ExportDownload. An unknown or disabled server is a
// *NotFoundError (OPNsense itself answers it with the "(none)" entry only)
func (opn *OpenVPNApi) ExportAccounts(vpnid string) ([]ExportAccount, error) {
	if vpnid == "" {
		return nil, errors.New("a server vpnid is required")
	}
	var endpoint = opn.exportEndpoint("accounts", vpnid)
	var keys, values, err = opn.exportGetObject(endpoint)
	if err != nil {
		return nil, err
	}

	var accounts = make([]ExportAccount, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		var account ExportAccount
		if err := json.Unmarshal(values[key], &account); err != nil {
			return nil, fmt.Errorf("could not decode account %s from %s: %w", key, endpoint, err)
		}
		account.Certref = key
		if account.Users == nil {
			account.Users = []string{}
		}
		accounts = append(accounts, account)
	}
	if len(accounts) == 0 {
		if _, err := opn.ExportServerGet(vpnid); err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

// ExportTemplates lists the export file formats, in the order of OPNsense
func (opn *OpenVPNApi) ExportTemplates() ([]ExportTemplate, error) {
	var endpoint = opn.exportEndpoint("templates")
	var keys, values, err = opn.exportGetObject(endpoint)
	if err != nil {
		return nil, err
	}

	var templates = make([]ExportTemplate, 0, len(keys))
	for _, key := range keys {
		var template struct {
			Name             string   `json:"name"`
			SupportedOptions []string `json:"supportedOptions"`
		}
		if err := json.Unmarshal(values[key], &template); err != nil {
			return nil, fmt.Errorf("could not decode template %s from %s: %w", key, endpoint, err)
		}
		if template.SupportedOptions == nil {
			template.SupportedOptions = []string{}
		}
		templates = append(templates, ExportTemplate{Name: key, Description: template.Name, SupportedOptions: template.SupportedOptions})
	}
	return templates, nil
}

// exportPresetsResult is the answer of validate_presets / store_presets / download
type exportPresetsResult struct {
	Result      string                     `json:"result"`
	Changed     bool                       `json:"changed"`
	Validations coreapi.ValidationMessages `json:"validations"`
	Filename    string                     `json:"filename"`
	Filetype    string                     `json:"filetype"`
	Content     string                     `json:"content"`
}

// validationError returns the validations as *ValidationError keyed by the option names (openvpn_export.local_port
// becomes local_port)
func (r exportPresetsResult) validationError() error {
	var validations = make(map[string]string, len(r.Validations))
	for field, message := range r.Validations {
		validations[strings.TrimPrefix(field, "openvpn_export.")] = message
	}
	return &coreapi.ValidationError{Validations: validations}
}

// exportBody is the form OPNsense expects: {"openvpn_export": {...}}
func exportBody(options ExportOptions) map[string]ExportOptions {
	if options == nil {
		options = ExportOptions{}
	}
	return map[string]ExportOptions{"openvpn_export": options}
}

func exportCheckOptions(options ExportOptions, allowed ...string) error {
	for name := range options {
		var known = false
		for _, allowedName := range allowed {
			known = known || name == allowedName
		}
		if !known {
			return fmt.Errorf("unknown export option %q", name)
		}
	}
	return nil
}

// ExportValidatePresets checks options for the server vpnid without storing them and tells whether they differ
// from the stored presets. A rejected option is a *ValidationError keyed by the option name. The server is not
// checked: OPNsense validates against new (default) presets for an unknown vpnid
func (opn *OpenVPNApi) ExportValidatePresets(vpnid string, options ExportOptions) (changed bool, err error) {
	return opn.exportPresets("validate_presets", vpnid, options)
}

// ExportStorePresets stores options (only the given ones, the others are kept) as presets of the server vpnid,
// changed tells whether anything was saved. An unknown or disabled server is a *NotFoundError (checked first,
// OPNsense would create presets for it), a rejected option a *ValidationError keyed by the option name. The
// hostname is required: without a stored one it must be part of options
func (opn *OpenVPNApi) ExportStorePresets(vpnid string, options ExportOptions) (changed bool, err error) {
	if _, err := opn.ExportServerGet(vpnid); err != nil {
		return false, err
	}
	return opn.exportPresets("store_presets", vpnid, options)
}

func (opn *OpenVPNApi) exportPresets(method string, vpnid string, options ExportOptions) (bool, error) {
	if vpnid == "" {
		return false, errors.New("a server vpnid is required")
	}
	if err := exportCheckOptions(options, ExportPresetNames...); err != nil {
		return false, err
	}
	var result exportPresetsResult
	if err := opn.DoJSON("POST", opn.exportEndpoint(method, vpnid), exportBody(options), &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "ok":
		return result.Changed, nil
	case "failed":
		return false, result.validationError()
	default:
		return false, fmt.Errorf("unexpected answer from %s: result %q", method, result.Result)
	}
}

// ExportDownload exports the client configuration of the server vpnid with the client certificate certref (""
// exports without certificate, for servers authenticating users only). options (ExportPresetNames and
// ExportOptionP12Password) override the presets; like the GUI, all options are sent and OPNsense STORES them as the
// server's presets when they differ (ExportFile.PresetsChanged), except the p12 password. Without a template
// (preset or option) ExportDefaultTemplate is used. A hostname is required, as preset or option.
//
// An unknown or disabled server is a *NotFoundError, rejected options a *ValidationError keyed by the option name,
// a certificate of another CA an *HttpError ("Certificate does not belong to server CA")
func (opn *OpenVPNApi) ExportDownload(vpnid string, certref string, options ExportOptions) (ExportFile, error) {
	if vpnid == "" {
		return ExportFile{}, errors.New("a server vpnid is required")
	}
	if err := exportCheckOptions(options, append([]string{ExportOptionP12Password}, ExportPresetNames...)...); err != nil {
		return ExportFile{}, err
	}
	// OPNsense overlays the stored presets over the server's settings, empty ones included: without sending the
	// effective values (as the GUI does), an unset port preset exports "remote <host>  <proto>" without port
	var server, serverErr = opn.ExportServerGet(vpnid)
	if serverErr != nil {
		return ExportFile{}, serverErr
	}
	var body = ExportOptions{}
	for name, value := range server.Presets {
		body[name] = value
	}
	for name, value := range options {
		body[name] = value
	}
	if body[ExportOptionTemplate] == "" {
		body[ExportOptionTemplate] = ExportDefaultTemplate
	}
	options = body

	var endpoint = opn.exportEndpoint("download", vpnid)
	if certref != "" {
		endpoint = opn.exportEndpoint("download", vpnid, certref)
	}

	var result exportPresetsResult
	if err := opn.DoJSON("POST", endpoint, exportBody(options), &result); err != nil {
		return ExportFile{}, err
	}
	switch result.Result {
	case "ok":
	case "failed":
		if len(result.Validations) > 0 {
			return ExportFile{}, result.validationError()
		}
		// answered before looking at the options: the server is unknown or disabled
		return ExportFile{}, exportServerNotFound(vpnid)
	default:
		return ExportFile{}, fmt.Errorf("unexpected answer from download: result %q", result.Result)
	}
	if result.Filename == "" && result.Content == "" {
		// OPNsense validated (and stored) the options, but does not know the template
		return ExportFile{}, &coreapi.NotFoundError{Name: fmt.Sprintf("export template %s", options[ExportOptionTemplate])}
	}

	var content, decodeErr = base64.StdEncoding.DecodeString(result.Content)
	if decodeErr != nil {
		return ExportFile{}, fmt.Errorf("could not decode the exported file: %w", decodeErr)
	}
	var filename = exportSafeFilename(result.Filename)
	if filename == "" {
		filename = "openvpn.ovpn"
	}
	return ExportFile{Filename: filename, Filetype: result.Filetype, Content: content, PresetsChanged: result.Changed}, nil
}

// exportSafeFilename strips any path from a file name suggested by the server
func exportSafeFilename(name string) string {
	name = strings.TrimSpace(name[strings.LastIndexAny(name, `/\`)+1:])
	if name == "." || name == ".." {
		return ""
	}
	return name
}
