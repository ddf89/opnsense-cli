package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// System > High Availability > Settings (/ui/core/hasync) is the model behind api/core/hasync (get, set,
// reconfigure = configctl interface pfsync configure). System > High Availability > Status (/ui/core/hasync_status)
// is api/core/hasync_status: version and services ask the backup node over XMLRPC (synchronizetoip), start/stop/
// restart/<service>/<id> and restart_all first push the configuration to the backup ("filter sync") and reload its
// templates, then act on its services. Without a configured peer version answers {"response":false} and services
// has no rows.
//
// 26.7 quirk: get returns the XMLRPC password in clear text. The pfsyncversion choices depend on the installed
// release (26.7.0: 1301 and 1400; later 26.7.x also 1500), use the choices get returns.

// HaSyncSettings are the HA settings. Flags are "1"/"0", option fields hold the selected key(s) (comma separated
// for SyncItems)
type HaSyncSettings struct {
	DisablePreempt  string `json:"disablepreempt"`
	DisconnectPpps  string `json:"disconnectppps"`
	PfsyncInterface string `json:"pfsyncinterface"`
	PfsyncPeerIp    string `json:"pfsyncpeerip"`
	PfsyncVersion   string `json:"pfsyncversion"`
	PfsyncDefer     string `json:"pfsyncdefer"`
	SynchronizeToIp string `json:"synchronizetoip"`
	VerifyPeer      string `json:"verifypeer"`
	Username        string `json:"username"`
	// Password is the XMLRPC password of the backup node, a secret
	Password  string `json:"-"`
	SyncItems string `json:"syncitems"`
	// Options are the choices of the option fields by API name (pfsyncinterface, pfsyncversion, syncitems)
	Options map[string][]HaSyncOption `json:"-"`
}

// HaSyncOption is one choice of an option field: Key is stored and sent, Name displayed
type HaSyncOption struct {
	Key      string
	Name     string
	Selected bool
}

// HaSyncOptionFields are the API names of the option fields
var HaSyncOptionFields = []string{"pfsyncinterface", "pfsyncversion", "syncitems"}

func (s *HaSyncSettings) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = HaSyncSettings{Options: map[string][]HaSyncOption{}}
	var text = func(key string) (string, error) {
		var value string
		if field, ok := raw[key]; ok {
			if err := json.Unmarshal(field, &value); err != nil {
				return "", fmt.Errorf("%s: %w", key, err)
			}
		}
		return value, nil
	}
	for _, field := range []struct {
		key    string
		target *string
	}{
		{"disablepreempt", &s.DisablePreempt}, {"disconnectppps", &s.DisconnectPpps}, {"pfsyncpeerip", &s.PfsyncPeerIp},
		{"pfsyncdefer", &s.PfsyncDefer}, {"synchronizetoip", &s.SynchronizeToIp}, {"verifypeer", &s.VerifyPeer},
		{"username", &s.Username}, {"password", &s.Password},
	} {
		var value, err = text(field.key)
		if err != nil {
			return err
		}
		*field.target = value
	}
	for _, field := range []struct {
		key    string
		target *string
	}{{"pfsyncinterface", &s.PfsyncInterface}, {"pfsyncversion", &s.PfsyncVersion}, {"syncitems", &s.SyncItems}} {
		var options, err = haSyncOptions(raw[field.key])
		if err != nil {
			return fmt.Errorf("%s: %w", field.key, err)
		}
		s.Options[field.key] = options
		var selected []string
		for _, option := range options {
			if option.Selected {
				selected = append(selected, option.Key)
			}
		}
		*field.target = strings.Join(selected, ",")
	}
	return nil
}

// haSyncOptions decodes an OPNsense option map {"<key>":{"value":"..","selected":0|1},...} keeping its order
func haSyncOptions(raw json.RawMessage) ([]HaSyncOption, error) {
	var options = make([]HaSyncOption, 0)
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] == '[' {
		return options, nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		var option struct {
			Value    string `json:"value"`
			Selected any    `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		options = append(options, HaSyncOption{Key: key, Name: option.Value, Selected: coreServiceFlag(option.Selected)})
	}
	return options, nil
}

// HaSyncSettingsPatch holds the settings to change (API values: "1"/"0" flags, option keys, comma separated
// sync items), nil fields are kept
type HaSyncSettingsPatch struct {
	DisablePreempt  *string
	DisconnectPpps  *string
	PfsyncInterface *string
	PfsyncPeerIp    *string
	PfsyncVersion   *string
	PfsyncDefer     *string
	SynchronizeToIp *string
	VerifyPeer      *string
	Username        *string
	Password        *string
	SyncItems       *string
}

func (patch HaSyncSettingsPatch) body() map[string]string {
	var fields = map[string]string{}
	for key, value := range map[string]*string{
		"disablepreempt": patch.DisablePreempt, "disconnectppps": patch.DisconnectPpps,
		"pfsyncinterface": patch.PfsyncInterface, "pfsyncpeerip": patch.PfsyncPeerIp,
		"pfsyncversion": patch.PfsyncVersion, "pfsyncdefer": patch.PfsyncDefer,
		"synchronizetoip": patch.SynchronizeToIp, "verifypeer": patch.VerifyPeer, "username": patch.Username,
		"password": patch.Password, "syncitems": patch.SyncItems,
	} {
		if value != nil {
			fields[key] = *value
		}
	}
	return fields
}

func (opn *SystemApi) haSyncEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "hasync", method)
}

func (opn *SystemApi) haStatusEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "hasync_status", method)
}

// HaSyncSettingsGet returns the HA settings with the choices of the option fields
func (opn *SystemApi) HaSyncSettingsGet() (HaSyncSettings, error) {
	var container struct {
		Hasync *HaSyncSettings `json:"hasync"`
	}
	if err := opn.DoJSON("GET", opn.haSyncEndpoint("get"), nil, &container); err != nil {
		return HaSyncSettings{}, err
	}
	if container.Hasync == nil {
		return HaSyncSettings{}, errors.New("unexpected answer from OPNsense: no hasync settings")
	}
	return *container.Hasync, nil
}

// HaSyncSettingsUpdate saves the non nil settings, the others are kept. pfsync changes take effect with
// HaSyncReconfigure
func (opn *SystemApi) HaSyncSettingsUpdate(patch HaSyncSettingsPatch) error {
	var fields = patch.body()
	if len(fields) == 0 {
		return errors.New("no HA setting to change")
	}
	_, err := opn.Mutate(opn.haSyncEndpoint("set"), map[string]any{"hasync": fields})
	return err
}

// HaSyncReconfigure applies the pfsync settings (configctl interface pfsync configure)
func (opn *SystemApi) HaSyncReconfigure() error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.haSyncEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("HA reconfigure failed: status %q", container.Status)
	}
	return nil
}

// HaPeerVersion is what the backup node reports about itself
type HaPeerVersion struct {
	// Reachable is false when no peer is configured or it could not be queried (Message tells why when known)
	Reachable bool
	Message   string
	Firmware  string
	Base      string
	Kernel    string
	// Local is the core version of this firewall, to compare with Firmware
	Local string
}

// HaPeerVersionGet asks the backup node (synchronizetoip) for its versions
func (opn *SystemApi) HaPeerVersionGet() (HaPeerVersion, error) {
	var container struct {
		Response json.RawMessage `json:"response"`
		Status   string          `json:"status"`
		Message  string          `json:"message"`
	}
	if err := opn.DoJSON("GET", opn.haStatusEndpoint("version"), nil, &container); err != nil {
		return HaPeerVersion{}, err
	}
	if container.Status == "error" {
		return HaPeerVersion{Message: container.Message}, nil
	}
	var response struct {
		Firmware struct {
			Version   string `json:"version"`
			MyVersion string `json:"_my_version"`
		} `json:"firmware"`
		Base struct {
			Version string `json:"version"`
		} `json:"base"`
		Kernel struct {
			Version string `json:"version"`
		} `json:"kernel"`
	}
	if trimmed := bytes.TrimSpace(container.Response); len(trimmed) == 0 || trimmed[0] != '{' ||
		json.Unmarshal(trimmed, &response) != nil || response.Firmware.Version == "" {
		return HaPeerVersion{Message: "no backup node configured (synchronize-to-ip) or it did not answer"}, nil
	}
	return HaPeerVersion{Reachable: true, Firmware: response.Firmware.Version, Base: response.Base.Version,
		Kernel: response.Kernel.Version, Local: strings.TrimSpace(response.Firmware.MyVersion)}, nil
}

// HaRemoteService is a service of the backup node
type HaRemoteService struct {
	// Uid is name or name_id, unique in the list
	Uid         string
	Name        string
	Id          string
	Description string
	Running     bool
	// NoCheck services can not be stopped (the web UI only offers restart)
	NoCheck bool
}

func (s *HaRemoteService) UnmarshalJSON(data []byte) error {
	var raw struct {
		Uid         string `json:"uid"`
		Name        string `json:"name"`
		Id          any    `json:"id"`
		Description string `json:"description"`
		Status      any    `json:"status"`
		NoCheck     any    `json:"nocheck"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var id = ""
	if raw.Id != nil {
		id = fmt.Sprint(raw.Id)
	}
	*s = HaRemoteService{Uid: raw.Uid, Name: raw.Name, Id: id, Description: raw.Description,
		Running: coreServiceFlag(raw.Status), NoCheck: coreServiceFlag(raw.NoCheck)}
	if s.Uid == "" {
		s.Uid = s.Name
		if id != "" {
			s.Uid += "_" + id
		}
	}
	return nil
}

// HaRemoteServiceListRaw lists the services of the backup node (cached by OPNsense for 5 seconds) with the raw
// API objects, empty without a reachable peer
func (opn *SystemApi) HaRemoteServiceListRaw() ([]HaRemoteService, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.haStatusEndpoint("services"), "")
	if err != nil {
		return nil, nil, err
	}
	var services = make([]HaRemoteService, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &services[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected remote service from OPNsense: %w", err)
		}
	}
	return services, rows, nil
}

// HaRemoteServiceAction pushes the configuration to the backup node and then starts, stops or restarts one of
// its services (name and the instance id, "" for none)
func (opn *SystemApi) HaRemoteServiceAction(action string, name string, id string) error {
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("unknown remote service action %q", action)
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("cannot act on a remote service without name")
	}
	var endpoint = opn.haStatusEndpoint(action) + "/" + url.PathEscape(name)
	if id != "" {
		endpoint += "/" + url.PathEscape(id)
	}
	var container struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return haStatusError(fmt.Sprintf("remote %s of %s", action, name), container.Status, container.Message)
	}
	return nil
}

// HaSync pushes the configuration to the backup node and restarts all its services ("Synchronize and reconfigure
// all"), returns the number of restarted services
func (opn *SystemApi) HaSync() (int, error) {
	var container struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Count   int    `json:"count"`
	}
	if err := opn.DoJSON("POST", opn.haStatusEndpoint("restart_all"), nil, &container); err != nil {
		return 0, err
	}
	if container.Status != "ok" {
		return 0, haStatusError("HA sync", container.Status, container.Message)
	}
	return container.Count, nil
}

func haStatusError(what string, status string, message string) error {
	if message != "" {
		return fmt.Errorf("%s failed: %s", what, message)
	}
	return fmt.Errorf("%s failed: status %q (is a backup node configured and reachable?)", what, status)
}
