package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
)

// LoggingGeneral are the general settings of System > Settings > Logging (syslog-ng). Booleans are "0" / "1"
type LoggingGeneral struct {
	Enabled  string `json:"enabled"`
	LogLocal string `json:"loglocal"`
	// MaxPreserve is the number of rotated log files to keep (OPNsense default 31)
	MaxPreserve string `json:"maxpreserve"`
	// MaxFileSize rotates a log file before the daily rotation once it exceeds this size, empty for no size limit
	MaxFileSize string `json:"maxfilesize"`
}

// LoggingGeneralFields are the general settings to change with LoggingGeneralSet. Only non nil fields are sent,
// OPNsense keeps all others (syslog/settings/set is a partial merge)
type LoggingGeneralFields struct {
	Enabled     *string `json:"enabled,omitempty"`
	LogLocal    *string `json:"loglocal,omitempty"`
	MaxPreserve *string `json:"maxpreserve,omitempty"`
	MaxFileSize *string `json:"maxfilesize,omitempty"`
}

// LoggingDestination is a remote syslog target. Program, Level and Facility are comma separated lists of
// option keys (e.g. "filterlog,unbound" / "info,err" / "kern,local0"), empty sends everything
type LoggingDestination struct {
	Uuid string `json:"uuid,omitempty"`
	// Enabled is "0" / "1", empty on create uses the OPNsense default (enabled)
	Enabled string `json:"enabled,omitempty"`
	// Transport is one of udp4, tcp4, udp6, tcp6, tls4, tls6 and must match the address family of Hostname
	Transport string `json:"transport"`
	Program   string `json:"program"`
	Level     string `json:"level"`
	Facility  string `json:"facility"`
	Hostname  string `json:"hostname"`
	// Certificate is the refid of a client certificate, required for the tls transports
	Certificate string `json:"certificate"`
	// Port of the remote syslog server, empty on create uses the OPNsense default (514)
	Port string `json:"port,omitempty"`
	// Rfc5424 "1" sends messages in RFC 5424 format instead of RFC 3164 (BSD), empty on create uses the default ("0")
	Rfc5424     string `json:"rfc5424,omitempty"`
	Description string `json:"description"`
}

// LoggingDestinationFields are the destination fields to change with LoggingDestinationUpdate, only non nil fields are sent
type LoggingDestinationFields struct {
	Enabled     *string `json:"enabled,omitempty"`
	Transport   *string `json:"transport,omitempty"`
	Program     *string `json:"program,omitempty"`
	Level       *string `json:"level,omitempty"`
	Facility    *string `json:"facility,omitempty"`
	Hostname    *string `json:"hostname,omitempty"`
	Certificate *string `json:"certificate,omitempty"`
	Port        *string `json:"port,omitempty"`
	Rfc5424     *string `json:"rfc5424,omitempty"`
	Description *string `json:"description,omitempty"`
}

// LoggingStat is one counter of the syslog-ng statistics (syslog/service/stats)
type LoggingStat struct {
	Description    string `json:"Description"`
	SourceName     string `json:"SourceName"`
	SourceId       string `json:"SourceId"`
	SourceInstance string `json:"SourceInstance"`
	State          string `json:"State"`
	Type           string `json:"Type"`
	Number         string `json:"Number"`
}

// LoggingTransports are the valid values of LoggingDestination.Transport
var LoggingTransports = []string{"udp4", "tcp4", "udp6", "tcp6", "tls4", "tls6"}

// LoggingLevels are the valid values of LoggingDestination.Level
var LoggingLevels = []string{"debug", "info", "notice", "warn", "err", "crit", "alert", "emerg"}

// LoggingFacilities are the valid values of LoggingDestination.Facility
var LoggingFacilities = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp",
	"security", "console", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

func (opn *SystemApi) loggingSettingsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("syslog", "settings", method)
}

func (opn *SystemApi) loggingServiceEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("syslog", "service", method)
}

// LoggingGeneralGet returns the general logging settings
func (opn *SystemApi) LoggingGeneralGet() (LoggingGeneral, error) {
	var container struct {
		Syslog *struct {
			General LoggingGeneral `json:"general"`
		} `json:"syslog"`
	}
	if err := opn.DoJSON("GET", opn.loggingSettingsEndpoint("get"), nil, &container); err != nil {
		return LoggingGeneral{}, err
	}
	if container.Syslog == nil {
		return LoggingGeneral{}, fmt.Errorf("unexpected answer from syslog settings: no syslog section")
	}
	return container.Syslog.General, nil
}

// LoggingGeneralSet changes only the non nil general settings
func (opn *SystemApi) LoggingGeneralSet(fields LoggingGeneralFields) error {
	var container = map[string]any{"syslog": map[string]any{"general": fields}}
	var _, err = opn.Mutate(opn.loggingSettingsEndpoint("set"), container)
	return err
}

// LoggingDestinationList returns all remote destinations, searchPhrase is a substring match over all columns ("" for all)
func (opn *SystemApi) LoggingDestinationList(searchPhrase string) ([]LoggingDestination, error) {
	return coreapi.Search[LoggingDestination](opn.OPNsense, opn.loggingSettingsEndpoint("search_destinations"), searchPhrase)
}

// LoggingDestinationGet returns the destination with the given uuid or a *NotFoundError
func (opn *SystemApi) LoggingDestinationGet(uuid string) (LoggingDestination, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.loggingSettingsEndpoint("get_destination/"+uuid), nil, &raw); err != nil {
		return LoggingDestination{}, err
	}

	// unknown uuids are answered with an empty array
	var notFound = &coreapi.NotFoundError{Name: fmt.Sprintf("logging destination %s", uuid)}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return LoggingDestination{}, notFound
	}
	// get_* returns option fields as {"<key>":{"value":"..","selected":1}}, decode every field raw
	var container struct {
		Destination map[string]json.RawMessage `json:"destination"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return LoggingDestination{}, err
	}
	if container.Destination == nil {
		return LoggingDestination{}, notFound
	}

	var field = func(name string) string {
		return loggingSelectedOptions(container.Destination[name])
	}
	return LoggingDestination{
		Uuid:        uuid,
		Enabled:     field("enabled"),
		Transport:   field("transport"),
		Program:     field("program"),
		Level:       field("level"),
		Facility:    field("facility"),
		Hostname:    field("hostname"),
		Certificate: field("certificate"),
		Port:        field("port"),
		Rfc5424:     field("rfc5424"),
		Description: field("description"),
	}, nil
}

// LoggingDestinationFind returns the single destination whose description equals description exactly.
// Returns *NotFoundError if there is none and *TooManyFoundError (listing the uuids) if there are several
func (opn *SystemApi) LoggingDestinationFind(description string) (LoggingDestination, error) {
	var destinations, err = opn.LoggingDestinationList(description)
	if err != nil {
		return LoggingDestination{}, err
	}
	var matches = coreapi.Filter(destinations, func(d LoggingDestination) bool {
		return d.Description == description
	})

	switch len(matches) {
	case 0:
		return LoggingDestination{}, &coreapi.NotFoundError{Name: fmt.Sprintf("logging destination with description %q", description)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, match.Uuid)
		}
		return LoggingDestination{}, &coreapi.TooManyFoundError{
			Name: fmt.Sprintf("logging destination with description %q, %d candidates: %s", description, len(matches), strings.Join(uuids, ", ")),
		}
	}
}

// LoggingDestinationCreate adds a remote destination and returns its uuid, Uuid is ignored
func (opn *SystemApi) LoggingDestinationCreate(destination LoggingDestination) (string, error) {
	destination.Uuid = ""
	var container = map[string]any{"destination": destination}
	return opn.Mutate(opn.loggingSettingsEndpoint("add_destination"), container)
}

// LoggingDestinationUpdate changes only the non nil fields of the destination uuid.
// Returns *NotFoundError when the uuid does not exist (checked first, set_destination would create it)
func (opn *SystemApi) LoggingDestinationUpdate(uuid string, fields LoggingDestinationFields) error {
	if uuid == "" {
		return errors.New("cannot update a logging destination without uuid")
	}
	// set_destination creates the destination when a well-formed uuid does not exist (yet), so make sure it does
	if _, err := opn.LoggingDestinationGet(uuid); err != nil {
		return err
	}
	var container = map[string]any{"destination": fields}
	var _, err = opn.Mutate(opn.loggingSettingsEndpoint("set_destination/"+uuid), container)
	return loggingNotFoundOnBareFailure(err, uuid)
}

// LoggingDestinationRemove deletes the destination uuid, returns *NotFoundError if it does not exist
func (opn *SystemApi) LoggingDestinationRemove(uuid string) error {
	var _, err = opn.Mutate(opn.loggingSettingsEndpoint("del_destination/"+uuid), map[string]any{})
	return err
}

// LoggingDestinationSetEnabled enables or disables the destination uuid and returns whether its state changed
func (opn *SystemApi) LoggingDestinationSetEnabled(uuid string, enabled bool) (bool, error) {
	var state = "0"
	if enabled {
		state = "1"
	}
	// toggle_destination/<uuid>/<0|1> answers {"result":"Enabled"|"Disabled","changed":true} or {"result":"failed"}
	var container struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	var endpoint = opn.loggingSettingsEndpoint(fmt.Sprintf("toggle_destination/%s/%s", uuid, state))
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &container); err != nil {
		return false, err
	}

	switch container.Result {
	case "Enabled", "Disabled":
		return container.Changed, nil
	case "failed", "not found":
		return false, &coreapi.NotFoundError{Name: fmt.Sprintf("logging destination %s", uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, container.Result)
	}
}

// LoggingServiceStatus returns the state of the syslog-ng service: running, stopped, ...
func (opn *SystemApi) LoggingServiceStatus() (string, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.loggingServiceEndpoint("status"), nil, &container); err != nil {
		return "", err
	}
	if container.Status == "" {
		return "", fmt.Errorf("unexpected answer from syslog service status: no status given")
	}
	return container.Status, nil
}

// LoggingServiceReconfigure applies the saved logging configuration (regenerates the syslog-ng config and reloads it)
func (opn *SystemApi) LoggingServiceReconfigure() error {
	var container struct {
		Status    string `json:"status"`
		StatusMsg string `json:"status_msg"`
	}
	// actions must be POSTed, a GET is silently ignored by OPNsense
	if err := opn.DoJSON("POST", opn.loggingServiceEndpoint("reconfigure"), nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		if container.StatusMsg != "" {
			return fmt.Errorf("syslog reconfigure failed: %s", container.StatusMsg)
		}
		return fmt.Errorf("syslog reconfigure failed: status %q", container.Status)
	}
	return nil
}

// LoggingServiceRestart restarts the syslog-ng service, OPNsense answers {"response":"OK"}
func (opn *SystemApi) LoggingServiceRestart() error {
	var container struct {
		Response any `json:"response"`
	}
	if err := opn.DoJSON("POST", opn.loggingServiceEndpoint("restart"), nil, &container); err != nil {
		return err
	}
	if response, isString := container.Response.(string); !isString || response != "OK" {
		return fmt.Errorf("syslog service restart failed: unexpected response %v", container.Response)
	}
	return nil
}

// LoggingStats returns the syslog-ng counters. The endpoint ignores searchPhrase, so searchPhrase is matched here,
// case-insensitive over all columns ("" for all)
func (opn *SystemApi) LoggingStats(searchPhrase string) ([]LoggingStat, error) {
	var stats, err = coreapi.Search[LoggingStat](opn.OPNsense, opn.loggingServiceEndpoint("stats"), "")
	if err != nil {
		return nil, err
	}

	var phrase = strings.ToLower(searchPhrase)
	return coreapi.Filter(stats, func(s LoggingStat) bool {
		var columns = strings.Join([]string{s.Description, s.SourceName, s.SourceId, s.SourceInstance, s.State, s.Type, s.Number}, "\n")
		return strings.Contains(strings.ToLower(columns), phrase)
	}), nil
}

// loggingNotFoundOnBareFailure maps the bare {"result":"failed"} that set_* answers for unknown uuids to *NotFoundError
func loggingNotFoundOnBareFailure(err error, uuid string) error {
	if validationErr, isValidation := err.(*coreapi.ValidationError); isValidation && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("logging destination %s", uuid)}
	}
	return err
}

// loggingSelectedOptions returns a plain string value, or the selected keys of an OPNsense option map
// joined by "," in the order OPNsense lists them
func loggingSelectedOptions(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain
	}

	// walk the object with a decoder to keep the key order, map iteration would be random
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ""
	}
	var selected = make([]string, 0)
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return strings.Join(selected, ",")
		}
		var option struct {
			Selected any `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return strings.Join(selected, ",")
		}
		if key, isString := keyToken.(string); isString && fmt.Sprint(option.Selected) == "1" {
			selected = append(selected, key)
		}
	}
	return strings.Join(selected, ",")
}
