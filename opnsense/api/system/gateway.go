package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
)

// Gateway is a row of System > Gateways > Configuration (api/routing/settings/search_gateway).
//
// There are two kinds of rows:
//   - gateways stored in the configuration, their uuid is a regular uuid
//   - gateways OPNsense generates for dynamic interfaces (DHCP, PPPoE, ...) like WAN_DHCP which are not configured,
//     their uuid is their name. Changing one stores a configured override (OPNsense creates it with a new uuid),
//     removing the override brings back the generated gateway
//
// search_gateway mixes the types of the values (priority is a number for generated rows and a string for configured
// ones, flags are booleans or "0"/"1"), Gateway normalizes them: numbers are strings, flags are bools
type Gateway struct {
	Uuid        string
	Name        string
	Description string // descr
	// Interface is the OPNsense interface key like lan or opt1, InterfaceDescription its name like LAN
	Interface            string
	InterfaceDescription string // interface_descr
	Device               string // if: the network device, like vtnet0
	IpProtocol           string // inet or inet6
	// Address is the gateway IP (gateway), the current address for dynamic gateways
	Address string
	// Disabled gateways are not used
	Disabled bool
	// Upstream is the configured "upstream gateway" flag (the model field defaultgw): a candidate for the default route
	Upstream bool
	// Default is true for the gateway which is the active default gateway now (search_gateway defaultgw)
	Default bool
	// Dynamic gateways get their address from the interface (DHCP, PPPoE, ...)
	Dynamic bool
	// Virtual is set by OPNsense for generated rows which are not stored in the configuration
	Virtual    bool
	FarGateway bool // fargw: the gateway may be outside of the interface subnet
	// MonitorDisable: the gateway is considered always up (no dpinger monitoring)
	MonitorDisable            bool
	MonitorNoRoute            bool   // monitor_noroute: no host route for the monitor IP
	MonitorKillStates         bool   // monitor_killstates: kill states when the gateway goes down (failover states)
	MonitorKillStatesPriority bool   // monitor_killstates_priority: kill states when a higher priority gateway comes up (failback states)
	Monitor                   string // the monitor IP, empty for the gateway address
	ForceDown                 bool   // force_down: the gateway is considered down
	NoSync                    bool   // nosync: not synced to an HA peer
	Priority                  string // 0-255, lower is more important
	Weight                    string // 1-10, the weight in gateway groups
	// The monitoring thresholds as configured, "" for the default. Current holds the effective values of
	// configured gateways keyed by field name (latencylow, ..., data_length)
	LatencyLow   string
	LatencyHigh  string
	LossLow      string
	LossHigh     string
	Interval     string
	TimePeriod   string // time_period
	LossInterval string // loss_interval
	DataLength   string // data_length
	Current      map[string]string
	// Status as shown by the GUI (e.g. Online, Offline, Pending, Misconfigured Gateway IP) and the monitoring
	// values, "~" when there are none
	Status string
	Delay  string
	StdDev string
	Loss   string
	// Raw is the row as returned by the API
	Raw json.RawMessage
}

// UnmarshalJSON reads a search_gateway row, tolerating the mixed value types
func (g *Gateway) UnmarshalJSON(data []byte) error {
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	var text = func(key string) string {
		return gatewayText(row[key])
	}
	var flag = func(key string) bool {
		return gatewayFlag(row[key])
	}
	*g = Gateway{
		Uuid: text("uuid"), Name: text("name"), Description: text("descr"),
		Interface: text("interface"), InterfaceDescription: text("interface_descr"), Device: text("if"),
		IpProtocol: text("ipprotocol"), Address: text("gateway"),
		Disabled: flag("disabled"), Upstream: flag("upstream"), Default: flag("defaultgw"), Dynamic: flag("dynamic"),
		Virtual: flag("virtual"), FarGateway: flag("fargw"), MonitorDisable: flag("monitor_disable"),
		MonitorNoRoute: flag("monitor_noroute"), MonitorKillStates: flag("monitor_killstates"),
		MonitorKillStatesPriority: flag("monitor_killstates_priority"), Monitor: text("monitor"),
		ForceDown: flag("force_down"), NoSync: flag("nosync"), Priority: text("priority"), Weight: text("weight"),
		LatencyLow: text("latencylow"), LatencyHigh: text("latencyhigh"), LossLow: text("losslow"), LossHigh: text("losshigh"),
		Interval: text("interval"), TimePeriod: text("time_period"), LossInterval: text("loss_interval"),
		DataLength: text("data_length"), Status: text("status"), Delay: text("delay"), StdDev: text("stddev"), Loss: text("loss"),
		Raw: append(json.RawMessage(nil), data...),
	}
	for key, value := range row {
		if field, isCurrent := strings.CutPrefix(key, "current_"); isCurrent {
			if g.Current == nil {
				g.Current = map[string]string{}
			}
			g.Current[field] = gatewayText(value)
		}
	}
	return nil
}

// gatewayText renders a JSON value of mixed type as string: numbers without exponent, booleans as "1"/"0"
func gatewayText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
		return "0"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		var encoded, _ = json.Marshal(v)
		return string(encoded)
	}
}

// gatewayFlag reads a flag sent as boolean, "0"/"1" or number
func gatewayFlag(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		}
		return false
	case float64:
		return v != 0
	default:
		return false
	}
}

// IsConfigured is false for gateways OPNsense generates for dynamic interfaces which are not stored in the
// configuration (their uuid is their name)
func (g Gateway) IsConfigured() bool {
	return GatewayIsUuid(g.Uuid)
}

var gatewayUuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// GatewayIsUuid tells whether id is a uuid (a configured gateway) and not a gateway name. OPNsense handles every
// other id passed to get_gateway / set_gateway as a name
func GatewayIsUuid(id string) bool {
	return gatewayUuidPattern.MatchString(id)
}

// GatewayFields holds gateway fields for GatewayCreate / GatewayUpdate keyed by the API field name, see GatewayFieldNames
type GatewayFields map[string]string

// GatewayFieldNames are the writable fields of a gateway, in the order of the GUI
var GatewayFieldNames = []string{
	"disabled", "name", "descr", "interface", "ipprotocol", "gateway", "defaultgw", "fargw", "monitor_disable",
	"monitor_noroute", "monitor_killstates", "monitor_killstates_priority", "monitor", "force_down", "nosync",
	"priority", "weight", "latencylow", "latencyhigh", "losslow", "losshigh", "interval", "time_period",
	"loss_interval", "data_length",
}

// GatewayDefaults are the values OPNsense uses for a new gateway (the empty thresholds use the monitoring
// defaults), interface, name and gateway have no usable default
var GatewayDefaults = GatewayFields{
	"disabled": "0", "descr": "", "ipprotocol": "inet", "defaultgw": "0", "fargw": "0", "monitor_disable": "1",
	"monitor_noroute": "0", "monitor_killstates": "0", "monitor_killstates_priority": "0", "monitor": "",
	"force_down": "0", "nosync": "0", "priority": "255", "weight": "1", "latencylow": "", "latencyhigh": "",
	"losslow": "", "losshigh": "", "interval": "", "time_period": "", "loss_interval": "", "data_length": "",
}

// GatewayDynamicAddress is the gateway value of configured gateways of dynamic interfaces
const GatewayDynamicAddress = "dynamic"

var gatewayNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

// GatewayValidateName checks a gateway name like OPNsense does: 1-32 characters of a-z, A-Z, 0-9, _ and -
func GatewayValidateName(name string) error {
	if !gatewayNamePattern.MatchString(name) {
		return fmt.Errorf("invalid gateway name %q: 1-32 characters of a-z, A-Z, 0-9, _ and -", name)
	}
	return nil
}

// GatewayValidateAddress checks an address (gateway or monitor) for protocol inet / inet6 ("" for any).
// Empty is accepted (dynamic resp. the gateway itself), dynamic only when allowDynamic
func GatewayValidateAddress(address string, protocol string, allowDynamic bool) error {
	if address == "" || allowDynamic && address == GatewayDynamicAddress {
		return nil
	}
	var ip = net.ParseIP(address)
	switch {
	case ip == nil:
		return fmt.Errorf("invalid address %q: expected an IPv4 or IPv6 address", address)
	case protocol == "inet" && ip.To4() == nil:
		return fmt.Errorf("invalid address %q: expected an IPv4 address for an IPv4 gateway", address)
	case protocol == "inet6" && (ip.To4() != nil || strings.Contains(address, ".")):
		return fmt.Errorf("invalid address %q: expected an IPv6 address for an IPv6 gateway", address)
	}
	return nil
}

// gatewayRange is the allowed range of a numeric field, empty values are allowed when optional (the default applies)
type gatewayRange struct {
	min, max int
	optional bool
}

var gatewayRanges = map[string]gatewayRange{
	"priority":      {0, 255, false},
	"weight":        {1, 10, false},
	"latencylow":    {1, 1 << 30, true},
	"latencyhigh":   {1, 1 << 30, true},
	"losslow":       {1, 99, true},
	"losshigh":      {1, 100, true},
	"interval":      {1, 1 << 30, true},
	"time_period":   {1, 1 << 30, true},
	"loss_interval": {1, 1 << 30, true},
	"data_length":   {0, 1 << 30, true},
}

var gatewayFlags = map[string]bool{
	"disabled": true, "defaultgw": true, "fargw": true, "monitor_disable": true, "monitor_noroute": true,
	"monitor_killstates": true, "monitor_killstates_priority": true, "force_down": true, "nosync": true,
}

// GatewayValidateFields checks the fields client-side. protocol is the address family the addresses must match
// (the ipprotocol of the gateway when the fields do not change it, "" when not known)
func GatewayValidateFields(fields GatewayFields, protocol string) error {
	if value, given := fields["ipprotocol"]; given {
		protocol = value
	}
	var names = make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		var value = fields[name]
		var err error
		switch {
		case name == "name":
			err = GatewayValidateName(value)
		case name == "ipprotocol":
			if value != "inet" && value != "inet6" {
				err = fmt.Errorf("invalid ipprotocol %q: expected inet or inet6", value)
			}
		case name == "interface":
			if value == "" || strings.ContainsFunc(value, unicode.IsSpace) {
				err = fmt.Errorf("invalid interface %q: expected an interface key like lan or opt1", value)
			}
		case name == "gateway":
			err = GatewayValidateAddress(value, protocol, true)
		case name == "monitor":
			err = GatewayValidateAddress(value, protocol, false)
		case name == "descr":
			if strings.ContainsFunc(value, unicode.IsControl) {
				err = fmt.Errorf("invalid description %q: control characters are not allowed", value)
			}
		case gatewayFlags[name]:
			if value != "0" && value != "1" {
				err = fmt.Errorf("invalid %s %q: expected 0 or 1", name, value)
			}
		default:
			var limits, isNumber = gatewayRanges[name]
			if !isNumber {
				return fmt.Errorf("unknown gateway field %q", name)
			}
			if value == "" && limits.optional {
				continue
			}
			var number, convErr = strconv.Atoi(value)
			if convErr != nil || number < limits.min || number > limits.max {
				err = fmt.Errorf("invalid %s %q: expected a number from %d to %d", name, value, limits.min, limits.max)
			}
		}
		if err != nil {
			return err
		}
	}

	for _, pair := range [][2]string{{"latencylow", "latencyhigh"}, {"losslow", "losshigh"}} {
		var low, lowErr = strconv.Atoi(fields[pair[0]])
		var high, highErr = strconv.Atoi(fields[pair[1]])
		if lowErr == nil && highErr == nil && low >= high {
			return fmt.Errorf("%s (%d) must be lower than %s (%d)", pair[0], low, pair[1], high)
		}
	}
	return nil
}

func (opn *SystemApi) gatewayEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("routing", "settings", method)
}

// GatewayList returns all gateways, configured and generated ones, with their status.
// search_gateway ignores searchPhrase on GET (only a POST would filter), so there is no search variant
func (opn *SystemApi) GatewayList() ([]Gateway, error) {
	return coreapi.Search[Gateway](opn.OPNsense, opn.gatewayEndpoint("search_gateway"), "")
}

// GatewayGet returns the gateway with this uuid or (exactly) this name, or a *NotFoundError.
// get_gateway is no help: it answers unknown uuids with an empty default record
func (opn *SystemApi) GatewayGet(id string) (Gateway, error) {
	var gateways, err = opn.GatewayList()
	if err != nil {
		return Gateway{}, err
	}
	return gatewayFind(gateways, id)
}

func gatewayFind(gateways []Gateway, id string) (Gateway, error) {
	if id == "" {
		return Gateway{}, errors.New("gateway uuid or name must not be empty")
	}
	for _, gateway := range gateways {
		if gateway.Uuid == id {
			return gateway, nil
		}
	}
	for _, gateway := range gateways {
		if gateway.Name == id {
			return gateway, nil
		}
	}
	return Gateway{}, &coreapi.NotFoundError{Name: fmt.Sprintf("gateway %s", id)}
}

// GatewayCreate adds a gateway and returns its uuid. name and interface are required (OPNsense would silently use
// wan), fields not given get the OPNsense defaults (GatewayDefaults). The address (gateway) must be unique
func (opn *SystemApi) GatewayCreate(fields GatewayFields) (string, error) {
	for _, required := range []string{"name", "interface"} {
		if fields[required] == "" {
			return "", fmt.Errorf("a new gateway needs a %s", required)
		}
	}
	if err := GatewayValidateFields(fields, "inet"); err != nil {
		return "", err
	}
	return opn.Mutate(opn.gatewayEndpoint("add_gateway"), map[string]GatewayFields{"gateway_item": fields})
}

// GatewayUpdate changes the given fields of the gateway with this uuid or name and returns the uuid of the
// configured gateway. The name can not be changed (OPNsense refuses it).
//
// A configured gateway gets only the given fields (set_gateway merges). A generated gateway of a dynamic interface
// (not configured) is overridden like the GUI does it: its complete record (get_gateway/<name>) merged with the
// fields is stored with set_gateway/<name>, OPNsense creates a configured gateway with a new uuid for it.
// Returns *NotFoundError for unknown gateways (checked first, set_gateway would create a new one)
func (opn *SystemApi) GatewayUpdate(id string, fields GatewayFields) (string, error) {
	if len(fields) == 0 {
		return "", errors.New("no gateway fields to change")
	}
	var gateway, err = opn.GatewayGet(id)
	if err != nil {
		return "", err
	}
	if name, given := fields["name"]; given && name != gateway.Name {
		return "", fmt.Errorf("gateway %s can not be renamed to %s: OPNsense does not allow changing the name of a gateway", gateway.Name, name)
	}
	if err := GatewayValidateFields(fields, gateway.IpProtocol); err != nil {
		return "", err
	}

	if gateway.IsConfigured() {
		return gateway.Uuid, opn.gatewaySet(gateway.Uuid, fields)
	}
	return opn.gatewayOverride(gateway, fields)
}

// gatewaySet sends fields to set_gateway/<uuid> without checking that uuid exists
func (opn *SystemApi) gatewaySet(uuid string, fields GatewayFields) error {
	var body = map[string]GatewayFields{"gateway_item": fields}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.gatewayEndpoint("set_gateway"), uuid), body)
	return gatewayMutationError(uuid, err)
}

// gatewayOverride stores a configured override of the generated gateway with its complete record merged with
// fields and returns the uuid OPNsense created for it
func (opn *SystemApi) gatewayOverride(gateway Gateway, fields GatewayFields) (string, error) {
	var record, err = opn.GatewayRecord(gateway.Name)
	if err != nil {
		return "", err
	}
	if record["name"] != gateway.Name {
		// get_gateway answers unknown names with an empty default record
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("gateway %s", gateway.Name)}
	}
	for name, value := range fields {
		record[name] = value
	}
	if err := opn.gatewaySet(gateway.Name, record); err != nil {
		return "", err
	}

	var gateways, listErr = opn.GatewayList()
	if listErr != nil {
		return "", fmt.Errorf("the override of %s was stored, but listing the gateways failed: %w", gateway.Name, listErr)
	}
	for _, candidate := range gateways {
		if candidate.Name == gateway.Name && candidate.IsConfigured() {
			return candidate.Uuid, nil
		}
	}
	return "", fmt.Errorf("the override of %s was stored, but no configured gateway with this name is listed", gateway.Name)
}

// GatewayRecord returns the stored fields of the gateway with this uuid or name as get_gateway returns them, with the
// option fields (interface, ipprotocol) reduced to the selected key. Generated gateways of dynamic interfaces have an
// empty gateway (address). For an unknown uuid or name OPNsense answers with the defaults of a new gateway (empty name)
func (opn *SystemApi) GatewayRecord(id string) (GatewayFields, error) {
	var record, err = opn.gatewayGetRecord(id)
	if err != nil {
		return nil, err
	}
	var fields = GatewayFields{}
	for _, name := range GatewayFieldNames {
		var raw, given = record[name]
		if !given {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			fields[name] = value
			continue
		}
		var options map[string]gatewayOption
		if err := json.Unmarshal(raw, &options); err == nil {
			fields[name] = gatewaySelected(options)
			continue
		}
		var other any
		if err := json.Unmarshal(raw, &other); err != nil {
			return nil, fmt.Errorf("unexpected value of %s in get_gateway: %s", name, raw)
		}
		fields[name] = gatewayText(other)
	}
	return fields, nil
}

type gatewayOption struct {
	Value    string `json:"value"`
	Selected any    `json:"selected"`
}

// gatewaySelected returns the selected keys of an option field, comma separated and sorted
func gatewaySelected(options map[string]gatewayOption) string {
	var selected []string
	for key, option := range options {
		if gatewayFlag(option.Selected) {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return strings.Join(selected, ",")
}

func (opn *SystemApi) gatewayGetRecord(id string) (map[string]json.RawMessage, error) {
	var endpoint = opn.gatewayEndpoint("get_gateway")
	if id != "" {
		endpoint += "/" + id
	}
	var container struct {
		GatewayItem map[string]json.RawMessage `json:"gateway_item"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	if container.GatewayItem == nil {
		return nil, fmt.Errorf("unexpected answer from %s: no gateway_item", endpoint)
	}
	return container.GatewayItem, nil
}

// GatewayInterface is an interface a gateway can be attached to
type GatewayInterface struct {
	Key         string // like lan or opt1
	Description string // like LAN
}

// GatewayInterfaces returns the interfaces gateways can use (the options of get_gateway), sorted by key
func (opn *SystemApi) GatewayInterfaces() ([]GatewayInterface, error) {
	var record, err = opn.gatewayGetRecord("")
	if err != nil {
		return nil, err
	}
	var options map[string]gatewayOption
	if err := json.Unmarshal(record["interface"], &options); err != nil {
		return nil, fmt.Errorf("unexpected interface options in get_gateway: %w", err)
	}
	var interfaces = make([]GatewayInterface, 0, len(options))
	for key, option := range options {
		if key != "" {
			interfaces = append(interfaces, GatewayInterface{Key: key, Description: option.Value})
		}
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Key < interfaces[j].Key })
	return interfaces, nil
}

// GatewayRemove deletes the configured gateway uuid. Removing the override of a dynamic interface's gateway brings
// back the generated one, generated gateways themselves can not be removed. Gateways in use by an interface, a
// gateway group or a static route are refused by OPNsense, its message is returned.
// Returns *NotFoundError when the uuid does not exist
func (opn *SystemApi) GatewayRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if !GatewayIsUuid(uuid) {
		return fmt.Errorf("%s is generated by OPNsense for a dynamic interface and is not configured, it can not be removed (disable it instead)", uuid)
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.gatewayEndpoint("del_gateway"), uuid), nil)
	return gatewayMutationError(uuid, err)
}

// gatewayMutationError turns a bare {"result":"failed"} (unknown uuid) into *NotFoundError and the HTTP 500 of a
// refused change ({"errorMessage":"Gateway x cannot be deleted because it is in use on ..."}) into its message
func gatewayMutationError(uuid string, err error) error {
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 || coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("gateway %s", uuid), Err: err}
	}
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 && httpErr.Message != "" && !strings.HasPrefix(httpErr.Message, "{") {
		return errors.New(httpErr.Message)
	}
	return err
}

// GatewaySetEnabled enables or disables the gateway with this uuid or name and returns whether its state changed.
// A generated gateway of a dynamic interface is overridden for that (see GatewayUpdate)
func (opn *SystemApi) GatewaySetEnabled(id string, enabled bool) (bool, error) {
	var gateway, err = opn.GatewayGet(id)
	if err != nil {
		return false, err
	}
	if !gateway.IsConfigured() {
		if gateway.Disabled != enabled {
			return false, nil
		}
		var _, overrideErr = opn.gatewayOverride(gateway, GatewayFields{"disabled": gatewayBit(!enabled)})
		return overrideErr == nil, overrideErr
	}

	// toggle_gateway/<uuid>/<0|1> sets the given state, without the state it would flip it
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.gatewayEndpoint("toggle_gateway"), gateway.Uuid, gatewayBit(enabled))
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed": // removed meanwhile
		return false, &coreapi.NotFoundError{Name: fmt.Sprintf("gateway %s", gateway.Uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

func gatewayBit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// GatewayReconfigure applies the gateway configuration: routes, the default gateway and the gateway monitoring
// (configd "interface routes configure")
func (opn *SystemApi) GatewayReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.gatewayEndpoint("reconfigure"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("applying the gateways failed: status %q", result.Status)
	}
	return nil
}

// GatewayStatus is the monitoring state of a gateway (api/routes/gateway/status)
type GatewayStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Status is the dpinger state: none (up), down, loss, delay, delay+loss or force_down
	Status           string `json:"status"`
	StatusTranslated string `json:"status_translated"`
	// Loss, Delay (RTT) and StdDev (RTTd) as text like "0.0 %" and "0.4 ms", "~" without monitoring
	Loss    string `json:"loss"`
	Delay   string `json:"delay"`
	StdDev  string `json:"stddev"`
	Monitor string `json:"monitor"`
	// Raw is the item as returned by the API
	Raw json.RawMessage `json:"-"`
}

// GatewayStatuses returns the monitoring state of all gateways (also the ones not applied yet).
// OPNsense answers status "failed" without items when it knows no gateway at all, that is an empty list
func (opn *SystemApi) GatewayStatuses() ([]GatewayStatus, error) {
	var endpoint = opn.EndpointForPluginControllerMethod("routes", "gateway", "status")
	var container struct {
		Items  []json.RawMessage `json:"items"`
		Status string            `json:"status"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return nil, err
	}
	if container.Status != "ok" && len(container.Items) > 0 {
		return nil, fmt.Errorf("unexpected gateway status from %s: %q", endpoint, container.Status)
	}
	var statuses = make([]GatewayStatus, len(container.Items))
	for i, item := range container.Items {
		var row map[string]any
		if err := json.Unmarshal(item, &row); err != nil {
			return nil, fmt.Errorf("unexpected gateway status from %s: %w", endpoint, err)
		}
		statuses[i] = GatewayStatus{
			Name: gatewayText(row["name"]), Address: gatewayText(row["address"]), Status: gatewayText(row["status"]),
			StatusTranslated: gatewayText(row["status_translated"]), Loss: gatewayText(row["loss"]),
			Delay: gatewayText(row["delay"]), StdDev: gatewayText(row["stddev"]), Monitor: gatewayText(row["monitor"]),
			Raw: item,
		}
	}
	return statuses, nil
}
