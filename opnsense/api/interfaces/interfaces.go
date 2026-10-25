// Package interfaces wraps the OPNsense API behind the Interfaces menu (api/interfaces/*): the devices (VLAN,
// LAGG, bridge, GIF, GRE, loopback, VXLAN), virtual IPs, static ARP/NDP neighbors, the global interface settings,
// the interface overview and a read-only view of the interface assignments
package interfaces

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// InterfacesApi wraps api/interfaces of OPNsense 26.7
//
//goland:noinspection GoNameStartsWithPackageName
type InterfacesApi struct {
	*coreapi.OPNsense
}

func (opn *InterfacesApi) endpoint(controller string, method string) string {
	return opn.EndpointForPluginControllerMethod("interfaces", controller, method)
}

// Kind describes one item type of the Interfaces menu: its controller, the JSON key of its records and how
// its device name is formed. Use the predefined kinds (Vlans, Laggs, ...)
type Kind struct {
	// Name is used in messages, e.g. "VLAN"
	Name       string
	controller string
	container  string
	// deviceField holds the device name (vlanif, laggif, ...), devicePrefix + deviceId forms it otherwise
	deviceField  string
	devicePrefix string
	// keep returns the fields every set_item has to repeat from the current record, see Update
	keep func(item Item) map[string]string
}

var (
	// Vlans are Interfaces > Devices > VLAN (api/interfaces/vlan_settings). Fields: if (parent device), tag
	// (1-4094), pcp (0-7), proto ("" automatic, 802.1q, 802.1ad), descr, vlanif (device name, generated as vlan0N
	// or qinq0N when empty)
	Vlans = Kind{Name: "VLAN", controller: "vlan_settings", container: "vlan", deviceField: "vlanif", keep: vlanKeep}
	// Laggs are Interfaces > Devices > LAGG (api/interfaces/lagg_settings). Fields: members (unassigned physical
	// devices, comma separated), primary_member, proto (none, lacp, failover, fec, loadbalance, roundrobin),
	// lacp_fast_timeout, use_flowid ("", 1, 0), lagghash (l2,l3,l4), lacp_strict ("", 1, 0), mtu, descr. The
	// device name laggif is assigned by OPNsense and can not be changed
	Laggs = Kind{Name: "LAGG", controller: "lagg_settings", container: "lagg", deviceField: "laggif"}
	// Bridges are Interfaces > Devices > Bridge (api/interfaces/bridge_settings). Fields: members (interface
	// identifiers like lan, opt1), linklocal, enablestp, proto (rstp, stp), stp, maxage, fwdelay, holdcnt, maxaddr,
	// timeout, span, edge, autoedge, ptp, autoptp, static, private, descr. The device name bridgeif is assigned by
	// OPNsense and can not be changed
	Bridges = Kind{Name: "bridge", controller: "bridge_settings", container: "bridge", deviceField: "bridgeif"}
	// Gifs are Interfaces > Devices > GIF (api/interfaces/gif_settings). Fields: local-addr (an interface
	// identifier, a CARP VIP like wan_vip1 or an address; stored in if or ipaddr), remote-addr, tunnel-local-addr,
	// tunnel-remote-addr, tunnel-remote-net (1-128), link1 (ECN friendly), link2 (no ingress filtering), noclamp
	// (newer 26.7 releases only), descr. The device name gifif is assigned by OPNsense
	Gifs = Kind{Name: "GIF", controller: "gif_settings", container: "gif", deviceField: "gifif"}
	// Gres are Interfaces > Devices > GRE (api/interfaces/gre_settings), the fields of Gifs without the flags.
	// The device name greif is assigned by OPNsense
	Gres = Kind{Name: "GRE", controller: "gre_settings", container: "gre", deviceField: "greif"}
	// Loopbacks are Interfaces > Devices > Loopback (api/interfaces/loopback_settings). Fields: description
	// (required); deviceId is numbered by OPNsense, the device is lo<deviceId>
	Loopbacks = Kind{Name: "loopback", controller: "loopback_settings", container: "loopback", devicePrefix: "lo"}
	// Vxlans are Interfaces > Devices > VXLAN (api/interfaces/vxlan_settings). Fields: vxlanid (VNI 0-16777215),
	// vxlanlocal (source address), vxlanlocalport, vxlanremote, vxlanremoteport, vxlangroup (multicast group,
	// instead of vxlanremote), vxlandev (interface identifier, required with a group). deviceId is numbered by
	// OPNsense, the device is vxlan<deviceId>
	Vxlans = Kind{Name: "VXLAN", controller: "vxlan_settings", container: "vxlan", devicePrefix: "vxlan"}
	// Vips are Interfaces > Virtual IPs (api/interfaces/vip_settings). Fields: interface (identifier), mode
	// (ipalias, carp, proxyarp), network (address/bits, search rows hold it as subnet and subnet_bits), gateway,
	// noexpand, nobind, password (CARP, returned in clear text by search_item), vhid, advbase, advskew, peer,
	// peer6, nosync, descr
	Vips = Kind{Name: "virtual IP", controller: "vip_settings", container: "vip", keep: vipKeep}
	// Neighbors are Interfaces > Neighbors, static ARP/NDP entries (api/interfaces/neighbor_settings). Fields:
	// etheraddr, ipaddress, descr; origin is "manual" for configured entries, other origins are generated (e.g.
	// from DHCP reservations) and can not be changed here
	Neighbors = Kind{Name: "neighbor", controller: "neighbor_settings", container: "neighbor"}
)

// Kinds lists all item kinds
var Kinds = []Kind{Vlans, Laggs, Bridges, Gifs, Gres, Loopbacks, Vxlans, Vips, Neighbors}

// NeighborManual is the origin of configured neighbors
const NeighborManual = "manual"

// Item is one record as search_item returns it
type Item struct {
	Uuid string
	// Fields are the API values: option fields hold the selected key(s), comma separated
	Fields map[string]string
	// Display holds the texts OPNsense adds for option fields ("%if": "vtnet0 (52:54:...) [LAN]")
	Display map[string]string
	// Raw is the row as OPNsense sent it
	Raw json.RawMessage
}

// Get returns a field value, "" when the record has no such field
func (item Item) Get(field string) string {
	return item.Fields[field]
}

// Has tells whether the record has the field at all (some fields exist only in newer releases)
func (item Item) Has(field string) bool {
	var _, has = item.Fields[field]
	return has
}

func (item *Item) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*item = Item{Fields: map[string]string{}, Display: map[string]string{}, Raw: append(json.RawMessage(nil), data...)}
	for key, value := range raw {
		var text = valueText(value)
		switch {
		case key == "uuid":
			item.Uuid = text
		case strings.HasPrefix(key, "%"):
			item.Display[key[1:]] = text
		default:
			item.Fields[key] = text
		}
	}
	return nil
}

// valueText renders a JSON value as text: strings as they are, lists comma separated, true/false as 1/0, null as ""
func valueText(value json.RawMessage) string {
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	var list []json.RawMessage
	if json.Unmarshal(value, &list) == nil {
		var texts = make([]string, 0, len(list))
		for _, element := range list {
			texts = append(texts, valueText(element))
		}
		return strings.Join(texts, ",")
	}
	var flag bool
	if json.Unmarshal(value, &flag) == nil {
		if flag {
			return "1"
		}
		return "0"
	}
	if trimmed := strings.TrimSpace(string(value)); trimmed != "null" {
		return trimmed
	}
	return ""
}

// Device returns the device name of an item (vlan01, lagg0, lo1, ...), "" for virtual IPs and neighbors. The VLAN
// search marks assigned devices with the interface name ("vlan01 [OPT1]"), that suffix is removed
func (kind Kind) Device(item Item) string {
	switch {
	case kind.deviceField != "":
		var device, _, _ = strings.Cut(item.Get(kind.deviceField), " [")
		return device
	case kind.devicePrefix != "" && item.Get("deviceId") != "":
		return kind.devicePrefix + item.Get("deviceId")
	}
	return ""
}

// HasDevice tells whether the items of this kind are devices with a name
func (kind Kind) HasDevice() bool {
	return kind.deviceField != "" || kind.devicePrefix != ""
}

func vlanKeep(item Item) map[string]string {
	// set_item regenerates the device name from the posted parent and tag: without them a QinQ device would be
	// renamed, and the "assigned" checks compare the posted tag
	var device, _, _ = strings.Cut(item.Get("vlanif"), " [")
	return map[string]string{"if": item.Get("if"), "tag": item.Get("tag"), "vlanif": device}
}

func vipKeep(item Item) map[string]string {
	// set_item treats a missing network or interface as a change of the address and queues the removal of the
	// current address for the next apply
	return map[string]string{"interface": item.Get("interface"), "network": VipNetwork(item)}
}

// VipNetwork returns the address/bits of a virtual IP, "" when it has no address
func VipNetwork(item Item) string {
	if item.Get("subnet") == "" {
		return ""
	}
	return item.Get("subnet") + "/" + item.Get("subnet_bits")
}

// --- items

// Search returns the items of a kind where any field contains searchPhrase ("" for all), in API order
func (opn *InterfacesApi) Search(kind Kind, searchPhrase string) ([]Item, error) {
	if kind.controller == "" {
		return nil, errors.New("unknown item kind")
	}
	return coreapi.Search[Item](opn.OPNsense, opn.endpoint(kind.controller, "search_item"), searchPhrase)
}

// List returns all items of a kind
func (opn *InterfacesApi) List(kind Kind) ([]Item, error) {
	return opn.Search(kind, "")
}

// Get returns the item with this uuid or a *NotFoundError (get_item answers an unknown uuid with [], so the
// existence is checked by search)
func (opn *InterfacesApi) Get(kind Kind, uuid string) (Item, error) {
	if uuid == "" {
		return Item{}, fmt.Errorf("cannot look up a %s without uuid", kind.Name)
	}
	var items, err = opn.List(kind)
	if err != nil {
		return Item{}, err
	}
	for _, item := range items {
		if item.Uuid == uuid {
			return item, nil
		}
	}
	return Item{}, &coreapi.NotFoundError{Name: kind.Name + " " + uuid}
}

// Create adds an item from fields (API names, fields not given get the OPNsense defaults) and returns its uuid.
// Device names are assigned by OPNsense (VLANs take vlanif when given)
func (opn *InterfacesApi) Create(kind Kind, fields map[string]string) (string, error) {
	if kind.controller == "" {
		return "", errors.New("unknown item kind")
	}
	var uuid, err = opn.Mutate(opn.endpoint(kind.controller, "add_item"), map[string]any{kind.container: fields})
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("OPNsense saved the %s but returned no uuid", kind.Name)
	}
	return uuid, nil
}

// Update changes the given fields of an item, the others are kept. The item must exist (set_item would create
// it, checked first). Fields OPNsense needs on every change are repeated from the current record unless given:
// parent, tag and device name of VLANs, interface and network of virtual IPs. Generated neighbors can not be
// changed
func (opn *InterfacesApi) Update(kind Kind, uuid string, fields map[string]string) error {
	var current, err = opn.Get(kind, uuid)
	if err != nil {
		return err
	}
	if err := checkChangeable(kind, current); err != nil {
		return err
	}
	var body = map[string]string{}
	if kind.keep != nil {
		for field, value := range kind.keep(current) {
			body[field] = value
		}
	}
	for field, value := range fields {
		body[field] = value
	}
	_, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint(kind.controller, "set_item"), url.PathEscape(uuid)),
		map[string]any{kind.container: body})
	return err
}

// Remove deletes an item. Unknown uuids are a *NotFoundError, items in use (an assigned device, a VLAN with QinQ
// children, an address used by NAT rules, ...) are refused by OPNsense with an *HttpError naming the use
func (opn *InterfacesApi) Remove(kind Kind, uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a %s by uuid %q", kind.Name, uuid)
	}
	if kind.controller == Neighbors.controller {
		var current, err = opn.Get(kind, uuid)
		if err != nil {
			return err
		}
		if err := checkChangeable(kind, current); err != nil {
			return err
		}
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint(kind.controller, "del_item"), url.PathEscape(uuid)), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: kind.Name + " " + uuid, Err: err}
	}
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
		return fmt.Errorf("cannot remove %s %s: %s", kind.Name, uuid, httpErr.Message)
	}
	return err
}

func checkChangeable(kind Kind, item Item) error {
	if kind.controller == Neighbors.controller && item.Get("origin") != "" && item.Get("origin") != NeighborManual {
		return fmt.Errorf("neighbor %s is generated by %s and can not be changed here", item.Get("ipaddress"), item.Get("origin"))
	}
	return nil
}

// Reconfigure applies the saved items of a kind (POST reconfigure), what that touches depends on the kind:
//   - VLANs: creates new VLAN devices, removes deleted ones, updates priority and protocol of existing ones
//   - LAGGs, GIFs, GREs: (re)configures the changed devices, removes deleted ones
//   - bridges: removes deleted bridges and reconfigures every bridge and its members
//   - loopbacks, VXLANs: creates the configured devices and removes the others of the type
//   - virtual IPs: removes deleted addresses, adds new or changed ones (CARP included)
//   - neighbors: sets the static ARP/NDP entries and removes deleted ones
func (opn *InterfacesApi) Reconfigure(kind Kind) error {
	if kind.controller == "" {
		return errors.New("unknown item kind")
	}
	return opn.reconfigure(kind.controller, kind.Name)
}

// reconfigure POSTs controller/reconfigure, a GET is a silent no-op. The status is "ok" or the configd output
func (opn *InterfacesApi) reconfigure(controller string, what string) error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint(controller, "reconfigure"), map[string]any{}, &container); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(container.Status), "ok") {
		return fmt.Errorf("%s reconfigure failed: status %q", what, container.Status)
	}
	return nil
}

// --- forms

// Option is one choice of an option field: Key is stored and sent, Value is the display text
type Option struct {
	Key      string
	Value    string
	Selected bool
}

// Form is a new record as get_item without uuid returns it: the default values and the choices of the option
// fields (which depend on the firewall, e.g. the parent devices of VLANs or the members of LAGGs and bridges)
type Form struct {
	// Defaults are the default values, option fields as their selected key(s) comma separated
	Defaults map[string]string
	// Options are the choices of the option fields by field name, in API order
	Options map[string][]Option
}

// Form returns the defaults and the option choices of a new item
func (opn *InterfacesApi) Form(kind Kind) (Form, error) {
	if kind.controller == "" {
		return Form{}, errors.New("unknown item kind")
	}
	var container map[string]map[string]json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint(kind.controller, "get_item"), nil, &container); err != nil {
		return Form{}, err
	}
	var record, found = container[kind.container]
	if !found {
		return Form{}, fmt.Errorf("unexpected answer from %s get_item: no %s record", kind.Name, kind.container)
	}
	return parseForm(record), nil
}

func parseForm(record map[string]json.RawMessage) Form {
	var form = Form{Defaults: map[string]string{}, Options: map[string][]Option{}}
	for field, value := range record {
		if options, err := parseOptions(value); err == nil {
			form.Options[field] = options
			var selected = make([]string, 0)
			for _, option := range options {
				if option.Selected {
					selected = append(selected, option.Key)
				}
			}
			form.Defaults[field] = strings.Join(selected, ",")
			continue
		}
		form.Defaults[field] = valueText(value)
	}
	return form
}

// parseOptions decodes an OPNsense option map {"<key>":{"value":"..","selected":0|1},...} keeping its order, or an
// option list [{"value":"..","selected":0|1},...] whose keys are the indexes (disablevlanhwfilter of the settings)
func parseOptions(raw json.RawMessage) ([]Option, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	var token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	var isList = token == json.Delim('[')
	if token != json.Delim('{') && !isList {
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	var options = make([]Option, 0)
	for index := 0; decoder.More(); index++ {
		var key = strconv.Itoa(index)
		if !isList {
			var keyToken, keyErr = decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			key, _ = keyToken.(string)
		}
		var option struct {
			Value    *string         `json:"value"`
			Selected json.RawMessage `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return nil, err
		}
		if option.Value == nil {
			return nil, fmt.Errorf("not an option map: %.50s", raw)
		}
		var selected = strings.Trim(string(option.Selected), `"`)
		options = append(options, Option{Key: key, Value: *option.Value, Selected: selected == "1" || selected == "true"})
	}
	if isList && len(options) == 0 {
		// an empty list is a list field without values (LAGG members without choices), not an option list
		return nil, fmt.Errorf("not an option list: %.50s", raw)
	}
	return options, nil
}

// UnusedVhid returns the lowest VHID (1-255) no virtual IP uses yet
func (opn *InterfacesApi) UnusedVhid() (int, error) {
	var container struct {
		Vhid   int    `json:"vhid"`
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("vip_settings", "get_unused_vhid"), nil, &container); err != nil {
		return 0, err
	}
	if container.Status != "ok" {
		return 0, errors.New("no unused VHID left (1-255 are in use)")
	}
	return container.Vhid, nil
}
