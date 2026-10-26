package interfaces

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Interfaces > Assignments (api/interfaces/assignment, OPNsense 26.7). The rows are keyed by the interface
// identifier (lan, wan, opt1), which is also their uuid. Changes are staged: add_item, set_item and del_item write
// the change to /tmp/.interfaces.todo (descr and lock, and the anchor <optN><if/><descr/></optN> of a new
// assignment, go to config.xml at once), search_item shows a staged change in pending_action ("update" for new and
// changed interfaces, "relink" for a device change) and hides interfaces staged for removal, pending reports
// whether anything is staged and reconfigure applies it all

// Pending actions of an assignment (Assignment.PendingAction)
const (
	// AssignmentPendingUpdate is a new assignment or a changed setting (e.g. enabled)
	AssignmentPendingUpdate = "update"
	// AssignmentPendingRelink is a change of the device
	AssignmentPendingRelink = "relink"
)

// Assignment is one assigned interface of Interfaces > Assignments
type Assignment struct {
	// Identifier is the interface key like lan, wan, opt1, it is the uuid of the row
	Identifier string
	// Description is the description, OPNsense shows the upper case identifier when it is empty
	Description string
	// Device is the network device like vtnet0, vlan01
	Device string
	// DeviceText is the device with its MAC address or VLAN details as OPNsense shows it
	DeviceText string
	// Locked assignments can not be removed (new assignments are locked unless lock=0 is given)
	Locked bool
	// Enabled tells whether the interface is enabled
	Enabled bool
	// PendingAction is the staged change ("" none, AssignmentPendingUpdate, AssignmentPendingRelink)
	PendingAction string
	// Group is how OPNsense groups the device (Hardware, VLAN, ...)
	Group string
	// IPv4Type and IPv6Type are the address configuration types as OPNsense shows them (Static IPv4, DHCP, ...)
	IPv4Type string
	IPv6Type string
	// IPv4 and IPv6 are the static addresses (address/bits)
	IPv4 string
	IPv6 string
	// Raw is the row as OPNsense sent it
	Raw json.RawMessage
}

// AssignmentChange are the fields of an add or set, nil fields are not sent (set: kept, add: OPNsense default)
type AssignmentChange struct {
	// Device is the network device to assign (if)
	Device *string
	// Description (descr): letters, digits and underscores, unique
	Description *string
	// Locked (lock) prevents the removal, OPNsense defaults to locked for a new assignment
	Locked *bool
	// Enabled (enable), OPNsense defaults to enabled for a new assignment
	Enabled *bool
}

func (change AssignmentChange) fields() map[string]string {
	var fields = map[string]string{}
	if change.Device != nil {
		fields["if"] = *change.Device
	}
	if change.Description != nil {
		fields["descr"] = *change.Description
	}
	if change.Locked != nil {
		fields["lock"] = boolText(*change.Locked)
	}
	if change.Enabled != nil {
		fields["enable"] = boolText(*change.Enabled)
	}
	return fields
}

func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// AssignmentDescriptionPattern is what OPNsense accepts as description of an assignment
var AssignmentDescriptionPattern = regexp.MustCompile(`^[A-Za-z0-9_]{0,255}$`)

var assignmentIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func checkAssignmentIdentifier(identifier string) error {
	if !assignmentIdentifierPattern.MatchString(identifier) {
		return fmt.Errorf("invalid interface identifier %q", identifier)
	}
	return nil
}

func assignmentFromItem(row Item) Assignment {
	var identifier = row.Get("identifier")
	if identifier == "" {
		identifier = row.Uuid
	}
	var description = row.Get("descr")
	if description == "" {
		description = row.Display["descr"]
	}
	var typeText = func(field string) string {
		if text := row.Display[field]; text != "" {
			return text
		}
		return row.Get(field)
	}
	return Assignment{
		Identifier: identifier, Description: description, Device: row.Get("if"), DeviceText: row.Display["if"],
		Locked: row.Get("lock") == "1", Enabled: row.Get("enable") != "0", PendingAction: row.Get("pending_action"),
		Group: row.Get("optgroup"), IPv4Type: typeText("type4"), IPv6Type: typeText("type6"),
		IPv4: row.Get("ipaddr"), IPv6: row.Get("ipaddrv6"), Raw: row.Raw,
	}
}

// AssignmentSearch returns the assigned interfaces where any field contains searchPhrase ("" for all), in API
// order. Interfaces staged for removal are not listed
func (opn *InterfacesApi) AssignmentSearch(searchPhrase string) ([]Assignment, error) {
	var rows, err = coreapi.Search[Item](opn.OPNsense, opn.endpoint("assignment", "search_item"), searchPhrase)
	if err != nil {
		return nil, err
	}
	var assignments = make([]Assignment, 0, len(rows))
	for _, row := range rows {
		assignments = append(assignments, assignmentFromItem(row))
	}
	return assignments, nil
}

// Assignments returns the assigned interfaces in API order
func (opn *InterfacesApi) Assignments() ([]Assignment, error) {
	return opn.AssignmentSearch("")
}

// AssignmentGet returns the assignment with this identifier or a *NotFoundError (get_item answers an unknown
// identifier with [], the existence is checked by search)
func (opn *InterfacesApi) AssignmentGet(identifier string) (Assignment, error) {
	if err := checkAssignmentIdentifier(identifier); err != nil {
		return Assignment{}, err
	}
	var assignments, err = opn.Assignments()
	if err != nil {
		return Assignment{}, err
	}
	for _, assignment := range assignments {
		if assignment.Identifier == identifier {
			return assignment, nil
		}
	}
	return Assignment{}, &coreapi.NotFoundError{Name: "interface " + identifier}
}

// AssignmentDevices returns the devices OPNsense offers for an assignment (the choices of the if field, assigned
// devices included), Value is the device with its MAC address or VLAN details
func (opn *InterfacesApi) AssignmentDevices() ([]Option, error) {
	var container map[string]map[string]json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("assignment", "get_item"), nil, &container); err != nil {
		return nil, err
	}
	var record, found = container["interface"]
	if !found {
		return nil, errors.New("unexpected answer from assignment get_item: no interface record")
	}
	var options, err = parseOptions(record["if"])
	if err != nil {
		return nil, fmt.Errorf("unexpected device choices of assignment get_item: %w", err)
	}
	return options, nil
}

// AssignmentCreate assigns a device (change.Device is required) as the next free optN and returns that identifier.
// The new interface is enabled and locked unless change says otherwise, it has no address configuration. Like
// every assignment change it only takes effect with AssignmentApply
func (opn *InterfacesApi) AssignmentCreate(change AssignmentChange) (string, error) {
	if change.Device == nil || *change.Device == "" {
		return "", errors.New("a device is required to add an assignment")
	}
	var uuid, err = opn.Mutate(opn.endpoint("assignment", "add_item"), map[string]any{"interface": change.fields()})
	if err != nil {
		return "", err
	}
	// the identifier is given by the model when it is saved, look it up by the (unique) device
	var assignments, listErr = opn.Assignments()
	if listErr != nil {
		return "", listErr
	}
	for _, assignment := range assignments {
		if assignment.Device == *change.Device {
			return assignment.Identifier, nil
		}
	}
	if uuid != "" {
		return uuid, nil
	}
	return "", fmt.Errorf("OPNsense saved the assignment of %s but it is not listed", *change.Device)
}

// AssignmentUpdate changes the given fields of an existing assignment, the others are kept. A description or lock
// change is saved at once, a device change (relink) or an enable/disable is staged for AssignmentApply.
//
// OPNsense stages a change only when the record differs from config.xml: changing a staged value back to the
// applied one (disable, then enable again before apply) is ignored and the staged record stays. The result is read
// back, such an ignored change is an error
func (opn *InterfacesApi) AssignmentUpdate(identifier string, change AssignmentChange) error {
	if _, err := opn.AssignmentGet(identifier); err != nil {
		return err
	}
	var fields = change.fields()
	if len(fields) == 0 {
		return errors.New("nothing to change")
	}
	if _, err := opn.Mutate(opn.endpoint("assignment", "set_item")+"/"+url.PathEscape(identifier), map[string]any{"interface": fields}); err != nil {
		return err
	}
	var updated, err = opn.AssignmentGet(identifier)
	if err != nil {
		return err
	}
	var ignored []string
	if change.Device != nil && updated.Device != *change.Device {
		ignored = append(ignored, "device")
	}
	if change.Description != nil && updated.Description != *change.Description {
		// an empty description is shown as the upper case identifier
		if *change.Description != "" || !strings.EqualFold(updated.Description, identifier) {
			ignored = append(ignored, "description")
		}
	}
	if change.Locked != nil && updated.Locked != *change.Locked {
		ignored = append(ignored, "lock")
	}
	if change.Enabled != nil && updated.Enabled != *change.Enabled {
		ignored = append(ignored, "enabled state")
	}
	if len(ignored) > 0 {
		return fmt.Errorf("OPNsense kept the staged %s of %s: a change back to the applied value is ignored while a change of the interface is staged, apply the staged change first",
			strings.Join(ignored, " and "), identifier)
	}
	return nil
}

// AssignmentRemove stages the removal of an assignment. OPNsense refuses locked interfaces and interfaces that are
// members of a group, bridge, GRE or GIF tunnel (an error naming the reason). The apply of the removal deletes the
// interface from every firewall filter, NAT, NPT and 1:1 rule and deletes the rules left without an interface
func (opn *InterfacesApi) AssignmentRemove(identifier string) error {
	if err := checkAssignmentIdentifier(identifier); err != nil {
		return err
	}
	var _, err = opn.Mutate(opn.endpoint("assignment", "del_item")+"/"+url.PathEscape(identifier), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: "interface " + identifier, Err: err}
	}
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
		return fmt.Errorf("cannot remove interface %s: %s", identifier, httpErr.Message)
	}
	return err
}

// AssignmentPending tells whether assignment changes are staged and wait for AssignmentApply
func (opn *InterfacesApi) AssignmentPending() (bool, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("assignment", "pending"), nil, &container); err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(container.Status)) {
	case "pending":
		return true, nil
	case "ok":
		return false, nil
	}
	return false, fmt.Errorf("unexpected answer from assignment pending: status %q", container.Status)
}

// AssignmentApply applies every staged assignment change (POST reconfigure): the changed interfaces are reset and
// configured again (removed ones only reset), routing, IPsec, dynamic DNS, pfsync and proxy ARP of them are
// reconfigured, the DHCP and DNS services are reloaded, removed interfaces are deleted from all firewall and NAT
// rules (rules left without an interface are deleted) and the firewall rules are reloaded
func (opn *InterfacesApi) AssignmentApply() error {
	return opn.reconfigure("assignment", "assignment")
}
