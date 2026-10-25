package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Group is an interface group of Firewall > Groups (api/firewall/group). Rules on a group apply to all members.
//
// OPNsense also lists the built-in groups enc0, openvpn and wireguard, their uuid is their name (no dashes) and they
// can neither be changed nor removed (see IsBuiltin)
type Group struct {
	Uuid string
	// Name is the group (and pf interface group) name, see GroupValidateName. Renaming a group renames it in all rules
	Name string
	// Members are interface identifiers like lan, wan or opt1 (see GroupInterfaces)
	Members []string
	// MembersText are the descriptions of the members as OPNsense shows them, e.g. "LAN, WAN" (read-only)
	MembersText string
	// NoGroup keeps the members out of a combined entry in the interfaces menu
	NoGroup bool
	// Sequence sorts the groups (0-9999)
	Sequence    int
	Description string
}

// GroupInterface is an interface which can be a group member
type GroupInterface struct {
	Name        string // identifier like lan or opt1
	Description string // like LAN
}

// GroupPatch holds the fields to change, nil fields are kept
type GroupPatch struct {
	Name        *string
	Members     *[]string
	NoGroup     *bool
	Sequence    *int
	Description *string
}

const (
	groupSequenceMax = 9999
	groupNameMax     = 15
)

var groupNamePattern = regexp.MustCompile(`^[a-zA-Z_]([a-zA-Z0-9_]*[a-zA-Z_])?$`)

// IsBuiltin is true for the built-in groups (enc0, openvpn, wireguard) which can not be changed
func (g Group) IsBuiltin() bool {
	return GroupIsBuiltinUuid(g.Uuid)
}

// GroupIsBuiltinUuid tells whether uuid is the key of a built-in group (its name instead of a uuid)
func GroupIsBuiltinUuid(uuid string) bool {
	return uuid != "" && !strings.Contains(uuid, "-")
}

func (g *Group) UnmarshalJSON(data []byte) error {
	var raw struct {
		Uuid        string `json:"uuid"`
		Ifname      string `json:"ifname"`
		Members     string `json:"members"`
		MembersText string `json:"%members"`
		NoGroup     string `json:"nogroup"`
		Sequence    string `json:"sequence"`
		Descr       string `json:"descr"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var sequence int
	if raw.Sequence != "" {
		var err error
		if sequence, err = strconv.Atoi(raw.Sequence); err != nil {
			return fmt.Errorf("unexpected sequence %q of group %s", raw.Sequence, raw.Ifname)
		}
	}
	*g = Group{Uuid: raw.Uuid, Name: raw.Ifname, Members: groupSplitList(raw.Members), MembersText: raw.MembersText,
		NoGroup: raw.NoGroup == "1", Sequence: sequence, Description: raw.Descr}
	return nil
}

// groupSplitList splits a comma separated API list, without empty elements
func groupSplitList(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

func groupBit(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// GroupValidateName checks a group name like OPNsense: 1-15 letters, digits and underscores, not starting or
// ending with a digit
func GroupValidateName(name string) error {
	if len(name) > groupNameMax || !groupNamePattern.MatchString(name) {
		return fmt.Errorf("invalid group name %q: 1-%d letters, digits and underscores, not starting or ending with a digit",
			name, groupNameMax)
	}
	return nil
}

func groupValidatePatch(patch GroupPatch) error {
	if patch.Name != nil {
		if err := GroupValidateName(*patch.Name); err != nil {
			return err
		}
	}
	if patch.Members != nil {
		if len(*patch.Members) == 0 {
			return errors.New("a group needs at least one member interface")
		}
		var seen = map[string]bool{}
		for _, member := range *patch.Members {
			if member == "" || strings.ContainsAny(member, ", ") {
				return fmt.Errorf("invalid member interface %q", member)
			}
			if seen[member] {
				return fmt.Errorf("member interface %s is given twice", member)
			}
			seen[member] = true
		}
	}
	if patch.Sequence != nil && (*patch.Sequence < 0 || *patch.Sequence > groupSequenceMax) {
		return fmt.Errorf("invalid group sequence %d: must be 0-%d", *patch.Sequence, groupSequenceMax)
	}
	return nil
}

// --- API

type groupContainer struct {
	Group map[string]string `json:"group"`
}

func (patch GroupPatch) body() map[string]string {
	var fields = map[string]string{}
	if patch.Name != nil {
		fields["ifname"] = *patch.Name
	}
	if patch.Members != nil {
		fields["members"] = strings.Join(*patch.Members, ",")
	}
	if patch.NoGroup != nil {
		fields["nogroup"] = groupBit(*patch.NoGroup)
	}
	if patch.Sequence != nil {
		fields["sequence"] = strconv.Itoa(*patch.Sequence)
	}
	if patch.Description != nil {
		fields["descr"] = *patch.Description
	}
	return fields
}

func groupNotFound(what string) error {
	return &coreapi.NotFoundError{Name: "group " + what}
}

// GroupSearch returns the groups (including the built-in ones) where any column contains searchPhrase ("" for all),
// sorted by name like OPNsense does
func (opn *FirewallApi) GroupSearch(searchPhrase string) ([]Group, error) {
	return coreapi.Search[Group](opn.OPNsense, opn.endpoint("firewall", "group", "search_item"), searchPhrase)
}

func (opn *FirewallApi) GroupList() ([]Group, error) {
	return opn.GroupSearch("")
}

// GroupGet returns the group with the given uuid (or built-in key) or a *NotFoundError.
// (get_item/<uuid> answers an unknown uuid with [] and members as option map, so the search is filtered)
func (opn *FirewallApi) GroupGet(uuid string) (Group, error) {
	if uuid == "" {
		return Group{}, errors.New("cannot look up a group without uuid")
	}
	var groups, err = opn.GroupList()
	if err != nil {
		return Group{}, err
	}
	for _, group := range groups {
		if group.Uuid == uuid {
			return group, nil
		}
	}
	return Group{}, groupNotFound(uuid)
}

// GroupGetByName returns the group with exactly this name (names are unique) or a *NotFoundError
func (opn *FirewallApi) GroupGetByName(name string) (Group, error) {
	if name == "" {
		return Group{}, errors.New("cannot look up a group by an empty name")
	}
	var groups, err = opn.GroupSearch(name)
	if err != nil {
		return Group{}, err
	}
	for _, group := range groups {
		if group.Name == name {
			return group, nil
		}
	}
	return Group{}, groupNotFound(name)
}

// GroupInterfaces returns the interfaces which can be group members, sorted by identifier
func (opn *FirewallApi) GroupInterfaces() ([]GroupInterface, error) {
	var container struct {
		Group struct {
			Members map[string]struct {
				Value string `json:"value"`
			} `json:"members"`
		} `json:"group"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("firewall", "group", "get_item"), nil, &container); err != nil {
		return nil, err
	}
	var interfaces = make([]GroupInterface, 0, len(container.Group.Members))
	for name, option := range container.Group.Members {
		if name != "" {
			interfaces = append(interfaces, GroupInterface{Name: name, Description: option.Value})
		}
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})
	return interfaces, nil
}

// groupInterfaceNamePattern matches interface identifiers OPNsense assigns (lan, wan, optN, lo0, ...), refused
// even when the interface is not offered as a member right now
var groupInterfaceNamePattern = regexp.MustCompile(`(?i)^(lan|wan|opt[0-9]+|lo[0-9]*|enc[0-9]+|pflog[0-9]+|pfsync[0-9]+)$`)

// groupCheckNameIsNoInterface refuses a group name which is an interface identifier (like lan): OPNsense means to
// refuse it but its check is broken. Registering such a group overwrites the interface's own configuration (seen
// on 26.7: <interfaces><lan> became a group placeholder and LAN lost its device), and it can then not be removed
// while rules use the interface
func (opn *FirewallApi) groupCheckNameIsNoInterface(name string) error {
	if groupInterfaceNamePattern.MatchString(name) {
		return fmt.Errorf("%s is the name of an interface, a group needs another name", strings.ToLower(name))
	}
	var interfaces, err = opn.GroupInterfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if strings.EqualFold(iface.Name, name) {
			return fmt.Errorf("%s is the name of an interface, a group needs another name", iface.Name)
		}
	}
	return nil
}

// GroupCreate adds a group from Name, Members, NoGroup, Sequence and Description and returns its uuid
func (opn *FirewallApi) GroupCreate(group Group) (string, error) {
	var patch = GroupPatch{Name: &group.Name, Members: &group.Members, NoGroup: &group.NoGroup, Sequence: &group.Sequence,
		Description: &group.Description}
	if err := groupValidatePatch(patch); err != nil {
		return "", err
	}
	if err := opn.groupCheckNameIsNoInterface(group.Name); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("firewall", "group", "add_item"), groupContainer{Group: patch.body()})
}

// GroupUpdate changes the non nil fields of patch, the others are kept. A new Name renames the group in all rules
// too. Returns *NotFoundError for an unknown uuid (checked first: set_item with complete fields would create a group)
// and refuses built-in groups. The current name is always sent: set_item treats a missing name as a rename to ""
// and would remove the group from every rule using it
func (opn *FirewallApi) GroupUpdate(uuid string, patch GroupPatch) error {
	if uuid == "" {
		return errors.New("cannot update a group without uuid")
	}
	if GroupIsBuiltinUuid(uuid) {
		return fmt.Errorf("%s is a built-in group and can not be changed", uuid)
	}
	if err := groupValidatePatch(patch); err != nil {
		return err
	}
	var existing, err = opn.GroupGet(uuid)
	if err != nil {
		return err
	}
	if patch.Name == nil {
		patch.Name = &existing.Name
	} else if *patch.Name != existing.Name {
		if err := opn.groupCheckNameIsNoInterface(*patch.Name); err != nil {
			return err
		}
	}
	_, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("firewall", "group", "set_item"), uuid), groupContainer{Group: patch.body()})
	return err
}

// groupInUseError turns the HTTP 500 of a refused delete (a UserException) into a readable error
func groupInUseError(what string, err error) error {
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
		return fmt.Errorf("cannot remove %s: %s", what, strings.Join(strings.Fields(httpErr.Message), " "))
	}
	return err
}

// GroupRemove deletes the group with the given uuid. Returns *NotFoundError if it does not exist, refuses built-in
// groups, and a group used by rules can not be removed (the error names the rules)
func (opn *FirewallApi) GroupRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a group by uuid %q", uuid)
	}
	if GroupIsBuiltinUuid(uuid) {
		return fmt.Errorf("%s is a built-in group and can not be removed", uuid)
	}
	if _, err := opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("firewall", "group", "del_item"), uuid), nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: "group " + uuid, Err: err}
		}
		return groupInUseError("group "+uuid, err)
	}
	return nil
}

// GroupReconfigure applies the groups: registers the interface groups and reloads the filter
func (opn *FirewallApi) GroupReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("firewall", "group", "reconfigure"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("applying the groups failed: status %q", result.Status)
	}
	return nil
}
