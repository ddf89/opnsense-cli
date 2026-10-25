package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Privilege is an access privilege of System > Access > Privileges (api/auth/priv), e.g. page-all ("All pages").
// The list is fixed by OPNsense and its plugins, privileges are granted to users and groups
type Privilege struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	// Match are the URL patterns the privilege gives access to
	Match []string `json:"-"`
	// Users and Groups are the names of the users and groups the privilege is granted to directly
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
	// Raw is the search row as OPNsense returned it
	Raw json.RawMessage `json:"-"`
}

// PrivilegeHolders are the users and groups a privilege can be granted to (Key uuid, Value name) and whether it is
type PrivilegeHolders struct {
	Users  []Option
	Groups []Option
}

func (p *Privilege) UnmarshalJSON(data []byte) error {
	var raw struct {
		Id     string   `json:"id"`
		Name   string   `json:"name"`
		Match  string   `json:"match"`
		Users  []string `json:"users"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var match = make([]string, 0)
	for _, line := range strings.Split(raw.Match, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			match = append(match, line)
		}
	}
	*p = Privilege{Id: raw.Id, Name: raw.Name, Match: match, Users: raw.Users, Groups: raw.Groups,
		Raw: append(json.RawMessage(nil), data...)}
	if p.Users == nil {
		p.Users = []string{}
	}
	if p.Groups == nil {
		p.Groups = []string{}
	}
	return nil
}

// PrivilegeList returns all privileges in the order of OPNsense (search ignores ?searchPhrase=, filter the result)
func (opn *AuthApi) PrivilegeList() ([]Privilege, error) {
	return searchAll[Privilege](opn, opn.endpoint("priv", "search"))
}

// PrivilegeGet returns the privilege with this id or a *NotFoundError (get_item answers any id, so the list is used)
func (opn *AuthApi) PrivilegeGet(id string) (Privilege, error) {
	if id == "" {
		return Privilege{}, errors.New("cannot look up a privilege without id")
	}
	var privileges, err = opn.PrivilegeList()
	if err != nil {
		return Privilege{}, err
	}
	for _, privilege := range privileges {
		if privilege.Id == id {
			return privilege, nil
		}
	}
	return Privilege{}, &coreapi.NotFoundError{Name: fmt.Sprintf("privilege %q", id)}
}

// PrivilegeHoldersGet returns all users and groups with the flag whether the privilege is granted to them
func (opn *AuthApi) PrivilegeHoldersGet(id string) (PrivilegeHolders, error) {
	if id == "" || strings.ContainsAny(id, "/?#%") {
		return PrivilegeHolders{}, fmt.Errorf("invalid privilege id %q", id)
	}
	var answer struct {
		Priv map[string]json.RawMessage `json:"priv"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("priv", "get_item")+"/"+id, nil, &answer); err != nil {
		return PrivilegeHolders{}, err
	}
	if answer.Priv == nil {
		return PrivilegeHolders{}, fmt.Errorf("unexpected answer from priv/get_item/%s: no priv", id)
	}
	var holders PrivilegeHolders
	var err error
	if holders.Users, err = decodeOptions(answer.Priv["users"]); err != nil {
		return PrivilegeHolders{}, fmt.Errorf("unexpected users from priv/get_item/%s: %w", id, err)
	}
	if holders.Groups, err = decodeOptions(answer.Priv["groups"]); err != nil {
		return PrivilegeHolders{}, fmt.Errorf("unexpected groups from priv/get_item/%s: %w", id, err)
	}
	return holders, nil
}

// PrivilegeGrant grants the privilege to the users and groups (uuids), the other holders are kept
func (opn *AuthApi) PrivilegeGrant(id string, userUuids []string, groupUuids []string) error {
	return opn.privilegeChange(id, userUuids, groupUuids, true)
}

// PrivilegeRevoke revokes the privilege from the users and groups (uuids), the other holders are kept
func (opn *AuthApi) PrivilegeRevoke(id string, userUuids []string, groupUuids []string) error {
	return opn.privilegeChange(id, userUuids, groupUuids, false)
}

// privilegeChange reads the holders, changes the given ones and writes the complete holder lists back: set_item
// replaces both lists. The privilege id is checked first, set_item writes unknown ids to the users and groups
// without validation
func (opn *AuthApi) privilegeChange(id string, userUuids []string, groupUuids []string, grant bool) error {
	if len(userUuids) == 0 && len(groupUuids) == 0 {
		return errors.New("no users or groups given")
	}
	if _, err := opn.PrivilegeGet(id); err != nil {
		return err
	}
	var holders, err = opn.PrivilegeHoldersGet(id)
	if err != nil {
		return err
	}
	var users, usersErr = privilegeApply(holders.Users, userUuids, grant, "user")
	if usersErr != nil {
		return usersErr
	}
	var groups, groupsErr = privilegeApply(holders.Groups, groupUuids, grant, "group")
	if groupsErr != nil {
		return groupsErr
	}
	var body = map[string]any{"priv": map[string]string{"users": strings.Join(users, ","), "groups": strings.Join(groups, ",")}}
	_, err = opn.mutate(opn.endpoint("priv", "set_item")+"/"+id, "privilege "+id, body)
	return err
}

// privilegeApply returns the selected keys of options after granting or revoking changes (keys of options)
func privilegeApply(options []Option, changes []string, grant bool, what string) ([]string, error) {
	for _, change := range changes {
		if !slices.ContainsFunc(options, func(option Option) bool { return option.Key == change }) {
			return nil, &coreapi.NotFoundError{Name: what + " " + change}
		}
	}
	var result = make([]string, 0, len(options))
	for _, option := range options {
		var selected = option.Selected
		if slices.Contains(changes, option.Key) {
			selected = grant
		}
		if selected {
			result = append(result, option.Key)
		}
	}
	return result, nil
}
