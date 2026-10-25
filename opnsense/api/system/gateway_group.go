package system

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

// GatewayGroupTierCount is the number of priority tiers of a gateway group (item, item2 .. item5 in the API)
const GatewayGroupTierCount = 5

// The trigger levels of a gateway group: when a member counts as down
const (
	GatewayGroupTriggerDown          = "down"            // Member Down (the default)
	GatewayGroupTriggerLoss          = "downloss"        // Packet Loss
	GatewayGroupTriggerLatency       = "downlatency"     // High Latency
	GatewayGroupTriggerLossOrLatency = "downlosslatency" // "Packet Loss and High Latency": down on either
)

// The pool options of a gateway group: how connections are spread over the members of a tier
const (
	GatewayGroupPoolDefault          = ""
	GatewayGroupPoolRoundRobin       = "round-robin"
	GatewayGroupPoolRoundRobinSticky = "round-robin sticky-address"
)

const gatewayGroupNotFound = "gateway group %s"

// GatewayGroupTriggers and GatewayGroupPoolOptions are the values OPNsense accepts for Trigger and PoolOptions
var (
	GatewayGroupTriggers = []string{GatewayGroupTriggerDown, GatewayGroupTriggerLoss, GatewayGroupTriggerLatency,
		GatewayGroupTriggerLossOrLatency}
	GatewayGroupPoolOptions = []string{GatewayGroupPoolDefault, GatewayGroupPoolRoundRobin, GatewayGroupPoolRoundRobinSticky}
)

// gatewayGroupNamePattern is the mask of the OPNsense model
var gatewayGroupNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,32}$`)

// gatewayGroupMemberPattern is what a gateway name looks like (no commas or spaces, they would split or break the
// comma separated tier)
var gatewayGroupMemberPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)

// GatewayGroup is a group of System > Gateways > Group (api/routing/group_settings)
type GatewayGroup struct {
	Uuid string `json:"uuid"`
	// Name is unique, must not be the name of a gateway and can not be changed after creation
	Name string `json:"name"`
	// Tiers holds the gateway names of tier 1 (highest priority, API field item) to tier 5 (item5)
	Tiers [GatewayGroupTierCount][]string `json:"-"`
	// Trigger is one of GatewayGroupTriggers
	Trigger string `json:"trigger"`
	// PoolOptions is one of GatewayGroupPoolOptions
	PoolOptions string `json:"poolopts"`
	Description string `json:"descr"`
	// Status is the status of the members per tier (only set by search, read-only)
	Status [GatewayGroupTierCount][]GatewayGroupMemberStatus `json:"-"`
}

// GatewayGroupMemberStatus is the dpinger status of a member as reported by search.
// Members which are disabled or not active only have Name, Label ("danger") and StatusText
type GatewayGroupMemberStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	// Status is the dpinger status: none (= online), down, force_down, loss, delay, delay+loss
	Status     string `json:"status"`
	Loss       string `json:"loss"`
	Delay      string `json:"delay"`
	StdDev     string `json:"stddev"`
	Monitor    string `json:"monitor"`
	StatusText string `json:"status_translated"`
	// Label is the UI colour: success, warning, danger or default
	Label string `json:"label"`
}

// GatewayGroupCandidate is a gateway which can be a member of a group
type GatewayGroupCandidate struct {
	Name string
	// Description is "NAME - address" as OPNsense shows it
	Description string
}

// GatewayGroupPatch holds the fields to change, nil fields are kept. The name can not be changed
type GatewayGroupPatch struct {
	// Tiers[i] replaces tier i+1, an empty (non nil) slice clears it (except tier 1, which OPNsense never clears)
	Tiers       [GatewayGroupTierCount]*[]string
	Trigger     *string
	PoolOptions *string
	Description *string
}

// gatewayGroupTierField is the API field of tier index i (0 based): item, item2 .. item5
func gatewayGroupTierField(i int) string {
	if i == 0 {
		return "item"
	}
	return "item" + strconv.Itoa(i+1)
}

// gatewayGroupSplit splits a comma separated API list, without empty elements
func gatewayGroupSplit(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

func (g *GatewayGroup) UnmarshalJSON(data []byte) error {
	type plain GatewayGroup
	var fields struct {
		plain
		Item     string          `json:"item"`
		Item2    string          `json:"item2"`
		Item3    string          `json:"item3"`
		Item4    string          `json:"item4"`
		Item5    string          `json:"item5"`
		Gateways json.RawMessage `json:"gateways"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*g = GatewayGroup(fields.plain)
	for i, value := range []string{fields.Item, fields.Item2, fields.Item3, fields.Item4, fields.Item5} {
		g.Tiers[i] = gatewayGroupSplit(value)
	}
	return g.unmarshalStatus(fields.Gateways)
}

// unmarshalStatus reads the member status of search: an object keyed by tier number "1".."5" (a PHP array
// starting at 1), also accepted as a list starting with tier 1
func (g *GatewayGroup) unmarshalStatus(raw json.RawMessage) error {
	var trimmed = strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var tiers [][]GatewayGroupMemberStatus
		if err := json.Unmarshal(raw, &tiers); err != nil {
			return fmt.Errorf("unexpected gateway group status: %w", err)
		}
		for i, members := range tiers {
			if i < GatewayGroupTierCount {
				g.Status[i] = members
			}
		}
		return nil
	}
	var tiers map[string][]GatewayGroupMemberStatus
	if err := json.Unmarshal(raw, &tiers); err != nil {
		return fmt.Errorf("unexpected gateway group status: %w", err)
	}
	for key, members := range tiers {
		if tier, err := strconv.Atoi(key); err == nil && tier >= 1 && tier <= GatewayGroupTierCount {
			g.Status[tier-1] = members
		}
	}
	return nil
}

// Members returns all distinct member names in tier order
func (g GatewayGroup) Members() []string {
	var seen = map[string]bool{}
	var members []string
	for _, tier := range g.Tiers {
		for _, name := range tier {
			if !seen[name] {
				seen[name] = true
				members = append(members, name)
			}
		}
	}
	return members
}

// --- validation

// GatewayGroupValidateName checks the name like OPNsense: 1-32 characters of a-z, A-Z, 0-9, _ and -
func GatewayGroupValidateName(name string) error {
	if !gatewayGroupNamePattern.MatchString(name) {
		return fmt.Errorf("invalid gateway group name %q: 1-32 characters of a-z, A-Z, 0-9, _ and -", name)
	}
	return nil
}

// GatewayGroupValidateTier checks the gateway names of one tier: well-formed and not twice
func GatewayGroupValidateTier(members []string) error {
	var seen = map[string]bool{}
	for _, member := range members {
		if !gatewayGroupMemberPattern.MatchString(member) {
			return fmt.Errorf("invalid gateway name %q", member)
		}
		if seen[member] {
			return fmt.Errorf("gateway %s is given twice in the same tier", member)
		}
		seen[member] = true
	}
	return nil
}

func gatewayGroupValidateOption(what string, value string, allowed []string) error {
	for _, option := range allowed {
		if value == option {
			return nil
		}
	}
	return fmt.Errorf("invalid gateway group %s %q, valid are %q", what, value, allowed)
}

func gatewayGroupValidatePatch(patch GatewayGroupPatch) error {
	for i, tier := range patch.Tiers {
		if tier == nil {
			continue
		}
		if err := GatewayGroupValidateTier(*tier); err != nil {
			return fmt.Errorf("tier %d: %w", i+1, err)
		}
	}
	if patch.Trigger != nil {
		if err := gatewayGroupValidateOption("trigger", *patch.Trigger, GatewayGroupTriggers); err != nil {
			return err
		}
	}
	if patch.PoolOptions != nil {
		if err := gatewayGroupValidateOption("pool option", *patch.PoolOptions, GatewayGroupPoolOptions); err != nil {
			return err
		}
	}
	return nil
}

// --- API

func (opn *SystemApi) gatewayGroupEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("routing", "group_settings", method)
}

type gatewayGroupContainer struct {
	Group map[string]string `json:"gateway_group"`
}

// body renders the patch as the API fields
func (patch GatewayGroupPatch) body() map[string]string {
	var fields = map[string]string{}
	for i, tier := range patch.Tiers {
		if tier != nil {
			fields[gatewayGroupTierField(i)] = strings.Join(*tier, ",")
		}
	}
	if patch.Trigger != nil {
		fields["trigger"] = *patch.Trigger
	}
	if patch.PoolOptions != nil {
		fields["poolopts"] = *patch.PoolOptions
	}
	if patch.Description != nil {
		fields["descr"] = *patch.Description
	}
	return fields
}

// GatewayGroupSearch returns the groups where any column contains searchPhrase ("" for all) in API order,
// with the status of their members
func (opn *SystemApi) GatewayGroupSearch(searchPhrase string) ([]GatewayGroup, error) {
	return coreapi.Search[GatewayGroup](opn.OPNsense, opn.gatewayGroupEndpoint("search"), searchPhrase)
}

func (opn *SystemApi) GatewayGroupList() ([]GatewayGroup, error) {
	return opn.GatewayGroupSearch("")
}

// GatewayGroupGet returns the group with the given uuid or a *NotFoundError.
// (get/<uuid> answers an unknown uuid with [] and option maps instead of values, so the search is filtered)
func (opn *SystemApi) GatewayGroupGet(uuid string) (GatewayGroup, error) {
	if uuid == "" {
		return GatewayGroup{}, errors.New("cannot look up a gateway group without uuid")
	}
	var groups, err = opn.GatewayGroupList()
	if err != nil {
		return GatewayGroup{}, err
	}
	for _, group := range groups {
		if group.Uuid == uuid {
			return group, nil
		}
	}
	return GatewayGroup{}, &coreapi.NotFoundError{Name: fmt.Sprintf(gatewayGroupNotFound, uuid)}
}

// GatewayGroupGetByName returns the group with exactly this name (names are unique) or a *NotFoundError
func (opn *SystemApi) GatewayGroupGetByName(name string) (GatewayGroup, error) {
	if name == "" {
		return GatewayGroup{}, errors.New("cannot look up a gateway group by an empty name")
	}
	var groups, err = opn.GatewayGroupSearch(name)
	if err != nil {
		return GatewayGroup{}, err
	}
	for _, group := range groups {
		if group.Name == name {
			return group, nil
		}
	}
	return GatewayGroup{}, &coreapi.NotFoundError{Name: fmt.Sprintf(gatewayGroupNotFound, name)}
}

// GatewayGroupCreate adds a group from Name, Tiers, Trigger (default down), PoolOptions and Description and returns
// its uuid. At least one tier must have a member, the members must be gateways (see GatewayGroupCandidates)
func (opn *SystemApi) GatewayGroupCreate(group GatewayGroup) (string, error) {
	if err := GatewayGroupValidateName(group.Name); err != nil {
		return "", err
	}
	if group.Trigger == "" {
		group.Trigger = GatewayGroupTriggerDown
	}
	var patch = GatewayGroupPatch{Trigger: &group.Trigger, PoolOptions: &group.PoolOptions, Description: &group.Description}
	var hasMember bool
	for i := range group.Tiers {
		patch.Tiers[i] = &group.Tiers[i]
		hasMember = hasMember || len(group.Tiers[i]) > 0
	}
	if !hasMember {
		return "", errors.New("a gateway group needs at least one gateway in one of its tiers")
	}
	if err := gatewayGroupValidatePatch(patch); err != nil {
		return "", err
	}

	var fields = patch.body()
	fields["name"] = group.Name
	return opn.Mutate(opn.gatewayGroupEndpoint("add"), gatewayGroupContainer{Group: fields})
}

// GatewayGroupUpdate changes the non nil fields of patch, the others are kept. Returns *NotFoundError for an unknown
// uuid (checked first: set/<uuid> with complete fields would create a group). Refuses to clear tier 1 of a group
// which has members there (OPNsense silently ignores an empty item) and to leave the group without members
func (opn *SystemApi) GatewayGroupUpdate(uuid string, patch GatewayGroupPatch) error {
	if uuid == "" {
		return errors.New("cannot update a gateway group without uuid")
	}
	if err := gatewayGroupValidatePatch(patch); err != nil {
		return err
	}

	var existing, err = opn.GatewayGroupGet(uuid)
	if err != nil {
		return err
	}
	if patch.Tiers[0] != nil && len(*patch.Tiers[0]) == 0 && len(existing.Tiers[0]) > 0 {
		return fmt.Errorf("tier 1 of gateway group %s can not be cleared (OPNsense ignores an empty tier 1), "+
			"put other gateways into it or remove and add the group", existing.Name)
	}
	var hasMember bool
	for i, tier := range existing.Tiers {
		if patch.Tiers[i] != nil {
			tier = *patch.Tiers[i]
		}
		hasMember = hasMember || len(tier) > 0
	}
	if !hasMember {
		return fmt.Errorf("gateway group %s needs at least one gateway in one of its tiers", existing.Name)
	}

	var endpoint = fmt.Sprintf("%s/%s", opn.gatewayGroupEndpoint("set"), uuid)
	_, err = opn.Mutate(endpoint, gatewayGroupContainer{Group: patch.body()})
	return err
}

// GatewayGroupRemove deletes the group with the given uuid, returns *NotFoundError if it does not exist.
// A group in use (e.g. by a firewall rule) can not be removed, OPNsense answers with HTTP 500 naming the user
func (opn *SystemApi) GatewayGroupRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a gateway group by uuid %q", uuid)
	}
	var endpoint = fmt.Sprintf("%s/%s", opn.gatewayGroupEndpoint("del"), uuid)
	if _, err := opn.Mutate(endpoint, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf(gatewayGroupNotFound, uuid), Err: err}
		}
		var httpErr *coreapi.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
			return fmt.Errorf("cannot remove gateway group %s: %s", uuid, httpErr.Message)
		}
		return err
	}
	return nil
}

// GatewayGroupCandidates returns the gateways which can be group members, sorted by name. OPNsense caches this
// list: a gateway added in the last ~30 seconds may be missing, and is refused as member until it shows up
func (opn *SystemApi) GatewayGroupCandidates() ([]GatewayGroupCandidate, error) {
	var container struct {
		Group struct {
			Item map[string]struct {
				Value string `json:"value"`
			} `json:"item"`
		} `json:"gateway_group"`
	}
	if err := opn.DoJSON("GET", opn.gatewayGroupEndpoint("get"), nil, &container); err != nil {
		return nil, err
	}
	var candidates = make([]GatewayGroupCandidate, 0, len(container.Group.Item))
	for name, option := range container.Group.Item {
		if name != "" {
			candidates = append(candidates, GatewayGroupCandidate{Name: name, Description: option.Value})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Name < candidates[j].Name
	})
	return candidates, nil
}

// GatewayGroupReconfigure applies the gateway groups (configd "interface routes configure")
func (opn *SystemApi) GatewayGroupReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.gatewayGroupEndpoint("reconfigure"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("applying the gateway groups failed: status %q", result.Status)
	}
	return nil
}
