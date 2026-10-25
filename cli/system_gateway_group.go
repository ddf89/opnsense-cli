package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"sort"
	"strconv"
	"strings"
)

// /system/gateway/group: System > Gateways > Group. A group spreads or fails over traffic between gateways in up to
// five priority tiers: the members of the best tier which has a usable member are used (several in one tier share
// the load). Items are selected by the # of print, the uuid or the group name. Names can not be changed

const systemGatewayGroupItemHelp = "the #, uuid or name of the gateway group"

const systemGatewayGroupApplyHint = `Changes are only saved, run "/system/gateway/group apply" to apply them.`

// systemGatewayGroupTriggers maps the trigger argument to the API values
var systemGatewayGroupTriggers = [][2]string{
	{"member-down", system.GatewayGroupTriggerDown},
	{"packet-loss", system.GatewayGroupTriggerLoss},
	{"high-latency", system.GatewayGroupTriggerLatency},
	{"packet-loss-or-latency", system.GatewayGroupTriggerLossOrLatency},
}

// systemGatewayGroupPools maps the pool argument to the API values
var systemGatewayGroupPools = [][2]string{
	{"default", system.GatewayGroupPoolDefault},
	{"round-robin", system.GatewayGroupPoolRoundRobin},
	{"round-robin-sticky", system.GatewayGroupPoolRoundRobinSticky},
}

func systemGatewayGroupWords(mapping [][2]string) []string {
	var words = make([]string, len(mapping))
	for i, pair := range mapping {
		words[i] = pair[0]
	}
	return words
}

// systemGatewayGroupToApi maps an argument word to its API value (Values made sure it is one of them)
func systemGatewayGroupToApi(mapping [][2]string, word string) string {
	for _, pair := range mapping {
		if strings.EqualFold(pair[0], word) {
			return pair[1]
		}
	}
	return word
}

// systemGatewayGroupFromApi maps an API value to its argument word, unknown values are shown as they are
func systemGatewayGroupFromApi(mapping [][2]string, value string) string {
	for _, pair := range mapping {
		if pair[1] == value {
			return pair[0]
		}
	}
	return value
}

func systemGatewayGroupTierArg(tier int) string {
	return "tier" + strconv.Itoa(tier)
}

// systemGatewayGroupFieldArgs are the field arguments of add (with the OPNsense defaults) and set
func systemGatewayGroupFieldArgs(add bool) []Arg {
	var defaultValue = func(value string) string {
		if add {
			return value
		}
		return ""
	}
	var name = Arg{Name: "name", Help: "the group name, 1-32 characters of a-z, A-Z, 0-9, _ and -, not the name of a gateway",
		Required: add, Validate: systemGatewayGroupValidateName}
	if !add {
		name.Help = "the group name can not be changed, set fails for a different name"
	}
	var args = []Arg{name}
	for tier := 1; tier <= system.GatewayGroupTierCount; tier++ {
		var help = fmt.Sprintf("the gateways of tier %d (comma separated)", tier)
		if tier == 1 {
			help = "the gateways of tier 1, the highest priority (comma separated)"
		}
		args = append(args, Arg{Name: systemGatewayGroupTierArg(tier), Help: help, Type: List,
			Validate: systemGatewayGroupValidateTier, Complete: systemGatewayGroupGatewayNames})
	}
	return append(args,
		Arg{Name: "trigger", Help: "when a member counts as down (packet-loss-or-latency: on either)",
			Values: systemGatewayGroupWords(systemGatewayGroupTriggers), Default: defaultValue("member-down")},
		Arg{Name: "pool", Help: "how connections are spread over the members of a tier (sticky: a source stays on its gateway)",
			Values: systemGatewayGroupWords(systemGatewayGroupPools), Default: defaultValue("default")},
		Arg{Name: "description", Help: "any text"},
	)
}

func init() {
	var menu = Root.Menu("system/gateway/group")
	menu.Help = "gateway groups: failover and load balancing over gateways (System > Gateways > Group)"
	var item = Arg{Name: "item", Help: systemGatewayGroupItemHelp, Positional: true, Required: true, Complete: systemGatewayGroupItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the gateway groups with the status of their members",
			Long: `TIERS lists the gateways per tier ("1: GW_A, GW_B  2: GW_C"): the members of the best tier with a usable
member are used. STATUS counts the members by their current status, see show for the status of each member.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every gateway group", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only gateway groups where any field contains this text"},
			}, Run: systemGatewayGroupPrint},
		&Command{Name: "show", Help: "show all fields of one gateway group and the status of its members", Args: []Arg{item}, Run: systemGatewayGroupShow},
		&Command{Name: "add", Help: "add a gateway group, prints its uuid",
			Long: `At least one tier needs a gateway. If a group with this name exists already, add fails unless replace is
given, then that group is replaced completely (arguments not given are reset to their defaults; tier 1 can not
be cleared, OPNsense ignores that).
` + systemGatewayGroupApplyHint,
			Args:  append(systemGatewayGroupFieldArgs(true), Arg{Name: "replace", Help: "replace the group with the same name", Type: Bool}),
			Check: systemGatewayGroupCheckAdd, Run: systemGatewayGroupAdd},
		&Command{Name: "set", Help: "change fields of a gateway group, the others are kept",
			Long: `tierN= replaces the gateways of that tier, an empty value clears it. Tier 1 can not be cleared once it has
gateways (OPNsense ignores that) and the name can not be changed.
` + systemGatewayGroupApplyHint,
			Args:  append([]Arg{item}, systemGatewayGroupFieldArgs(false)...),
			Check: systemGatewayGroupCheckSet, Run: systemGatewayGroupSet},
		&Command{Name: "remove", Help: "remove a gateway group",
			Long: `A group used elsewhere, e.g. by a firewall rule, can not be removed.
` + systemGatewayGroupApplyHint,
			Args: []Arg{item}, Run: systemGatewayGroupRemove},
		&Command{Name: "apply", Help: "apply the gateway group changes: reconfigures the routes", Run: systemGatewayGroupApply},
	)
}

// --- validation

func systemGatewayGroupValidateName(value string) error {
	if err := system.GatewayGroupValidateName(value); err != nil {
		return fmt.Errorf("must be 1-32 characters of a-z, A-Z, 0-9, _ and -, got %q", value)
	}
	return nil
}

func systemGatewayGroupValidateTier(value string) error {
	return system.GatewayGroupValidateTier(splitList(value))
}

func systemGatewayGroupCheckAdd(args *Args) error {
	for tier := 1; tier <= system.GatewayGroupTierCount; tier++ {
		if len(args.List(systemGatewayGroupTierArg(tier))) > 0 {
			return nil
		}
	}
	return errors.New("a gateway group needs at least one gateway, give tier1= (or another tier)")
}

func systemGatewayGroupCheckSet(args *Args) error {
	for _, name := range args.Given() {
		if name != "item" {
			return nil
		}
	}
	return errors.New("nothing to change, give at least one field like tier1= or description= (type \"set ?\" for help)")
}

// systemGatewayGroupCheckMembers checks the gateways of the given tiers against the gateways OPNsense offers
func systemGatewayGroupCheckMembers(args *Args, candidates []system.GatewayGroupCandidate) error {
	var known = map[string]bool{}
	var names = make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		known[candidate.Name] = true
		names = append(names, candidate.Name)
	}
	for tier := 1; tier <= system.GatewayGroupTierCount; tier++ {
		var arg = systemGatewayGroupTierArg(tier)
		if !args.Has(arg) {
			continue
		}
		for _, member := range args.List(arg) {
			if !known[member] {
				return fmt.Errorf("%s: unknown gateway %q, the gateways are: %s (a gateway added in the last 30 seconds may not be offered yet)",
					arg, member, strings.Join(names, ", "))
			}
		}
	}
	return nil
}

// --- lookups

func systemGatewayGroupApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemGatewayGroupSearch returns the matching groups in API order, with the raw API objects for json output
func systemGatewayGroupSearch(api *system.SystemApi, searchPhrase string) ([]system.GatewayGroup, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("routing", "group_settings", "search")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var groups = make([]system.GatewayGroup, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &groups[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected gateway group from OPNsense: %w", err)
		}
	}
	return groups, rows, nil
}

func systemGatewayGroupUuid(group system.GatewayGroup) string {
	return group.Uuid
}

func systemGatewayGroupNames(group system.GatewayGroup) []string {
	return []string{group.Name}
}

// systemGatewayGroupSelect loads all groups and finds the one selector refers to
func systemGatewayGroupSelect(c *Context, api *system.SystemApi, selector string) (system.GatewayGroup, error) {
	var groups, _, err = systemGatewayGroupSearch(api, "")
	if err != nil {
		return system.GatewayGroup{}, err
	}
	return Select(c, selector, groups, systemGatewayGroupUuid, systemGatewayGroupNames)
}

// systemGatewayGroupItemNames completes item names from the API
func systemGatewayGroupItemNames(c *Context) []string {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return nil
	}
	var groups, _, searchErr = systemGatewayGroupSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

// systemGatewayGroupGatewayNames completes the tiers with the gateways which can be members
func systemGatewayGroupGatewayNames(c *Context) []string {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return nil
	}
	var candidates, listErr = api.GatewayGroupCandidates()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.Name)
	}
	return names
}

// --- output

// systemGatewayGroupTiers renders the tiers like "1: GW_A, GW_B  2: GW_C", empty tiers are left out
func systemGatewayGroupTiers(group system.GatewayGroup) string {
	var parts []string
	for i, tier := range group.Tiers {
		if len(tier) > 0 {
			parts = append(parts, fmt.Sprintf("%d: %s", i+1, strings.Join(tier, ", ")))
		}
	}
	return strings.Join(parts, "  ")
}

// systemGatewayGroupMemberStatus returns the status of every member once, in tier order
func systemGatewayGroupMemberStatus(group system.GatewayGroup) []system.GatewayGroupMemberStatus {
	var seen = map[string]bool{}
	var members []system.GatewayGroupMemberStatus
	for _, tier := range group.Status {
		for _, member := range tier {
			if !seen[member.Name] {
				seen[member.Name] = true
				members = append(members, member)
			}
		}
	}
	return members
}

func systemGatewayGroupStatusText(member system.GatewayGroupMemberStatus) string {
	if member.StatusText != "" {
		return member.StatusText
	}
	return member.Status
}

// systemGatewayGroupStatusSummary counts the members by status, like "1 Offline, 2 Online"
func systemGatewayGroupStatusSummary(group system.GatewayGroup) string {
	var counts = map[string]int{}
	for _, member := range systemGatewayGroupMemberStatus(group) {
		counts[systemGatewayGroupStatusText(member)]++
	}
	var parts = make([]string, 0, len(counts))
	for status, count := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", count, status))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// systemGatewayGroupMemberDetail renders the status of one member like "Online, 10.0.0.1, loss 0.0 %, delay 1 ms"
func systemGatewayGroupMemberDetail(member system.GatewayGroupMemberStatus) string {
	var parts = []string{systemGatewayGroupStatusText(member)}
	var add = func(label string, value string) {
		if value != "" && value != "~" {
			parts = append(parts, strings.TrimSpace(label+" "+value))
		}
	}
	add("", member.Address)
	add("loss", member.Loss)
	add("delay", member.Delay)
	add("stddev", member.StdDev)
	return strings.Join(parts, ", ")
}

// systemGatewayGroupFields are the fields of show and print detail, named like the arguments of add and set,
// followed by one "member NAME" field per member with its status
func systemGatewayGroupFields(group system.GatewayGroup) [][2]string {
	var fields = [][2]string{{"uuid", group.Uuid}, {"name", group.Name}}
	for i, tier := range group.Tiers {
		fields = append(fields, [2]string{systemGatewayGroupTierArg(i + 1), strings.Join(tier, ", ")})
	}
	fields = append(fields,
		[2]string{"trigger", systemGatewayGroupFromApi(systemGatewayGroupTriggers, group.Trigger)},
		[2]string{"pool", systemGatewayGroupFromApi(systemGatewayGroupPools, group.PoolOptions)},
		[2]string{"description", group.Description},
	)
	for _, member := range systemGatewayGroupMemberStatus(group) {
		fields = append(fields, [2]string{"member " + member.Name, systemGatewayGroupMemberDetail(member)})
	}
	return fields
}

func systemGatewayGroupPrint(c *Context, args *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	var groups, raw, searchErr = systemGatewayGroupSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(groups))
	for i, group := range groups {
		uuids[i] = group.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(groups))
		for i, group := range groups {
			items[i] = systemGatewayGroupFields(group)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(groups))
		for i, group := range groups {
			rows[i] = []string{group.Name, systemGatewayGroupTiers(group),
				systemGatewayGroupFromApi(systemGatewayGroupTriggers, group.Trigger),
				systemGatewayGroupFromApi(systemGatewayGroupPools, group.PoolOptions),
				systemGatewayGroupStatusSummary(group), group.Description}
		}
		c.Items([]string{"NAME", "TIERS", "TRIGGER", "POOL", "STATUS", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func systemGatewayGroupShow(c *Context, args *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGatewayGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemGatewayGroupFields(group))
	return nil
}

// --- changes

// systemGatewayGroupPatch returns the given field arguments, with all also the defaults of the arguments not given
func systemGatewayGroupPatch(args *Args, all bool) system.GatewayGroupPatch {
	var patch system.GatewayGroupPatch
	for i := range patch.Tiers {
		var arg = systemGatewayGroupTierArg(i + 1)
		if all || args.Has(arg) {
			var members = args.List(arg)
			patch.Tiers[i] = &members
		}
	}
	if all || args.Has("trigger") {
		var trigger = systemGatewayGroupToApi(systemGatewayGroupTriggers, args.String("trigger"))
		patch.Trigger = &trigger
	}
	if all || args.Has("pool") {
		var pool = systemGatewayGroupToApi(systemGatewayGroupPools, args.String("pool"))
		patch.PoolOptions = &pool
	}
	if all || args.Has("description") {
		var description = args.String("description")
		patch.Description = &description
	}
	return patch
}

func systemGatewayGroupAdd(c *Context, args *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var candidates, candidatesErr = api.GatewayGroupCandidates()
	if candidatesErr != nil {
		return candidatesErr
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate.Name, name) {
			return fmt.Errorf("%s is the name of a gateway, a gateway group needs another name", candidate.Name)
		}
	}
	if err := systemGatewayGroupCheckMembers(args, candidates); err != nil {
		return err
	}

	var existing, findErr = api.GatewayGroupGetByName(name)
	if findErr != nil && !coreapi.IsNotFound(findErr) {
		return findErr
	}
	var patch = systemGatewayGroupPatch(args, true)
	if findErr != nil {
		var group = system.GatewayGroup{Name: name, Trigger: *patch.Trigger, PoolOptions: *patch.PoolOptions, Description: *patch.Description}
		for i, tier := range patch.Tiers {
			group.Tiers[i] = *tier
		}
		var uuid, createErr = api.GatewayGroupCreate(group)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	}
	if !args.Bool("replace") {
		return fmt.Errorf("a gateway group named %s exists already (%s), change it with set or replace it with add ... replace",
			existing.Name, existing.Uuid)
	}
	if err := api.GatewayGroupUpdate(existing.Uuid, patch); err != nil {
		return err
	}
	c.Infof("replaced the existing gateway group %s", existing.Name)
	c.Println(existing.Uuid)
	return nil
}

func systemGatewayGroupSet(c *Context, args *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGatewayGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if args.Has("name") && args.String("name") != group.Name {
		return fmt.Errorf("gateway group %s can not be renamed (OPNsense does not allow it), add a group named %s and remove this one",
			group.Name, args.String("name"))
	}

	var patch = systemGatewayGroupPatch(args, false)
	for _, tier := range patch.Tiers {
		if tier != nil {
			var candidates, candidatesErr = api.GatewayGroupCandidates()
			if candidatesErr != nil {
				return candidatesErr
			}
			if err := systemGatewayGroupCheckMembers(args, candidates); err != nil {
				return err
			}
			break
		}
	}
	if patch == (system.GatewayGroupPatch{}) {
		return nil // only the unchanged name was given
	}
	return api.GatewayGroupUpdate(group.Uuid, patch)
}

func systemGatewayGroupRemove(c *Context, args *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	var group, selectErr = systemGatewayGroupSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.GatewayGroupRemove(group.Uuid)
}

func systemGatewayGroupApply(c *Context, _ *Args) error {
	var api, err = systemGatewayGroupApi(c)
	if err != nil {
		return err
	}
	return api.GatewayGroupReconfigure()
}
