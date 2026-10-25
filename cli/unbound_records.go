package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"opnsense-cli/opnsense/api/unbound"
	"strings"
)

// /unbound/acl, /unbound/forward, /unbound/blocklist, /unbound/host-alias: access lists, query forwarding and DNS
// over TLS servers, DNSBL policies and host override aliases of Unbound

func unboundDisabledField() dnsField {
	return dnsField{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the entry, but don't use it"}, Api: "enabled", Kind: dnsDisabled, Reset: "1"}
}

func unboundDescriptionField() dnsField {
	return dnsField{Arg: Arg{Name: "description", Help: "any text"}, Api: "description"}
}

// unboundRecord builds the search / create / update / remove functions of an unbound record type
func unboundRecord[T any](m *dnsRecordMenu, method string,
	create func(api *unbound.UnboundApi, record T) (string, error),
	update func(api *unbound.UnboundApi, uuid string, patch unbound.Patch) error,
	remove func(api *unbound.UnboundApi, uuid string) error) *dnsRecordMenu {
	if m.ApplyHint == "" {
		m.ApplyHint = unboundApplyHint
	}
	m.Search = func(c *Context, searchPhrase string) ([]json.RawMessage, error) {
		return dnsSearchRaw(c, "unbound", "settings", "search_"+method, searchPhrase)
	}
	m.Create = func(c *Context, patch map[string]string) (string, error) {
		var api, err = unboundApi(c)
		if err != nil {
			return "", err
		}
		var record T
		if err := dnsDecodeStrict(patch, &record); err != nil {
			return "", err
		}
		return create(api, record)
	}
	if update != nil {
		m.Update = func(c *Context, row dnsRow, patch map[string]string) error {
			var api, err = unboundApi(c)
			if err != nil {
				return err
			}
			return update(api, row.uuid(), patch)
		}
	}
	m.Remove = func(c *Context, uuid string) error {
		var api, err = unboundApi(c)
		if err != nil {
			return err
		}
		return remove(api, uuid)
	}
	return m
}

// unboundValidateNetworksOrIPs accepts a comma separated list of networks (CIDR) or addresses
func unboundValidateNetworksOrIPs(value string) error {
	for _, element := range splitList(value) {
		if net.ParseIP(element) == nil {
			if _, _, err := net.ParseCIDR(element); err != nil {
				return fmt.Errorf("must be addresses or networks like 192.0.2.0/24, got %q", element)
			}
		}
	}
	return nil
}

// unboundHostOverrideRef resolves host overrides by FQDN (host.domain or host.domain/RR) to their uuid
var unboundHostOverrideRef = &dnsRef{What: "host override", Load: func(c *Context) ([]dnsRefItem, error) {
	var api, err = unboundApi(c)
	if err != nil {
		return nil, err
	}
	var overrides, listErr = api.HostOverrideList()
	if listErr != nil {
		return nil, listErr
	}
	var items = make([]dnsRefItem, len(overrides))
	for i, override := range overrides {
		items[i] = dnsRefItem{Uuid: override.Uuid, Names: unboundHostOverrideItemNames(override)}
	}
	return items, nil
}}

var unboundAclActions = []string{"allow", "deny", "refuse", "allow_snoop", "deny_non_local", "refuse_non_local"}

func init() {
	unboundRecord(&dnsRecordMenu{
		Path:     "unbound/acl",
		Help:     "access lists: which networks may query Unbound",
		What:     "access list",
		ItemHelp: "the #, uuid or name of the access list",
		AddLong: `Networks no access list matches get the default action (see default-action), localhost and the
networks of the interfaces Unbound listens on are allowed automatically.

  add name=guests action=refuse networks=192.168.20.0/24`,
		Fields: []dnsField{
			unboundDisabledField(),
			{Arg: Arg{Name: "name", Help: "the name", Required: true, Validate: dnsNotEmpty}, Api: "name"},
			{Arg: Arg{Name: "action", Help: "allow (default), deny, refuse, allow_snoop, deny_non_local or refuse_non_local", Values: unboundAclActions},
				Api: "action", Reset: "allow"},
			{Arg: Arg{Name: "networks", Type: List, Help: "networks in CIDR notation like 192.168.20.0/24,fd00:20::/64", Required: true, Validate: dnsValidateNetworks},
				Api: "networks", Kind: dnsList},
			unboundDescriptionField(),
		},
		Columns: []string{"disabled", "name", "action", "networks", "description"},
		Names:   func(row dnsRow) []string { return []string{row["name"]} },
		Key:     func(row dnsRow) string { return row["name"] },
		KeyHelp: "the same name",
	}, "acl", (*unbound.UnboundApi).AclCreate, (*unbound.UnboundApi).AclUpdate, (*unbound.UnboundApi).AclRemove).register(
		&Command{Name: "default-action", Help: "show or change the action for networks no access list matches",
			Long: `Without argument it shows the default action, "default-action refuse" changes it. Make sure your own
network is allowed before you deny everything else.
` + unboundApplyHint,
			Args: []Arg{{Name: "action", Positional: true, Help: "the new default action", Values: []string{"allow", "deny", "refuse"}}},
			Run:  unboundAclDefaultAction},
	)

	var forwardMenu = unboundRecord(&dnsRecordMenu{
		Path:     "unbound/forward",
		Help:     "query forwarding: DNS servers (plain or DNS over TLS) Unbound forwards queries to",
		What:     "forward",
		ItemHelp: "the #, uuid, server address, domain or description of the entry",
		AddLong: `Queries for domain (and its subdomains, all queries without domain) are forwarded to server instead of
being resolved by Unbound. type=dot uses DNS over TLS (port 853 unless port= is given) and verifies the server
certificate against verify= when given. Several entries for the same domain are used together.

  add domain=corp.example server=10.0.0.53
  add type=dot server=9.9.9.9 verify=dns.quad9.net`,
		SetLong: `type= converts the entry between plain forwarding and DNS over TLS.`,
		Fields: []dnsField{
			unboundDisabledField(),
			{Arg: Arg{Name: "type", Help: "forward (plain DNS) or dot (DNS over TLS)", Values: []string{"forward", "dot"}, Default: "forward"}, Api: "type", Reset: "forward"},
			{Arg: Arg{Name: "domain", Help: "the domain to forward, empty for all queries"}, Api: "domain"},
			{Arg: Arg{Name: "server", Help: "address of the DNS server", Required: true, Validate: ValidateIP}, Api: "server"},
			{Arg: Arg{Name: "port", Type: Int, Help: "port of the server, empty for 53 (853 for dot)", Validate: ValidatePort}, Api: "port"},
			{Arg: Arg{Name: "verify", Help: "name to verify the server's TLS certificate against (dot)"}, Api: "verify"},
			{Arg: Arg{Name: "forward-tcp-upstream", Type: Bool, Help: "forward over TCP only"}, Api: "forward_tcp_upstream", Kind: dnsBool, Reset: "0"},
			{Arg: Arg{Name: "forward-first", Type: Bool, Help: "resolve the query itself when the server fails"}, Api: "forward_first", Kind: dnsBool, Reset: "0"},
			unboundDescriptionField(),
		},
		Columns: []string{"disabled", "type", "domain", "server", "port", "verify", "description"},
		Names:   func(row dnsRow) []string { return []string{row["server"], row["domain"], row["description"]} },
		Key: func(row dnsRow) string {
			return strings.Join([]string{row["type"], strings.TrimSuffix(row["domain"], "."), dnsmasqCanonicalIP(row["server"]), row["port"]}, " ")
		},
		KeyHelp: "the same type, domain, server and port",
		Prepare: func(_ *Context, row dnsRow, patch map[string]string) error {
			if _, given := patch["type"]; !given {
				patch["type"] = "forward"
				if row != nil && row["type"] != "" {
					patch["type"] = row["type"]
				}
			}
			return nil
		},
		Update: func(c *Context, row dnsRow, patch map[string]string) error {
			var api, err = unboundApi(c)
			if err != nil {
				return err
			}
			// enable / disable send only the enabled field, without the type Prepare adds for add and set
			var forwardType = patch["type"]
			if forwardType == "" {
				forwardType = row["type"]
			}
			return api.ForwardUpdate(row.uuid(), forwardType, patch)
		},
	}, "forward", (*unbound.UnboundApi).ForwardCreate, nil, (*unbound.UnboundApi).ForwardRemove)
	// search_forward only returns the plain forwards, search_dot the DNS over TLS ones: list both
	forwardMenu.Search = unboundForwardSearch
	forwardMenu.register(
		&Command{Name: "system-nameservers", Help: "show or change whether queries go to the system's DNS servers",
			Long: `Shows the system's DNS servers (System > Settings > General, DHCP / PPP on WAN) and whether Unbound
forwards the queries without a forward entry to them instead of resolving them itself. use=yes / use=no changes it.
` + unboundApplyHint,
			Args: []Arg{{Name: "use", Type: Bool, Help: "forward to the system's DNS servers"}},
			Run:  unboundForwardSystemNameservers},
	)
	unboundRecord(&dnsRecordMenu{
		Path:      "unbound/blocklist",
		Help:      "DNS blocklists (DNSBL): policies of lists blocked for source networks",
		What:      "blocklist",
		ItemHelp:  "the #, uuid or description of the blocklist policy",
		ApplyHint: `Changes are only saved, run "/unbound/blocklist update" to download and load the lists.`,
		AddLong: `A policy blocks the domains of the predefined lists type= (see types), of the lists at the URLs lists=,
blocklists= (exact names or regular expressions) and wildcards= (with all subdomains), except allowlists=, for the
clients in source-nets= (all when empty). Blocked names are answered with address= (0.0.0.0) or NXDOMAIN.

  add description=ads type=ag,hgz002 allowlists=example.com
  add description=kids type=hgz019,oisd2 source-nets=192.168.30.0/24 nxdomain`,
		Fields: []dnsField{
			unboundDisabledField(),
			{Arg: Arg{Name: "description", Help: "the name of the policy (required, unique)", Required: true, Validate: dnsNotEmpty}, Api: "description"},
			{Arg: Arg{Name: "type", Type: List, Help: "predefined lists by key like ag,hgz002, see types", Complete: unboundBlocklistTypeKeys},
				Api: "type", Kind: dnsList, Describe: true, ToApi: unboundBlocklistTypeValue},
			{Arg: Arg{Name: "lists", Type: List, Help: "URLs of additional blocklists"}, Api: "lists", Kind: dnsList},
			{Arg: Arg{Name: "allowlists", Type: List, Help: "domains never blocked (regular expressions allowed)"}, Api: "allowlists", Kind: dnsList},
			{Arg: Arg{Name: "blocklists", Type: List, Help: "domains always blocked (regular expressions allowed)"}, Api: "blocklists", Kind: dnsList},
			{Arg: Arg{Name: "wildcards", Type: List, Help: "domains blocked with all their subdomains"}, Api: "wildcards", Kind: dnsList},
			{Arg: Arg{Name: "source-nets", Type: List, Help: "client networks or addresses the policy applies to, empty for all", Validate: unboundValidateNetworksOrIPs},
				Api: "source_nets", Kind: dnsList},
			{Arg: Arg{Name: "address", Help: "IPv4 address blocked names resolve to, empty for 0.0.0.0", Validate: ValidateIP}, Api: "address"},
			{Arg: Arg{Name: "nxdomain", Type: Bool, Help: "answer blocked names with NXDOMAIN"}, Api: "nxdomain", Kind: dnsBool, Reset: "0"},
			{Arg: Arg{Name: "cache-ttl", Type: Int, Help: "seconds a downloaded list is kept, default 72000", Validate: ValidateRange(0, 1<<31-1)},
				Api: "cache_ttl", Reset: "72000"},
		},
		Columns: []string{"disabled", "description", "type", "source-nets", "nxdomain"},
		Names:   func(row dnsRow) []string { return []string{row["description"]} },
		Key:     func(row dnsRow) string { return row["description"] },
		KeyHelp: "the same description",
	}, "dnsbl", (*unbound.UnboundApi).BlocklistCreate, (*unbound.UnboundApi).BlocklistUpdate, (*unbound.UnboundApi).BlocklistRemove).register(
		&Command{Name: "types", Help: "list the predefined blocklists type= accepts", Args: []Arg{
			{Name: "search", Help: "only lists whose key, name or group contains this text"},
			{Name: "json", Type: Bool, Help: "one JSON object per line"},
		}, Run: unboundBlocklistTypes},
		&Command{Name: "update", Help: "download the lists of the enabled policies and load them into Unbound",
			Long: `Downloads all lists of the enabled policies (cached for cache-ttl) and reloads the blocklist of
Unbound; this applies the saved policies.`, Run: unboundBlocklistUpdate},
		&Command{Name: "allow", Help: "add a domain to a policy's allowlist and apply just that immediately",
			Long: `Adds domain to allowlists of the policy (moving it off its blocklists) and updates the running Unbound
without downloading the lists.`,
			Args: []Arg{
				{Name: "item", Positional: true, Required: true, Help: "the #, uuid or description of the policy"},
				{Name: "domain", Required: true, Help: "the domain", Validate: dnsNotEmpty},
			}, Run: unboundBlocklistAddDomain(true)},
		&Command{Name: "block", Help: "add a domain to a policy's blocklist and apply just that immediately",
			Long: `Adds domain to blocklists of the policy (moving it off its allowlists) and updates the running Unbound
without downloading the lists.`,
			Args: []Arg{
				{Name: "item", Positional: true, Required: true, Help: "the #, uuid or description of the policy"},
				{Name: "domain", Required: true, Help: "the domain", Validate: dnsNotEmpty},
			}, Run: unboundBlocklistAddDomain(false)},
		&Command{Name: "test", Help: "check whether a domain is blocked for a client", Args: []Arg{
			{Name: "domain", Positional: true, Required: true, Help: "the domain to test"},
			{Name: "source", Help: "the client address, default 127.0.0.1", Validate: ValidateIP},
			{Name: "json", Type: Bool, Help: "print the answer as JSON"},
		}, Run: unboundBlocklistTest},
	)

	unboundRecord(&dnsRecordMenu{
		Path:     "unbound/host-alias",
		Help:     "host override aliases: more names answered with the records of a host override",
		What:     "host alias",
		ItemHelp: "the #, uuid or FQDN host.domain of the alias",
		AddLong: `The alias hostname.domain answers with the records of the host override host= (its FQDN host.domain,
host.domain/RR when it has several records, or its uuid). Removing the host override removes its aliases.

  add host=web.example.lan hostname=www domain=example.lan`,
		Fields: []dnsField{
			unboundDisabledField(),
			{Arg: Arg{Name: "host", Help: "the host override: FQDN, FQDN/RR or uuid", Required: true}, Api: "host", Ref: unboundHostOverrideRef},
			{Arg: Arg{Name: "hostname", Help: "the host part of the alias, * for a wildcard"}, Api: "hostname"},
			{Arg: Arg{Name: "domain", Help: "the domain of the alias", Required: true, Validate: dnsNotEmpty}, Api: "domain"},
			unboundDescriptionField(),
		},
		Columns: []string{"disabled", "hostname", "domain", "host", "description"},
		Names:   func(row dnsRow) []string { return []string{unboundAliasFQDN(row)} },
		Key:     unboundAliasFQDN,
		KeyHelp: "the same FQDN",
	}, "host_alias", (*unbound.UnboundApi).HostAliasCreate, (*unbound.UnboundApi).HostAliasUpdate, (*unbound.UnboundApi).HostAliasRemove).register()
}

// unboundForwardSearch returns the plain forwards followed by the DNS over TLS servers
func unboundForwardSearch(c *Context, searchPhrase string) ([]json.RawMessage, error) {
	var forwards, err = dnsSearchRaw(c, "unbound", "settings", "search_forward", searchPhrase)
	if err != nil {
		return nil, err
	}
	dots, err := dnsSearchRaw(c, "unbound", "settings", "search_dot", searchPhrase)
	if err != nil {
		return nil, err
	}
	return append(forwards, dots...), nil
}

func unboundAliasFQDN(row dnsRow) string {
	return unbound.HostAlias{Hostname: row["hostname"], Domain: row["domain"]}.FQDN()
}

// --- extra commands

func unboundAclDefaultAction(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	if args.Has("action") {
		return api.AclSetDefaultAction(dnsCanonicalValue([]string{"allow", "deny", "refuse"}, args.String("action")))
	}
	action, err := api.AclDefaultAction()
	if err != nil {
		return err
	}
	c.Fields([][2]string{{"default-action", action}})
	return nil
}

func unboundForwardSystemNameservers(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	if args.Has("use") {
		return api.SetUseSystemNameservers(args.Bool("use"))
	}
	use, err := api.UseSystemNameservers()
	if err != nil {
		return err
	}
	nameservers, err := api.SystemNameservers()
	if err != nil {
		return err
	}
	c.Fields([][2]string{{"use", YesNo(Flag(use))}, {"nameservers", strings.Join(nameservers, ", ")}})
	return nil
}

func unboundBlocklistTypeKeys(c *Context) []string {
	var api, err = unboundApi(c)
	if err != nil {
		return nil
	}
	var types, listErr = api.BlocklistTypes()
	if listErr != nil {
		return nil
	}
	var keys = make([]string, 0, len(types))
	for _, option := range types {
		keys = append(keys, option.Key)
	}
	return keys
}

// unboundBlocklistTypeValue checks the predefined list keys and returns them as OPNsense spells them
func unboundBlocklistTypeValue(c *Context, value string) (string, error) {
	var api, err = unboundApi(c)
	if err != nil {
		return "", err
	}
	types, err := api.BlocklistTypes()
	if err != nil {
		return "", err
	}
	var keys []string
	for _, element := range splitList(value) {
		var found = false
		for _, option := range types {
			if strings.EqualFold(option.Key, element) {
				keys = append(keys, option.Key)
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("unknown list %q, see \"types\" for the keys", element)
		}
	}
	return strings.Join(keys, ","), nil
}

func unboundBlocklistTypes(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	types, err := api.BlocklistTypes()
	if err != nil {
		return err
	}
	var search = strings.ToLower(args.String("search"))
	var rows [][]string
	for _, option := range types {
		if search != "" && !strings.Contains(strings.ToLower(option.Key+" "+option.Value+" "+option.Group), search) {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(map[string]string{"key": option.Key, "name": strings.TrimSpace(option.Value), "group": option.Group}); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{option.Key, strings.TrimSpace(option.Value), option.Group})
	}
	if !args.Bool("json") {
		c.Table([]string{"KEY", "NAME", "GROUP"}, rows)
	}
	return nil
}

func unboundBlocklistUpdate(c *Context, _ *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.ServiceDnsbl()
}

// unboundBlocklistMenu is the record menu of /unbound/blocklist, for selecting a policy in allow / block
func unboundBlocklistSelect(c *Context, selector string) (dnsRow, error) {
	var menu = &dnsRecordMenu{
		Names: func(row dnsRow) []string { return []string{row["description"]} },
		Search: func(c *Context, searchPhrase string) ([]json.RawMessage, error) {
			return dnsSearchRaw(c, "unbound", "settings", "search_dnsbl", searchPhrase)
		},
	}
	var row, _, err = menu.run(c).selectRow(selector)
	return row, err
}

func unboundBlocklistAddDomain(allow bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var row, err = unboundBlocklistSelect(c, args.String("item"))
		if err != nil {
			return err
		}
		var api, apiErr = unboundApi(c)
		if apiErr != nil {
			return apiErr
		}
		return api.BlocklistAddDomain(row.uuid(), strings.TrimSpace(args.String("domain")), allow)
	}
}

func unboundBlocklistTest(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	result, err := api.BlocklistTest(strings.TrimSpace(args.String("domain")), args.String("source"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(result)
	}
	var fields = [][2]string{{"action", result.Action}}
	for _, key := range dnsSortedKeys(result.Policy) {
		var value = result.Policy[key]
		var text string
		switch typed := value.(type) {
		case string:
			text = typed
		case nil:
			text = ""
		default:
			var data, _ = json.Marshal(typed)
			text = string(data)
		}
		fields = append(fields, [2]string{"policy." + key, text})
	}
	c.Fields(fields)
	return nil
}
