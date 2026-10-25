package cli

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// /vpn/openvpn/client-override: client specific overrides (api/openvpn/client_overwrites). The natural key is the
// common name (exact, as OpenVPN compares it) together with the set of servers the override applies to

func init() {
	var menu = Root.Menu("vpn/openvpn/client-override")
	menu.Help = "client specific overrides: per client tunnel address, routes, DNS, block (VPN > OpenVPN > Client Specific Overrides)"
	var item = openvpnClientOverrideItemArg
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the client specific overrides",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every override"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only overrides where any field contains this text"},
			},
			Run: openvpnClientOverridePrint,
		},
		&Command{
			Name: "show",
			Help: "show all fields of one client specific override",
			Args: []Arg{item},
			Run:  openvpnClientOverrideShow,
		},
		&Command{
			Name: "add",
			Help: "add a client specific override, prints its uuid",
			Long: `An override is named by its common name and the servers it applies to (servers= or none for all
servers): if one with the same common name (case-sensitive, like OpenVPN) and the same servers exists already, add
fails unless replace is given, then that override is replaced completely (fields not given are cleared). Use set to
change single fields. OpenVPN merges all enabled overrides matching a client, so an override for all servers and
one for a single server can complement each other.

  add common-name=alice servers=office tunnel-network=10.8.0.8/30 local-networks=192.168.10.0/24
` + openvpnClientOverrideApplyHint,
			Args: append(openvpnClientOverrideFieldArgs(true),
				Arg{Name: "replace", Type: Bool, Help: "overwrite an existing override with the same common name and servers"}),
			Run: openvpnClientOverrideAdd,
		},
		&Command{
			Name: "set",
			Help: "change fields of a client specific override, the others are kept",
			Long: `All named arguments are new values, an empty value clears a field (e.g. tunnel-network= or servers= for
all servers). Lists replace the whole list.
` + openvpnClientOverrideApplyHint,
			Args: append([]Arg{item}, openvpnClientOverrideFieldArgs(false)...),
			Run:  openvpnClientOverrideSet,
		},
		&Command{
			Name: "remove",
			Help: "remove a client specific override",
			Long: openvpnClientOverrideApplyHint,
			Args: []Arg{item},
			Run:  openvpnClientOverrideRemove,
		},
		&Command{Name: "enable", Help: "enable a client specific override", Long: openvpnClientOverrideApplyHint,
			Args: []Arg{item}, Run: openvpnClientOverrideEnabler(true)},
		&Command{Name: "disable", Help: "disable a client specific override", Long: openvpnClientOverrideApplyHint,
			Args: []Arg{item}, Run: openvpnClientOverrideEnabler(false)},
	)
}

// openvpnClientOverrideApplyHint ends the help of the commands that change overrides
const openvpnClientOverrideApplyHint = `OpenVPN reads the overrides when a client connects: changes apply on its next connect, no reconfigure is
needed ("/vpn/openvpn/session remove" disconnects a client).`

var openvpnClientOverrideItemArg = Arg{
	Name: "item", Positional: true, Required: true,
	Help:     "the #, uuid or common name of the override",
	Complete: openvpnClientOverrideNames,
}

// openvpnClientOverrideNames completes the item names: the common names
func openvpnClientOverrideNames(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var overrides, listErr = api.ClientOverrideList("")
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(overrides))
	for _, override := range overrides {
		names = append(names, override.CommonName)
	}
	return names
}

// openvpnClientOverrideServerNames completes servers=: the descriptions of the server instances (the uuid when a
// server has no or no unique description)
func openvpnClientOverrideServerNames(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var servers, listErr = api.ClientOverrideServers()
	if listErr != nil {
		return nil
	}
	var count = map[string]int{}
	for _, server := range servers {
		count[strings.ToLower(server.Description())]++
	}
	var names = make([]string, 0, len(servers))
	for _, server := range servers {
		if description := server.Description(); description != "" && count[strings.ToLower(description)] == 1 {
			names = append(names, description)
		} else {
			names = append(names, server.Id)
		}
	}
	return names
}

// openvpnClientOverrideFieldArgs are the writable fields; for add the common name is required
func openvpnClientOverrideFieldArgs(add bool) []Arg {
	return []Arg{
		{Name: "common-name", Required: add, Validate: openvpnClientOverrideValidateCommonName,
			Help: "the client's certificate common name (or username, when the server uses it as common name)"},
		{Name: "servers", Type: List, Complete: openvpnClientOverrideServerNames,
			Help: "server instances (description or uuid) it applies to, empty for all servers"},
		{Name: "tunnel-network", Validate: openvpnClientOverrideValidateNetwork(4),
			Help: "IPv4 tunnel address of the client with prefix length, e.g. 10.8.0.8/30"},
		{Name: "tunnel-network6", Validate: openvpnClientOverrideValidateNetwork(6),
			Help: "IPv6 tunnel address of the client with prefix length, e.g. fd00:8::8/64"},
		{Name: "local-networks", Type: List, Validate: openvpnClientOverrideValidateNetworks,
			Help: "networks (or addresses) behind the server the client can reach, pushed as routes"},
		{Name: "remote-networks", Type: List, Validate: openvpnClientOverrideValidateNetworks,
			Help: "networks (or addresses) behind the client, routed to it (iroute)"},
		{Name: "redirect-gateway", Type: List, Values: openvpn.ClientOverrideRedirectGatewayOptions,
			Help: "push redirect-gateway with these flags (def1 = the usual default route override), empty for none"},
		{Name: "push-reset", Type: Bool, Help: "do not inherit the server's push options"},
		{Name: "block", Type: Bool, Help: "refuse the connection of this client"},
		{Name: "route-gateway", Validate: ValidateIP, Help: "gateway pushed to the client (route-gateway)"},
		{Name: "dns-domain", Type: List, Validate: openvpnClientOverrideValidateHostnames, Help: "DNS domain pushed to the client"},
		{Name: "dns-domain-search", Type: List, Validate: openvpnClientOverrideValidateHostnames, Help: "DNS search domains pushed to the client"},
		{Name: "dns-servers", Type: List, Validate: ValidateIPList, Help: "DNS servers pushed to the client"},
		{Name: "ntp-servers", Type: List, Validate: ValidateIPList, Help: "NTP servers pushed to the client"},
		{Name: "wins-servers", Type: List, Validate: ValidateIPList, Help: "WINS servers pushed to the client"},
		{Name: "register-dns", Type: Bool, Help: "make Windows clients register their DNS name (register-dns)"},
		{Name: "description", Help: "description"},
		{Name: "disabled", Type: Bool, Help: "keep the override, but don't apply it"},
	}
}

// openvpnClientOverrideFieldNames maps the argument names to the API field names (servers is resolved separately)
var openvpnClientOverrideFieldNames = [][2]string{
	{"common-name", "common_name"}, {"tunnel-network", "tunnel_network"}, {"tunnel-network6", "tunnel_networkv6"},
	{"local-networks", "local_networks"}, {"remote-networks", "remote_networks"}, {"redirect-gateway", "redirect_gateway"},
	{"push-reset", "push_reset"}, {"block", "block"}, {"route-gateway", "route_gateway"}, {"dns-domain", "dns_domain"},
	{"dns-domain-search", "dns_domain_search"}, {"dns-servers", "dns_servers"}, {"ntp-servers", "ntp_servers"},
	{"wins-servers", "wins_servers"}, {"register-dns", "register_dns"}, {"description", "description"},
	{"disabled", "enabled"},
}

// openvpnClientOverrideFields returns the field arguments (except servers) as API fields: all of them, or with
// onlyGiven just the given ones. Addresses and networks are normalized, lists comma joined
func openvpnClientOverrideFields(args *Args, onlyGiven bool) openvpn.ClientOverrideFields {
	var fields = openvpn.ClientOverrideFields{}
	for _, names := range openvpnClientOverrideFieldNames {
		var arg, field = names[0], names[1]
		if onlyGiven && !args.Has(arg) {
			continue
		}
		switch arg {
		case "disabled":
			fields[field] = Flag(!args.Bool(arg))
		case "push-reset", "block", "register-dns":
			fields[field] = Flag(args.Bool(arg))
		case "tunnel-network", "tunnel-network6":
			fields[field] = openvpnClientOverrideNormalizeNetwork(strings.TrimSpace(args.String(arg)))
		case "local-networks", "remote-networks":
			var networks = args.List(arg)
			for i, network := range networks {
				networks[i] = openvpnClientOverrideNormalizeNetwork(network)
			}
			fields[field] = strings.Join(networks, ",")
		case "route-gateway":
			fields[field] = openvpnClientOverrideNormalizeNetwork(strings.TrimSpace(args.String(arg)))
		case "dns-servers", "ntp-servers", "wins-servers":
			fields[field] = dnsmasqNormalizeIPs(args.List(arg))
		case "redirect-gateway":
			fields[field] = openvpnClientOverrideRedirectGateway(args.List(arg))
		case "dns-domain", "dns-domain-search":
			fields[field] = strings.Join(args.List(arg), ",")
		default:
			fields[field] = strings.TrimSpace(args.String(arg))
		}
	}
	return fields
}

// openvpnClientOverrideRedirectGateway maps the flags to the option keys in their spelling (the arguments are
// matched case-insensitively)
func openvpnClientOverrideRedirectGateway(values []string) string {
	var keys = make([]string, 0, len(values))
	for _, value := range values {
		for _, option := range openvpn.ClientOverrideRedirectGatewayOptions {
			if strings.EqualFold(option, value) {
				value = option
			}
		}
		keys = append(keys, value)
	}
	return strings.Join(keys, ",")
}

// openvpnClientOverrideNormalizeNetwork returns an address or network in canonical form (FD00:0::1/64 ->
// fd00::1/64), host bits are kept like OPNsense does
func openvpnClientOverrideNormalizeNetwork(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.String()
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func openvpnClientOverrideValidateCommonName(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty")
	}
	if strings.Contains(value, "/") {
		return fmt.Errorf("must not contain a slash, got %q", value)
	}
	return nil
}

// openvpnClientOverrideValidateNetwork accepts an address with prefix length of the given family (4 or 6)
func openvpnClientOverrideValidateNetwork(family int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var prefix, err = netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || (family == 4) != prefix.Addr().Is4() {
			return fmt.Errorf("must be an IPv%d network with prefix length like %s, got %q", family,
				map[int]string{4: "10.8.0.8/30", 6: "fd00:8::8/64"}[family], value)
		}
		return nil
	}
}

// openvpnClientOverrideValidateNetworks accepts comma separated networks (CIDR) or addresses
func openvpnClientOverrideValidateNetworks(value string) error {
	for _, element := range splitList(value) {
		if _, err := netip.ParsePrefix(element); err == nil {
			continue
		}
		if net.ParseIP(element) == nil {
			return fmt.Errorf("must be networks like 192.168.1.0/24 or addresses, got %q", element)
		}
	}
	return nil
}

var openvpnClientOverrideHostnamePattern = regexp.MustCompile(`^([A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?\.?$`)

// openvpnClientOverrideValidateHostnames accepts comma separated domain names
func openvpnClientOverrideValidateHostnames(value string) error {
	for _, element := range splitList(value) {
		if !openvpnClientOverrideHostnamePattern.MatchString(element) {
			return fmt.Errorf("must be domain names like example.lan, got %q", element)
		}
	}
	return nil
}

// openvpnClientOverrideResolveServers maps the servers argument (descriptions, labels or uuids) to the comma
// joined server ids the API expects, "" (all servers) for an empty list
func openvpnClientOverrideResolveServers(api *openvpn.OpenVPNApi, names []string) (string, error) {
	if len(names) == 0 {
		return "", nil
	}
	var servers, err = api.ClientOverrideServers()
	if err != nil {
		return "", err
	}
	var ids []string
	for _, name := range names {
		var id, resolveErr = openvpnClientOverrideResolveServer(servers, name)
		if resolveErr != nil {
			return "", resolveErr
		}
		if !containsFold(ids, id) {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ","), nil
}

func openvpnClientOverrideResolveServer(servers []openvpn.ClientOverrideServer, name string) (string, error) {
	for _, server := range servers {
		if strings.EqualFold(server.Id, name) {
			return server.Id, nil
		}
	}
	var matches []openvpn.ClientOverrideServer
	for _, server := range servers {
		if strings.EqualFold(server.Label, name) || strings.EqualFold(server.Description(), name) {
			matches = append(matches, server)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Id, nil
	case 0:
		var known = make([]string, 0, len(servers))
		for _, server := range servers {
			known = append(known, fmt.Sprintf("%q (%s)", server.Description(), server.Id))
		}
		if len(known) == 0 {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("openvpn server %q, there are no server instances", name)}
		}
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("openvpn server %q, the servers are %s", name, strings.Join(known, ", "))}
	default:
		var ids = make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.Id)
		}
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d openvpn servers named %q (%s), use the uuid",
			len(matches), name, strings.Join(ids, ", "))}
	}
}

// openvpnClientOverrideDisabled renders the enabled flag of the API as the disabled argument
func openvpnClientOverrideDisabled(override openvpn.ClientOverride) string {
	if override.Enabled == "0" {
		return "yes"
	}
	return "no"
}

// openvpnClientOverrideServersText renders the servers: OPNsense's labels "description (port / PROTO)", "all" for
// an override without servers
func openvpnClientOverrideServersText(override openvpn.ClientOverride) string {
	switch {
	case override.Servers == "":
		return "all"
	case override.ServersLabel != "":
		return override.ServersLabel
	default:
		return dnsmasqListCell(override.Servers)
	}
}

// openvpnClientOverrideTunnel renders both tunnel networks for a table cell
func openvpnClientOverrideTunnel(override openvpn.ClientOverride) string {
	var networks []string
	for _, network := range []string{override.TunnelNetwork, override.TunnelNetworkV6} {
		if network != "" {
			networks = append(networks, network)
		}
	}
	return strings.Join(networks, ", ")
}

// openvpnClientOverrideDetail are the fields of show and print detail, named like the arguments
func openvpnClientOverrideDetail(override openvpn.ClientOverride) [][2]string {
	return [][2]string{
		{"uuid", override.Uuid},
		{"common-name", override.CommonName},
		{"servers", openvpnClientOverrideServersText(override)},
		{"disabled", openvpnClientOverrideDisabled(override)},
		{"block", YesNo(override.Block)},
		{"tunnel-network", override.TunnelNetwork},
		{"tunnel-network6", override.TunnelNetworkV6},
		{"local-networks", override.LocalNetworks},
		{"remote-networks", override.RemoteNetworks},
		{"redirect-gateway", override.RedirectGateway},
		{"push-reset", YesNo(override.PushReset)},
		{"route-gateway", override.RouteGateway},
		{"dns-domain", override.DnsDomain},
		{"dns-domain-search", override.DnsDomainSearch},
		{"dns-servers", override.DnsServers},
		{"ntp-servers", override.NtpServers},
		{"wins-servers", override.WinsServers},
		{"register-dns", YesNo(override.RegisterDns)},
		{"description", override.Description},
	}
}

func openvpnClientOverridePrint(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	raws, overrides, err := api.ClientOverrideListRaw(args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, raw := range raws {
			if err := c.JSON(raw); err != nil {
				return err
			}
		}
		return nil
	}

	var uuids = make([]string, len(overrides))
	for i, override := range overrides {
		uuids[i] = override.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(overrides))
		for i, override := range overrides {
			details[i] = openvpnClientOverrideDetail(override)
		}
		c.Details(details, uuids)
		return nil
	}

	var rows = make([][]string, len(overrides))
	for i, override := range overrides {
		rows[i] = []string{openvpnClientOverrideDisabled(override), override.CommonName, openvpnClientOverrideServersText(override),
			openvpnClientOverrideTunnel(override), YesNo(override.Block), override.Description}
	}
	c.Items([]string{"DISABLED", "COMMON-NAME", "SERVERS", "TUNNEL-NETWORK", "BLOCK", "DESCRIPTION"}, rows, uuids)
	return nil
}

// openvpnClientOverrideSelect loads all overrides and returns the one the selector refers to: # of print, uuid or
// common name (several overrides of one common name for different servers are ambiguous)
func openvpnClientOverrideSelect(c *Context, api *openvpn.OpenVPNApi, selector string) (openvpn.ClientOverride, []openvpn.ClientOverride, error) {
	var overrides, err = api.ClientOverrideList("")
	if err != nil {
		return openvpn.ClientOverride{}, nil, err
	}
	override, err := Select(c, selector, overrides,
		func(o openvpn.ClientOverride) string { return o.Uuid },
		func(o openvpn.ClientOverride) []string { return []string{o.CommonName} })
	return override, overrides, err
}

func openvpnClientOverrideShow(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	override, _, err := openvpnClientOverrideSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(openvpnClientOverrideDetail(override))
	return nil
}

func openvpnClientOverrideAdd(c *Context, args *Args) error {
	var fields = openvpnClientOverrideFields(args, false)
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	servers, err := openvpnClientOverrideResolveServers(api, args.List("servers"))
	if err != nil {
		return err
	}
	var override = openvpn.ClientOverride{
		Enabled:         fields["enabled"],
		Servers:         servers,
		CommonName:      fields["common_name"],
		Block:           fields["block"],
		PushReset:       fields["push_reset"],
		TunnelNetwork:   fields["tunnel_network"],
		TunnelNetworkV6: fields["tunnel_networkv6"],
		LocalNetworks:   fields["local_networks"],
		RemoteNetworks:  fields["remote_networks"],
		RouteGateway:    fields["route_gateway"],
		RedirectGateway: fields["redirect_gateway"],
		RegisterDns:     fields["register_dns"],
		DnsDomain:       fields["dns_domain"],
		DnsDomainSearch: fields["dns_domain_search"],
		DnsServers:      fields["dns_servers"],
		NtpServers:      fields["ntp_servers"],
		WinsServers:     fields["wins_servers"],
		Description:     fields["description"],
	}

	if args.Bool("replace") {
		var uuid, replaced, replaceErr = api.ClientOverrideCreateOrUpdate(override)
		var tooMany *coreapi.TooManyFoundError
		if errors.As(replaceErr, &tooMany) {
			return fmt.Errorf("%w, change one with set or remove the duplicates", replaceErr)
		}
		if replaceErr != nil {
			return openvpnClientOverrideError(replaceErr)
		}
		if replaced {
			c.Infof("replaced the existing client specific override %s", override.CommonName)
		}
		c.Println(uuid)
		return nil
	}

	existing, err := api.ClientOverrideFindByKey(override.CommonName, override.Servers)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		var uuids = make([]string, len(existing))
		for i, match := range existing {
			uuids[i] = match.Uuid
		}
		return fmt.Errorf("a client specific override for %s with the same servers exists already (%s), change it with set or replace it with add ... replace",
			override.CommonName, strings.Join(uuids, ", "))
	}
	uuid, err := api.ClientOverrideCreate(override)
	if err != nil {
		return openvpnClientOverrideError(err)
	}
	c.Println(uuid)
	return nil
}

func openvpnClientOverrideSet(c *Context, args *Args) error {
	var fields = openvpnClientOverrideFields(args, true)
	if len(fields) == 0 && !args.Has("servers") {
		return errors.New("set: nothing to change, give at least one field like tunnel-network= or description= (type \"set ?\" for help)")
	}

	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	override, overrides, err := openvpnClientOverrideSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if args.Has("servers") {
		var servers, resolveErr = openvpnClientOverrideResolveServers(api, args.List("servers"))
		if resolveErr != nil {
			return resolveErr
		}
		fields["servers"] = servers
	}

	// a new common name or other servers must not collide with another override
	if _, renamed := fields["common_name"]; renamed || args.Has("servers") {
		var key = override
		if value, given := fields["common_name"]; given {
			key.CommonName = value
		}
		if value, given := fields["servers"]; given {
			key.Servers = value
		}
		for _, other := range overrides {
			if other.Uuid != override.Uuid && other.CommonName == key.CommonName && other.SameServers(key.Servers) {
				return fmt.Errorf("another client specific override for %s with the same servers exists already (%s)", key.CommonName, other.Uuid)
			}
		}
	}
	return openvpnClientOverrideError(api.ClientOverrideUpdate(override.Uuid, fields))
}

// openvpnClientOverrideError names the fields of an OPNsense validation error by their argument names
func openvpnClientOverrideError(err error) error {
	return openvpnValidationArgs(err, "cso.", func(field string) string {
		if field == "servers" {
			return "servers"
		}
		for _, names := range openvpnClientOverrideFieldNames {
			if names[1] == field {
				return names[0]
			}
		}
		return ""
	})
}

func openvpnClientOverrideRemove(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	override, _, err := openvpnClientOverrideSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return api.ClientOverrideRemove(override.Uuid)
}

// openvpnClientOverrideEnabler returns the run function of enable / disable
func openvpnClientOverrideEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = openvpnApi(c)
		if err != nil {
			return err
		}
		override, _, err := openvpnClientOverrideSelect(c, api, args.String("item"))
		if err != nil {
			return err
		}
		if (override.Enabled != "0") == enabled {
			c.Infof("client specific override %s is already %s", override.CommonName, EnabledWord(enabled))
			return nil
		}
		_, err = api.ClientOverrideSetEnabled(override.Uuid, enabled)
		return err
	}
}
