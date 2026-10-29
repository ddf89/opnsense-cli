package cli

import (
	"errors"
	"fmt"
	"net/netip"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"slices"
	"strings"
)

// /dnsmasq/host: host overrides and static DHCP reservations, natural key host + domain. print lists them by host
// name (sort= picks another order, sort=config the configured one that dnsmasq's hosts file follows), a one-shot #
// counts in host name order too

// dnsmasqHostSorts are the orders of print: the column to sort by, config = the configured (API) order
var dnsmasqHostSorts = []string{"host", "domain", "ip", "hwaddr", "description", "config"}

func init() {
	var menu = Root.Menu("dnsmasq/host")
	menu.Help = "host overrides and static DHCP reservations"
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the host overrides, by host name",
			Long: `Lists the hosts sorted by host name (then domain), numbers compare by value (host2 before host10) and case
is ignored. sort= picks another column; ip sorts by the first address, IPv4 before IPv6. sort=config keeps the
configured order, the order of dnsmasq's hosts file (OPNsense writes it in the order the hosts were added).
A # without a print before it (one-shot calls) counts in host name order; after print sort=… in the shell or a
script, # is the row of that print.

  print sort=ip
  print sort=config detail`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every host"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only hosts where any field contains this text"},
				{Name: "sort", Default: "host", Values: dnsmasqHostSorts, Help: "the order: by host (default), domain, ip, hwaddr, description, or config (the configured order)"},
			},
			Run: dnsmasqHostPrint,
		},
		&Command{
			Name: "show",
			Help: "show all fields of one host override",
			Args: []Arg{dnsmasqHostItemArg},
			Run:  dnsmasqHostShow,
		},
		&Command{
			Name: "add",
			Help: "add a host override, prints its uuid",
			Long: `The FQDN host.domain names the host: if it exists already, add fails unless replace is given, then that
host is replaced completely (fields not given are cleared). Use set to change single fields.
` + dnsmasqApplyHint,
			Args: append(dnsmasqHostFieldArgs(true),
				Arg{Name: "replace", Type: Bool, Help: "overwrite an existing host with the same host and domain"}),
			Run: dnsmasqHostAdd,
		},
		&Command{
			Name: "set",
			Help: "change fields of a host override, the others are kept",
			Long: `All named arguments are new values: "set web.example.lan host=www domain=other.lan" renames the host.
An empty value clears a field, e.g. cname= or description=.
` + dnsmasqApplyHint,
			Args: append([]Arg{dnsmasqHostItemArg}, dnsmasqHostFieldArgs(false)...),
			Run:  dnsmasqHostSet,
		},
		&Command{
			Name: "remove",
			Help: "remove a host override",
			Long: dnsmasqApplyHint,
			Args: []Arg{dnsmasqHostItemArg},
			Run:  dnsmasqHostRemove,
		},
	)
}

var dnsmasqHostItemArg = Arg{
	Name: "item", Positional: true, Required: true,
	Help:     "the #, uuid, FQDN host.domain or hostname of the host",
	Complete: dnsmasqHostNames,
}

// dnsmasqHostNames completes the item names: the FQDN of every host (the hostname of a host without domain)
func dnsmasqHostNames(c *Context) []string {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return nil
	}
	var hosts, listErr = api.HostList("")
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(hosts))
	for _, host := range hosts {
		names = append(names, host.FQDN())
	}
	return names
}

// dnsmasqHostFieldArgs are the writable fields; for add the host is required
func dnsmasqHostFieldArgs(add bool) []Arg {
	return []Arg{
		{Name: "host", Help: "hostname", Required: add, Validate: dnsmasqNotEmpty},
		{Name: "domain", Help: "domain of the host, empty for none"},
		{Name: "ip", Type: List, Help: "IPv4/IPv6 addresses", Validate: ValidateIPList},
		{Name: "cname", Type: List, Help: "CNAMEs pointing to this host"},
		{Name: "alias", Type: List, Help: "additional names of this host"},
		{Name: "hwaddr", Type: List, Help: "MAC addresses for a static DHCP reservation", Validate: ValidateMACList},
		{Name: "client-id", Help: "DHCP client identifier for the reservation"},
		{Name: "lease-time", Type: Int, Help: "DHCP lease time in seconds, empty for the default", Validate: dnsmasqValidateSeconds},
		{Name: "local", Type: Bool, Help: "the domain is local, answer only from hosts / DHCP"},
		{Name: "ignore", Type: Bool, Help: "ignore DHCP requests of this client"},
		{Name: "description", Help: "description"},
		{Name: "comments", Help: "comments"},
	}
}

// dnsmasqHostFieldNames maps the argument names to the API field names
var dnsmasqHostFieldNames = [][2]string{
	{"host", "host"}, {"domain", "domain"}, {"ip", "ip"}, {"cname", "cnames"}, {"alias", "aliases"},
	{"hwaddr", "hwaddr"}, {"client-id", "client_id"}, {"lease-time", "lease_time"}, {"local", "local"},
	{"ignore", "ignore"}, {"description", "descr"}, {"comments", "comments"},
}

// dnsmasqHostFields returns the field arguments as API fields: all of them, or with onlyGiven just the given ones.
// Lists are normalized (canonical IPs and MACs) and comma joined, an empty list clears the field
func dnsmasqHostFields(args *Args, onlyGiven bool) dnsmasq.HostFields {
	var fields = dnsmasq.HostFields{}
	for _, names := range dnsmasqHostFieldNames {
		var arg, field = names[0], names[1]
		if onlyGiven && !args.Has(arg) {
			continue
		}
		switch arg {
		case "ip":
			fields[field] = dnsmasqNormalizeIPs(args.List(arg))
		case "hwaddr":
			fields[field] = dnsmasqNormalizeMACs(args.List(arg))
		case "cname", "alias":
			fields[field] = strings.Join(args.List(arg), ",")
		case "local", "ignore":
			fields[field] = Flag(args.Bool(arg))
		default:
			fields[field] = strings.TrimSpace(args.String(arg))
		}
	}
	return fields
}

func dnsmasqHostPrint(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	raws, hosts, err := dnsmasqSearch[dnsmasq.Host](api, "settings", "search_host", args.String("search"))
	if err != nil {
		return err
	}
	var order = dnsmasqHostOrder(hosts, args.String("sort"))
	raws, hosts = dnsmasqReorder(raws, order), dnsmasqReorder(hosts, order)
	if args.Bool("json") {
		return dnsmasqPrintJSON(c, raws)
	}

	var uuids = make([]string, len(hosts))
	for i, host := range hosts {
		uuids[i] = host.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(hosts))
		for i, host := range hosts {
			details[i] = dnsmasqHostDetail(host)
		}
		c.Details(details, uuids)
		return nil
	}

	var rows = make([][]string, len(hosts))
	for i, host := range hosts {
		rows[i] = []string{host.Host, host.Domain, dnsmasqListCell(host.Ip), dnsmasqListCell(host.Hwaddr),
			dnsmasqListCell(host.Cnames), host.Description}
	}
	c.Items([]string{"HOST", "DOMAIN", "IP", "HWADDR", "CNAME", "DESCRIPTION"}, rows, uuids)
	return nil
}

// dnsmasqHostOrder returns the indexes of hosts in the order of sort (one of dnsmasqHostSorts). Ties keep the
// configured order
func dnsmasqHostOrder(hosts []dnsmasq.Host, sort string) []int {
	var order = make([]int, len(hosts))
	for i := range order {
		order[i] = i
	}
	if sort == "config" {
		return order
	}
	var byName = func(a, b dnsmasq.Host) int {
		if c := dnsmasqNaturalCompare(a.Host, b.Host); c != 0 {
			return c
		}
		return dnsmasqNaturalCompare(a.Domain, b.Domain)
	}
	slices.SortStableFunc(order, func(i, j int) int {
		var a, b = hosts[i], hosts[j]
		var c int
		switch sort {
		case "domain":
			c = dnsmasqNaturalCompare(a.Domain, b.Domain)
		case "ip":
			c = dnsmasqCompareFirstIP(a.Ip, b.Ip)
		case "hwaddr":
			c = dnsmasqNaturalCompare(a.Hwaddr, b.Hwaddr)
		case "description":
			c = dnsmasqNaturalCompare(a.Description, b.Description)
		}
		if c != 0 {
			return c
		}
		return byName(a, b)
	})
	return order
}

// dnsmasqReorder returns items in the order of the indexes
func dnsmasqReorder[T any](items []T, order []int) []T {
	var sorted = make([]T, len(order))
	for i, index := range order {
		sorted[i] = items[index]
	}
	return sorted
}

// dnsmasqCompareFirstIP compares the first addresses of two comma separated IP lists: IPv4 before IPv6, empty or
// invalid ones last
func dnsmasqCompareFirstIP(a string, b string) int {
	var first = func(list string) (netip.Addr, bool) {
		var head, _, _ = strings.Cut(list, ",")
		var addr, err = netip.ParseAddr(strings.TrimSpace(head))
		return addr.Unmap(), err == nil
	}
	var addrA, okA = first(a)
	var addrB, okB = first(b)
	switch {
	case okA && okB:
		return addrA.Compare(addrB)
	case okA:
		return -1
	case okB:
		return 1
	}
	return 0
}

// dnsmasqHostDetail are the fields of show and print detail, named like the arguments
func dnsmasqHostDetail(host dnsmasq.Host) [][2]string {
	return [][2]string{
		{"uuid", host.Uuid},
		{"host", host.Host},
		{"domain", host.Domain},
		{"ip", host.Ip},
		{"cname", host.Cnames},
		{"alias", host.Aliases},
		{"hwaddr", host.Hwaddr},
		{"client-id", host.ClientId},
		{"lease-time", host.LeaseTime},
		{"local", YesNo(host.Local)},
		{"ignore", YesNo(host.Ignore)},
		{"tag", host.SetTag},
		{"description", host.Description},
		{"comments", host.Comments},
	}
}

// dnsmasqHostSelect loads all hosts and returns the one the selector refers to: # of print, uuid, FQDN (a host
// without domain is named by its hostname), else a hostname that is unique over all domains
func dnsmasqHostSelect(c *Context, api *dnsmasq.DnsmasqApi, selector string) (dnsmasq.Host, []dnsmasq.Host, error) {
	var hosts, err = api.HostList("")
	if err != nil {
		return dnsmasq.Host{}, nil, err
	}
	// a one-shot # counts like the default print
	hosts = dnsmasqReorder(hosts, dnsmasqHostOrder(hosts, "host"))
	var uuidOf = func(host dnsmasq.Host) string { return host.Uuid }
	host, err := Select(c, selector, hosts, uuidOf, func(host dnsmasq.Host) []string { return []string{host.FQDN()} })
	if coreapi.IsNotFound(err) && !dnsmasqIsIndex(selector) {
		var byHostname, hostnameErr = Select(c, selector, hosts, uuidOf, func(host dnsmasq.Host) []string { return []string{host.Host} })
		if !coreapi.IsNotFound(hostnameErr) {
			return byHostname, hosts, hostnameErr
		}
	}
	return host, hosts, err
}

func dnsmasqHostShow(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	host, _, err := dnsmasqHostSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(dnsmasqHostDetail(host))
	return nil
}

func dnsmasqHostAdd(c *Context, args *Args) error {
	var fields = dnsmasqHostFields(args, false)
	var host = dnsmasq.Host{
		Host:        fields["host"],
		Domain:      fields["domain"],
		Local:       fields["local"],
		Ip:          fields["ip"],
		Cnames:      fields["cnames"],
		ClientId:    fields["client_id"],
		Hwaddr:      fields["hwaddr"],
		LeaseTime:   fields["lease_time"],
		Ignore:      fields["ignore"],
		Description: fields["descr"],
		Comments:    fields["comments"],
		Aliases:     fields["aliases"],
	}

	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}

	if args.Bool("replace") {
		var uuid, replaced, replaceErr = api.HostCreateOrUpdate(host)
		var tooMany *coreapi.TooManyFoundError
		if errors.As(replaceErr, &tooMany) {
			return fmt.Errorf("%w, change one with set or remove the duplicates", replaceErr)
		}
		if replaceErr != nil {
			return replaceErr
		}
		if replaced {
			c.Infof("replaced the existing host override %s", host.FQDN())
		}
		c.Println(uuid)
		return nil
	}

	existing, err := api.HostFindByFQDN(host.Host, host.Domain)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		var uuids = make([]string, len(existing))
		for i, match := range existing {
			uuids[i] = match.Uuid
		}
		return fmt.Errorf("the host %s exists already (%s), change it with set or replace it with add ... replace",
			host.FQDN(), strings.Join(uuids, ", "))
	}
	uuid, err := api.HostCreate(host)
	if err != nil {
		return err
	}
	c.Println(uuid)
	return nil
}

func dnsmasqHostSet(c *Context, args *Args) error {
	var fields = dnsmasqHostFields(args, true)
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like ip= or description= (type \"set ?\" for help)")
	}

	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	host, hosts, err := dnsmasqHostSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}

	// a rename must not create a duplicate FQDN
	if _, renamed := fields["host"]; renamed || args.Has("domain") {
		var renamedTo = dnsmasq.Host{Host: host.Host, Domain: host.Domain}
		if value, given := fields["host"]; given {
			renamedTo.Host = value
		}
		if value, given := fields["domain"]; given {
			renamedTo.Domain = value
		}
		for _, other := range hosts {
			if other.Uuid != host.Uuid && strings.EqualFold(other.Host, renamedTo.Host) && strings.EqualFold(other.Domain, renamedTo.Domain) {
				return fmt.Errorf("another host named %s exists already (%s)", renamedTo.FQDN(), other.Uuid)
			}
		}
	}

	return api.HostUpdate(host.Uuid, fields)
}

func dnsmasqHostRemove(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	host, _, err := dnsmasqHostSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return api.HostRemove(host.Uuid)
}
