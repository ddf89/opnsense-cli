package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strings"
)

// /dnsmasq/domain: domain overrides (forward a domain to a DNS server), natural key domain + ip. One domain can
// be forwarded to several servers, so a domain name alone may be ambiguous

func init() {
	var menu = Root.Menu("dnsmasq/domain")
	menu.Help = "domain overrides: forward a domain to a specific DNS server"
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the domain overrides",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every domain override"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only domain overrides where any field contains this text"},
			},
			Run: dnsmasqDomainPrint,
		},
		&Command{
			Name: "show",
			Help: "show all fields of one domain override",
			Args: []Arg{dnsmasqDomainItemArg},
			Run:  dnsmasqDomainShow,
		},
		&Command{
			Name: "add",
			Help: "forward a domain to a DNS server, prints its uuid",
			Long: `Queries for the domain and its subdomains are forwarded to ip (port 53 unless port= is given), without ip
the domain is answered locally only (from host overrides / leases). A domain can be forwarded to several
servers: add it once per ip. If the domain is already forwarded to this ip, add fails unless replace is given,
then that entry is replaced completely (fields not given are reset to their defaults).
` + dnsmasqApplyHint,
			Args: append(dnsmasqDomainFieldArgs(true),
				Arg{Name: "replace", Type: Bool, Help: "overwrite an existing entry with the same domain and ip"}),
			Run: dnsmasqDomainAdd,
		},
		&Command{
			Name: "set",
			Help: "change fields of a domain override, the others are kept",
			Long: `All named arguments are new values: "set corp.lan ip=10.0.0.54" changes the server of corp.lan.
An empty value clears a field, e.g. port= or ip= (answer the domain locally).
` + dnsmasqApplyHint,
			Args: append([]Arg{dnsmasqDomainItemArg}, dnsmasqDomainFieldArgs(false)...),
			Run:  dnsmasqDomainSet,
		},
		&Command{
			Name: "remove",
			Help: "remove a domain override",
			Long: dnsmasqApplyHint,
			Args: []Arg{dnsmasqDomainItemArg},
			Run:  dnsmasqDomainRemove,
		},
	)
}

var dnsmasqDomainItemArg = Arg{
	Name: "item", Positional: true, Required: true,
	Help:     "the #, uuid or domain of the entry (# or uuid when the domain is forwarded to several servers)",
	Complete: dnsmasqDomainNames,
}

// dnsmasqDomainNames completes the item names: the forwarded domains
func dnsmasqDomainNames(c *Context) []string {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return nil
	}
	var domains, listErr = api.DomainOverrideList("")
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(domains))
	for _, domain := range domains {
		names = append(names, domain.Domain)
	}
	return names
}

// dnsmasqDomainFieldArgs are the writable fields; for add the domain is required and sequence defaults to 1
func dnsmasqDomainFieldArgs(add bool) []Arg {
	var sequence = Arg{Name: "sequence", Type: Int, Help: "order of the entry in the generated config, 1-99999", Validate: dnsmasqValidateSequence}
	if add {
		sequence.Default = "1"
	}
	return []Arg{
		{Name: "domain", Help: "the domain to forward, like corp.lan", Required: add, Validate: dnsmasqNotEmpty},
		{Name: "ip", Help: "the DNS server to forward to (IPv4 or IPv6), empty to answer the domain locally", Validate: ValidateIP},
		{Name: "port", Type: Int, Help: "port of the DNS server, empty for 53", Validate: ValidatePort},
		{Name: "source-ip", Help: "source IP address for queries to the DNS server", Validate: ValidateIP},
		sequence,
		{Name: "description", Help: "description"},
	}
}

func dnsmasqValidateSequence(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	return ValidateRange(1, 99999)(value)
}

// dnsmasqDomainFields returns the given field arguments as partial update, IPs in canonical form
func dnsmasqDomainFields(args *Args) dnsmasq.DomainOverrideFields {
	var given = func(name string) *string {
		if !args.Has(name) {
			return nil
		}
		var value = strings.TrimSpace(args.String(name))
		if name == "ip" || name == "source-ip" {
			value = dnsmasqNormalizeIPs(args.List(name))
		}
		return &value
	}
	return dnsmasq.DomainOverrideFields{
		Domain:      given("domain"),
		Ip:          given("ip"),
		Port:        given("port"),
		Srcip:       given("source-ip"),
		Sequence:    given("sequence"),
		Description: given("description"),
	}
}

func dnsmasqDomainPrint(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	raws, domains, err := dnsmasqSearch[dnsmasq.DomainOverride](api, "settings", "search_domain", args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return dnsmasqPrintJSON(c, raws)
	}

	var uuids = make([]string, len(domains))
	for i, domain := range domains {
		uuids[i] = domain.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(domains))
		for i, domain := range domains {
			details[i] = dnsmasqDomainDetail(domain)
		}
		c.Details(details, uuids)
		return nil
	}

	var rows = make([][]string, len(domains))
	for i, d := range domains {
		rows[i] = []string{d.Sequence, d.Domain, d.Ip, d.Port, d.Srcip, d.Description}
	}
	c.Items([]string{"SEQUENCE", "DOMAIN", "IP", "PORT", "SOURCE-IP", "DESCRIPTION"}, rows, uuids)
	return nil
}

// dnsmasqDomainDetail are the fields of show and print detail, named like the arguments
func dnsmasqDomainDetail(d dnsmasq.DomainOverride) [][2]string {
	return [][2]string{
		{"uuid", d.Uuid},
		{"sequence", d.Sequence},
		{"domain", d.Domain},
		{"ip", d.Ip},
		{"port", d.Port},
		{"source-ip", d.Srcip},
		{"ipset", d.Ipset},
		{"description", d.Description},
	}
}

// dnsmasqDomainSelect loads all domain overrides and returns the one the selector refers to: # of print, uuid or
// domain (case-insensitive, trailing dot ignored). A domain forwarded to several servers is ambiguous
func dnsmasqDomainSelect(c *Context, api *dnsmasq.DnsmasqApi, selector string) (dnsmasq.DomainOverride, []dnsmasq.DomainOverride, error) {
	var domains, err = api.DomainOverrideList("")
	if err != nil {
		return dnsmasq.DomainOverride{}, nil, err
	}
	domain, err := Select(c, selector, domains,
		func(d dnsmasq.DomainOverride) string { return d.Uuid },
		func(d dnsmasq.DomainOverride) []string { return []string{d.Domain} })

	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		var candidates []string
		for _, d := range domains {
			if dnsmasqSameName(d.Domain, selector) {
				candidates = append(candidates, fmt.Sprintf("%s (ip %q)", d.Uuid, d.Ip))
			}
		}
		return domain, domains, &coreapi.TooManyFoundError{Name: fmt.Sprintf(
			"domain %s is forwarded to %d servers: %s, select one by its # from print or its uuid",
			selector, len(candidates), strings.Join(candidates, ", "))}
	}
	return domain, domains, err
}

func dnsmasqDomainShow(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	domain, _, err := dnsmasqDomainSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	// the search row has no canonical ipset value, so fetch the entry itself
	if domain, err = api.DomainOverrideGet(domain.Uuid); err != nil {
		return err
	}
	c.Fields(dnsmasqDomainDetail(domain))
	return nil
}

func dnsmasqDomainAdd(c *Context, args *Args) error {
	var domain = dnsmasq.DomainOverride{
		Domain:      strings.TrimSpace(args.String("domain")),
		Ip:          dnsmasqNormalizeIPs(args.List("ip")),
		Port:        args.String("port"),
		Srcip:       dnsmasqNormalizeIPs(args.List("source-ip")),
		Sequence:    args.String("sequence"),
		Description: args.String("description"),
	}

	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}

	if args.Bool("replace") {
		var uuid, created, replaceErr = api.DomainOverrideCreateOrUpdate(domain)
		var tooMany *coreapi.TooManyFoundError
		if errors.As(replaceErr, &tooMany) {
			return fmt.Errorf("%w, change one with set or remove the duplicates", replaceErr)
		}
		if replaceErr != nil {
			return replaceErr
		}
		if !created {
			c.Infof("replaced the existing domain override %s (ip %q)", domain.Domain, domain.Ip)
		}
		c.Println(uuid)
		return nil
	}

	candidates, err := api.DomainOverrideFindAll(domain.Domain, "")
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if dnsmasqSameIP(candidate.Ip, domain.Ip) {
			return fmt.Errorf("the domain %s is already forwarded to ip %q (%s), change it with set or replace it with add ... replace",
				domain.Domain, domain.Ip, candidate.Uuid)
		}
	}
	uuid, err := api.DomainOverrideCreate(domain)
	if err != nil {
		return err
	}
	c.Println(uuid)
	return nil
}

func dnsmasqDomainSet(c *Context, args *Args) error {
	var fields = dnsmasqDomainFields(args)
	if fields == (dnsmasq.DomainOverrideFields{}) {
		return errors.New("set: nothing to change, give at least one field like ip= or description= (type \"set ?\" for help)")
	}

	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	domain, domains, err := dnsmasqDomainSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}

	// changing domain or ip must not duplicate another entry
	if fields.Domain != nil || fields.Ip != nil {
		var newDomain, newIp = domain.Domain, domain.Ip
		if fields.Domain != nil {
			newDomain = *fields.Domain
		}
		if fields.Ip != nil {
			newIp = *fields.Ip
		}
		for _, other := range domains {
			if other.Uuid != domain.Uuid && dnsmasqSameName(other.Domain, newDomain) && dnsmasqSameIP(other.Ip, newIp) {
				return fmt.Errorf("the domain %s is already forwarded to ip %q (%s)", newDomain, newIp, other.Uuid)
			}
		}
	}

	return api.DomainOverrideUpdate(domain.Uuid, fields)
}

func dnsmasqDomainRemove(c *Context, args *Args) error {
	var api, err = dnsmasqApi(c)
	if err != nil {
		return err
	}
	domain, _, err := dnsmasqDomainSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return api.DomainOverrideRemove(domain.Uuid)
}
