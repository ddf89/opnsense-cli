package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"
	"strings"
)

// /unbound/host-override: DNS records (A, AAAA, MX, TXT) Unbound answers itself. Items are selected by the # of
// print, the uuid, the FQDN host.domain or, when a FQDN has several records, host.domain/RR

const unboundItemHelp = "the #, uuid or FQDN host.domain of the entry (host.domain/RR when the FQDN has several records)"

const unboundApplyHint = `Changes are only saved, run "/unbound/service reconfigure" to apply them.`

var unboundRecordTypes = []string{"A", "AAAA", "MX", "TXT"}

// unboundFieldArgs are the field arguments of add and set
func unboundFieldArgs(add bool) []Arg {
	var rrDefault, ptrDefault = "", ""
	if add {
		rrDefault, ptrDefault = "A", "yes"
	}
	return []Arg{
		{Name: "host", Help: "the host part, * for a wildcard", Required: add},
		{Name: "domain", Help: "the domain part", Required: add},
		{Name: "rr", Help: "the record type", Values: unboundRecordTypes, Default: rrDefault, Validate: unboundValidateRr},
		{Name: "ip", Help: "the address: IPv4 for A, IPv6 for AAAA records (required for them)", Validate: ValidateIP},
		{Name: "mx", Help: "the mail server like mail.example.lan (required for MX records)"},
		{Name: "mx-priority", Help: "the MX preference, lower is preferred (required for MX records)", Type: Int, Validate: ValidateRange(0, 65535)},
		{Name: "txtdata", Help: "the TXT record content (required for TXT records)"},
		{Name: "ttl", Help: "TTL in seconds, empty for the Unbound default", Type: Int, Validate: ValidateRange(0, 2147483647)},
		{Name: "ptr", Help: "also answer the reverse lookup (PTR) of A and AAAA records", Type: Bool, Default: ptrDefault},
		{Name: "description", Help: "any text"},
		{Name: "disabled", Help: "keep the entry, but don't answer it", Type: Bool},
	}
}

func unboundValidateRr(value string) error {
	if value == "" {
		return fmt.Errorf("must be one of %s", strings.Join(unboundRecordTypes, ", "))
	}
	return nil
}

func init() {
	var menu = Root.Menu("unbound/host-override")
	menu.Help = "host overrides: A, AAAA, MX and TXT records Unbound answers itself"
	var item = Arg{Name: "item", Help: unboundItemHelp, Positional: true, Required: true, Complete: unboundHostOverrideNames}
	menu.Add(
		&Command{Name: "print", Help: "list the host overrides", Args: []Arg{
			{Name: "detail", Help: "show all fields of every entry", Type: Bool},
			{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
			{Name: "search", Help: "only entries where any field contains this text"},
		}, Run: unboundHostOverridePrint},
		&Command{Name: "show", Help: "show all fields of one host override", Args: []Arg{item}, Run: unboundHostOverrideShow},
		&Command{Name: "add", Help: "add a host override, prints its uuid",
			Long: `There can only be one entry per host, domain and record type. If it exists already, add fails unless
replace is given, then that entry is replaced completely (arguments not given are reset to their defaults).
` + unboundApplyHint,
			Args: append(unboundFieldArgs(true), Arg{Name: "replace", Help: "replace the entry with the same host, domain and record type", Type: Bool}),
			Run:  unboundHostOverrideAdd},
		&Command{Name: "set", Help: "change fields of a host override, the others are kept",
			Long: `Switching an entry to MX or TXT drops its ip (unless ip= is given, which then fails).
` + unboundApplyHint,
			Args: append([]Arg{item}, unboundFieldArgs(false)...), Run: unboundHostOverrideSet},
		&Command{Name: "remove", Help: "remove a host override", Long: unboundApplyHint, Args: []Arg{item}, Run: unboundHostOverrideRemove},
		&Command{Name: "enable", Help: "enable a host override", Long: unboundApplyHint, Args: []Arg{item}, Run: unboundHostOverrideEnabler(true)},
		&Command{Name: "disable", Help: "disable a host override", Long: unboundApplyHint, Args: []Arg{item}, Run: unboundHostOverrideEnabler(false)},
	)
}

// unboundHostOverrideSearch returns the matching entries in API order, with the raw API objects for json output
func unboundHostOverrideSearch(api *unbound.UnboundApi, searchPhrase string) ([]unbound.HostOverride, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("unbound", "settings", "search_host_override")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var overrides = make([]unbound.HostOverride, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &overrides[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected host override from OPNsense: %w", err)
		}
	}
	return overrides, rows, nil
}

// unboundFQDN is host.domain, or the domain alone for an entry without host
func unboundFQDN(hostOverride unbound.HostOverride) string {
	var domain = strings.TrimSuffix(hostOverride.Domain, ".")
	if hostOverride.Host == "" {
		return domain
	}
	return hostOverride.Host + "." + domain
}

func unboundHostOverrideUuid(hostOverride unbound.HostOverride) string {
	return hostOverride.Uuid
}

// unboundHostOverrideItemNames are the names an entry can be selected by: host.domain and host.domain/RR
func unboundHostOverrideItemNames(hostOverride unbound.HostOverride) []string {
	var fqdn = unboundFQDN(hostOverride)
	return []string{fqdn, fqdn + "/" + strings.ToUpper(hostOverride.Rr)}
}

// unboundHostOverrideNames completes item names from the API
func unboundHostOverrideNames(c *Context) []string {
	var api, err = unboundApi(c)
	if err != nil {
		return nil
	}
	var overrides, _, searchErr = unboundHostOverrideSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var counts = map[string]int{}
	for _, hostOverride := range overrides {
		counts[strings.ToLower(unboundFQDN(hostOverride))]++
	}
	var names []string
	for _, hostOverride := range overrides {
		var itemNames = unboundHostOverrideItemNames(hostOverride)
		if counts[strings.ToLower(itemNames[0])] > 1 {
			names = append(names, itemNames[1])
		} else {
			names = append(names, itemNames[0])
		}
	}
	return names
}

// unboundHostOverrideSelect loads all entries and finds the one selector refers to
func unboundHostOverrideSelect(c *Context, api *unbound.UnboundApi, selector string) (unbound.HostOverride, error) {
	var overrides, _, err = unboundHostOverrideSearch(api, "")
	if err != nil {
		return unbound.HostOverride{}, err
	}
	// host.domain./RR: Select ignores a trailing dot of the whole selector only
	if fqdn, rr, hasRr := strings.Cut(strings.TrimSpace(selector), "/"); hasRr {
		selector = strings.TrimSuffix(fqdn, ".") + "/" + rr
	}
	var hostOverride, selectErr = Select(c, selector, overrides, unboundHostOverrideUuid, unboundHostOverrideItemNames)
	var tooMany *coreapi.TooManyFoundError
	if errors.As(selectErr, &tooMany) && !strings.Contains(selector, "/") {
		return hostOverride, fmt.Errorf("%w, or as %s/<RR>", selectErr, selector)
	}
	return hostOverride, selectErr
}

// unboundValue is the record data depending on the record type
func unboundValue(hostOverride unbound.HostOverride) string {
	switch strings.ToUpper(hostOverride.Rr) {
	case "MX":
		return strings.TrimSpace(hostOverride.Mxprio + " " + hostOverride.Mx)
	case "TXT":
		return hostOverride.Txtdata
	default:
		return hostOverride.Ip
	}
}

// unboundDisabled renders the enabled flag of the API as the disabled argument
func unboundDisabled(hostOverride unbound.HostOverride) string {
	if hostOverride.Enabled == "0" {
		return "yes"
	}
	return "no"
}

// unboundFields are the fields of show and print detail, named like the arguments of add and set
func unboundFields(hostOverride unbound.HostOverride) [][2]string {
	return [][2]string{
		{"uuid", hostOverride.Uuid},
		{"disabled", unboundDisabled(hostOverride)},
		{"host", hostOverride.Host},
		{"domain", hostOverride.Domain},
		{"rr", hostOverride.Rr},
		{"ip", hostOverride.Ip},
		{"mx", hostOverride.Mx},
		{"mx-priority", hostOverride.Mxprio},
		{"txtdata", hostOverride.Txtdata},
		{"ttl", hostOverride.Ttl},
		{"ptr", YesNo(hostOverride.Addptr)},
		{"description", hostOverride.Description},
	}
}

func unboundHostOverridePrint(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var overrides, raw, searchErr = unboundHostOverrideSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(overrides))
	for i, hostOverride := range overrides {
		uuids[i] = hostOverride.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			if err := c.JSON(row); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(overrides))
		for i, hostOverride := range overrides {
			items[i] = unboundFields(hostOverride)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(overrides))
		for i, hostOverride := range overrides {
			rows[i] = []string{
				unboundDisabled(hostOverride), hostOverride.Host, hostOverride.Domain, hostOverride.Rr,
				unboundValue(hostOverride), hostOverride.Ttl, YesNo(hostOverride.Addptr), hostOverride.Description,
			}
		}
		c.Items([]string{"DISABLED", "HOST", "DOMAIN", "RR", "VALUE", "TTL", "PTR", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func unboundHostOverrideShow(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var hostOverride, selectErr = unboundHostOverrideSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(unboundFields(hostOverride))
	return nil
}

// unboundApplyArgs sets the fields given as arguments (for add all of them, with the defaults of those not given)
func unboundApplyArgs(args *Args, hostOverride *unbound.HostOverride, all bool) {
	var given = func(name string) bool { return all || args.Has(name) }
	var texts = []struct {
		name  string
		field *string
	}{
		{"host", &hostOverride.Host},
		{"domain", &hostOverride.Domain},
		{"ip", &hostOverride.Ip},
		{"mx", &hostOverride.Mx},
		{"mx-priority", &hostOverride.Mxprio},
		{"txtdata", &hostOverride.Txtdata},
		{"ttl", &hostOverride.Ttl},
		{"description", &hostOverride.Description},
	}
	for _, field := range texts {
		if given(field.name) {
			*field.field = args.String(field.name)
		}
	}
	if given("rr") {
		hostOverride.Rr = strings.ToUpper(args.String("rr"))
	}
	if given("ptr") {
		hostOverride.Addptr = Flag(args.Bool("ptr"))
	}
	if given("disabled") {
		hostOverride.Enabled = Flag(!args.Bool("disabled"))
	}

	// switching an existing entry to MX / TXT: drop its ip, OPNsense would still validate it
	if !all && (hostOverride.Rr == "MX" || hostOverride.Rr == "TXT") && !args.Has("ip") {
		hostOverride.Ip = ""
	}
}

// unboundValidate checks the fields required by the record type, OPNsense validates the rest
func unboundValidate(hostOverride unbound.HostOverride) error {
	switch hostOverride.Rr {
	case "A", "AAAA":
		if hostOverride.Ip == "" {
			return fmt.Errorf("%s records need an address, please set ip=", hostOverride.Rr)
		}
		if err := ValidateIP(hostOverride.Ip); err != nil {
			return fmt.Errorf("ip %w", err)
		}
		// OPNsense accepts an IPv4 address for AAAA records, so check the address family ourselves
		var isIPv6 = strings.Contains(hostOverride.Ip, ":")
		if hostOverride.Rr == "A" && isIPv6 {
			return fmt.Errorf("an A record needs an IPv4 address, got %s", hostOverride.Ip)
		}
		if hostOverride.Rr == "AAAA" && !isIPv6 {
			return fmt.Errorf("an AAAA record needs an IPv6 address, got %s", hostOverride.Ip)
		}
	case "MX":
		if hostOverride.Mx == "" || hostOverride.Mxprio == "" {
			return fmt.Errorf("MX records need mx= and mx-priority=")
		}
		if err := ValidateRange(0, 65535)(hostOverride.Mxprio); err != nil {
			return fmt.Errorf("mx-priority %w", err)
		}
	case "TXT":
		if hostOverride.Txtdata == "" {
			return fmt.Errorf("TXT records need txtdata=")
		}
	}

	if hostOverride.Ip != "" && (hostOverride.Rr == "MX" || hostOverride.Rr == "TXT") {
		return fmt.Errorf("ip= is only used for A and AAAA records, not for %s", hostOverride.Rr)
	}
	return nil
}

func unboundHostOverrideAdd(c *Context, args *Args) error {
	var hostOverride unbound.HostOverride
	unboundApplyArgs(args, &hostOverride, true)
	if err := unboundValidate(hostOverride); err != nil {
		return err
	}

	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var existing, lookupErr = api.HostOverrideGetByFQDNAndRr(hostOverride.Host, hostOverride.Domain, hostOverride.Rr)
	switch {
	case coreapi.IsNotFound(lookupErr):
		var uuid, createErr = api.HostOverrideCreate(hostOverride)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case lookupErr != nil:
		return lookupErr
	case !args.Bool("replace"):
		return fmt.Errorf("%s/%s exists already (%s), change it with set or replace it with add ... replace",
			unboundFQDN(existing), existing.Rr, existing.Uuid)
	}

	hostOverride.Uuid = existing.Uuid
	var uuid, updateErr = api.HostOverrideUpdate(hostOverride)
	if updateErr != nil {
		return updateErr
	}
	c.Infof("replaced the existing host override %s/%s", unboundFQDN(existing), existing.Rr)
	c.Println(uuid)
	return nil
}

func unboundHostOverrideSet(c *Context, args *Args) error {
	var fields int
	for _, name := range args.Given() {
		if name != "item" {
			fields++
		}
	}
	if fields == 0 {
		return fmt.Errorf("set: nothing to change, give at least one field like ip= or description= (type \"set ?\" for help)")
	}

	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var hostOverride, selectErr = unboundHostOverrideSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	unboundApplyArgs(args, &hostOverride, false)
	if err := unboundValidate(hostOverride); err != nil {
		return err
	}
	_, err = api.HostOverrideUpdate(hostOverride)
	return err
}

func unboundHostOverrideRemove(c *Context, args *Args) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	var hostOverride, selectErr = unboundHostOverrideSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.HostEntryRemove(hostOverride.Uuid)
}

// unboundHostOverrideEnabler returns the run function of enable / disable
func unboundHostOverrideEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = unboundApi(c)
		if err != nil {
			return err
		}
		var hostOverride, selectErr = unboundHostOverrideSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		if (hostOverride.Enabled != "0") == enabled {
			c.Infof("host override %s/%s is already %s", unboundFQDN(hostOverride), hostOverride.Rr, EnabledWord(enabled))
			return nil
		}
		hostOverride.Enabled = Flag(enabled)
		_, err = api.HostOverrideUpdate(hostOverride)
		return err
	}
}
