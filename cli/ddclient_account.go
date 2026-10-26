package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"opnsense-cli/opnsense/api/ddclient"
)

// /ddclient/account: the DDNS accounts (Services > Dynamic DNS > Settings > Accounts) with the address last
// registered at the provider. Natural key: the description. Passwords are never printed

func init() {
	var menu = Root.Menu("ddclient/account")
	menu.Help = "Dynamic DNS accounts and their current address"
	menu.Add(
		&Command{Name: "print", Help: "list the accounts with their current address",
			Long: `Lists the accounts with the address last registered at the provider (CURRENT-IP) and when (UPDATED),
both empty before the first update. options=<field> lists the choices of service, protocol, check-ip or interface
instead (the services and check methods depend on the backend, see /ddclient/settings).`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every account"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (without the password)"},
				{Name: "search", Help: "only accounts where any field contains this text"},
				{Name: "options", Help: "list the choices of this field instead", Values: []string{"service", "protocol", "check-ip", "interface"}},
			},
			Run: ddclientRun(ddclientAccountPrint)},
		&Command{Name: "show", Help: "show all fields of one account", Args: []Arg{ddclientAccountItemArg},
			Run: ddclientRun(ddclientAccountShow)},
		&Command{Name: "add", Help: "add an account, prints its uuid",
			Long: `The description names the account: if it exists already, add fails unless replace is given, then that
account is replaced (fields not given get their defaults, a stored password is kept). New accounts are enabled
unless disabled is given: after the next reconfigure the service registers the address at the provider.

  add description=home service=dyndns2 username=me password=secret hostnames=home.example.com check-ip=web_icanhazip
  add description=office service=cloudflare password=token zone=example.com hostnames=office.example.com check-ip=if interface=wan disabled

password= ends up in the shell history. ` + ddclientApplyHint,
			Args: append(ddclientAccountFieldArgs(true), Arg{Name: "replace", Type: Bool, Help: "replace an existing account with the same description"}),
			Run:  ddclientRun(ddclientAccountAdd)},
		&Command{Name: "set", Help: "change fields of an account, the others are kept",
			Long: `All named arguments are new values, an empty value clears an optional field (server=, zone=). A
password can be changed but not cleared, password= ends up in the shell history.
` + ddclientApplyHint,
			Args: append([]Arg{ddclientAccountItemArg}, ddclientAccountFieldArgs(false)...),
			Run:  ddclientRun(ddclientAccountSet)},
		&Command{Name: "remove", Help: "remove an account", Long: ddclientApplyHint, Args: []Arg{ddclientAccountItemArg},
			Run: ddclientRun(ddclientAccountRemove)},
		&Command{Name: "enable", Help: "enable an account", Long: ddclientApplyHint, Args: []Arg{ddclientAccountItemArg},
			Run: ddclientRun(ddclientAccountEnable(true))},
		&Command{Name: "disable", Help: "disable an account", Long: ddclientApplyHint, Args: []Arg{ddclientAccountItemArg},
			Run: ddclientRun(ddclientAccountEnable(false))},
		&Command{Name: "refresh", Help: "update an account at its provider now (native backend)",
			Long: `Forces an update of the account: OPNsense stops the service, forgets the cached state of the account
and starts the service, which then registers the current address at the provider. Needs the native backend and
the service enabled; the service runs afterwards, also when it was stopped. Uses the saved configuration, an
account changed since the last reconfigure is refreshed with its old settings.`,
			Confirm: "This restarts the Dynamic DNS service, which then updates the account at its DDNS provider.",
			Args:    []Arg{ddclientAccountItemArg},
			Run:     ddclientRun(ddclientAccountRefresh)},
	)
}

var ddclientAccountItemArg = Arg{Name: "item", Positional: true, Required: true,
	Help: "the #, uuid or description of the account", Complete: ddclientAccountNames}

func ddclientAccountNames(c *Context) []string {
	var api, err = ddclientApi(c)
	if err != nil {
		return nil
	}
	var accounts, _, listErr = api.AccountList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, account := range accounts {
		names = append(names, account.Description)
	}
	return names
}

// ddclientCompleteOptions completes the keys of an option field
func ddclientCompleteOptions(field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = ddclientApi(c)
		if err != nil {
			return nil
		}
		var options, optionsErr = api.AccountOptions()
		if optionsErr != nil {
			return nil
		}
		var keys []string
		for _, option := range options[field] {
			if option.Key != "" {
				keys = append(keys, option.Key)
			}
		}
		return keys
	}
}

var (
	ddclientUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9\-.@_:+%]*$`)
	ddclientIpv6HostPattern = regexp.MustCompile(`^::(([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?$`)
	ddclientHostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9*_@]([a-zA-Z0-9*_.-]*[a-zA-Z0-9_])?\.?$`)
)

func ddclientValidateDescription(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty, the description names the account")
	}
	if len([]rune(value)) > 255 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("must be 1-255 characters on one line, got %q", value)
	}
	return nil
}

func ddclientValidateUsername(value string) error {
	if !ddclientUsernamePattern.MatchString(value) {
		return fmt.Errorf("may only contain letters, digits and - . @ _ : + %%, got %q", value)
	}
	return nil
}

func ddclientValidatePassword(value string) error {
	if value == "" {
		return errors.New("must not be empty, OPNsense keeps the stored password (a password can not be cleared)")
	}
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("must be one line")
	}
	return nil
}

func ddclientValidateLine(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("must be one line")
	}
	return nil
}

func ddclientValidateHostname(value string) error {
	if value != "" && !ddclientHostnamePattern.MatchString(value) {
		return fmt.Errorf("must be a host name like host.example.com, got %q", value)
	}
	return nil
}

func ddclientValidateHostnames(value string) error {
	for _, hostname := range splitList(value) {
		if err := ddclientValidateHostname(hostname); err != nil {
			return err
		}
	}
	return nil
}

func ddclientValidateIpv6Host(value string) error {
	if value != "" && !ddclientIpv6HostPattern.MatchString(value) {
		return fmt.Errorf("must be the host part of an IPv6 address like ::1000, got %q", value)
	}
	return nil
}

func ddclientNotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty, leave it out to keep the current value")
	}
	return nil
}

// ddclientAccountFieldNames maps the argument names to the API field names, in the order of the GUI
var ddclientAccountFieldNames = [][2]string{
	{"description", "description"}, {"disabled", "enabled"}, {"service", "service"}, {"protocol", "protocol"},
	{"server", "server"}, {"resource-id", "resourceId"}, {"username", "username"}, {"password", "password"},
	{"wildcard", "wildcard"}, {"zone", "zone"}, {"hostnames", "hostnames"}, {"ttl", "ttl"}, {"check-ip", "checkip"},
	{"interface", "interface"}, {"dynamic-ipv6-host", "dynipv6host"}, {"check-ip-timeout", "checkip_timeout"},
	{"force-ssl", "force_ssl"},
}

// ddclientAccountFieldArgs are the writable fields; add requires description, service, hostnames and check-ip
func ddclientAccountFieldArgs(add bool) []Arg {
	return []Arg{
		{Name: "description", Required: add, Help: "the name of the account (unique)", Validate: ddclientValidateDescription},
		{Name: "disabled", Type: Bool, Help: "keep the account, but don't update it"},
		{Name: "service", Required: add, Help: `the DDNS provider, see "print options=service"`, Validate: ddclientNotEmpty,
			Complete: ddclientCompleteOptions("service")},
		{Name: "protocol", Help: "the protocol of a custom service, empty for none", Values: []string{"dyndns1", "dyndns2", "get", "post", "put"}},
		{Name: "server", Help: "the server of a custom or PowerDNS service", Validate: ddclientValidateLine},
		{Name: "resource-id", Help: "the resource id (Azure)", Validate: ddclientValidateLine},
		{Name: "username", Help: "the user name at the provider", Validate: ddclientValidateUsername},
		{Name: "password", Help: "the password or API token at the provider; it is visible in the shell history and can not be cleared",
			Validate: ddclientValidatePassword},
		{Name: "wildcard", Type: Bool, Help: "also update the wildcard *.hostname (where the service supports it)"},
		{Name: "zone", Help: "the DNS zone (Cloudflare, Hetzner, …), empty for none", Validate: ddclientValidateHostname},
		{Name: "hostnames", Type: List, Required: add, Help: "the host names to update", Validate: ddclientValidateHostnames},
		{Name: "ttl", Type: Int, Help: "the TTL of the records in seconds (1-604800, default 300)", Validate: ddclientNumber(1, 604800)},
		{Name: "check-ip", Required: add, Help: `how to find the address: a web service, if (address of interface) or if6, see "print options=check-ip"`,
			Validate: ddclientNotEmpty, Complete: ddclientCompleteOptions("checkip")},
		{Name: "interface", Help: "the interface (key like wan) of check-ip=if/if6, empty for none", Complete: ddclientCompleteOptions("interface")},
		{Name: "dynamic-ipv6-host", Help: "replace the host part of the IPv6 address by this, like ::1000, empty for none",
			Validate: ddclientValidateIpv6Host},
		{Name: "check-ip-timeout", Type: Int, Help: "the timeout of the address check in seconds (10-60, default 10)", Validate: ddclientNumber(10, 60)},
		{Name: "force-ssl", Type: Bool, Help: "use HTTPS for the provider (default yes)"},
	}
}

// ddclientAccountFields returns the given field arguments as API fields
func ddclientAccountFields(args *Args) ddclient.AccountFields {
	var fields = ddclient.AccountFields{}
	for _, names := range ddclientAccountFieldNames {
		var arg, field = names[0], names[1]
		if !args.Has(arg) {
			continue
		}
		switch arg {
		case "disabled":
			fields[field] = Flag(!args.Bool(arg))
		case "wildcard", "force-ssl":
			fields[field] = Flag(args.Bool(arg))
		case "hostnames":
			fields[field] = strings.Join(args.List(arg), ",")
		case "protocol", "service", "check-ip", "interface":
			fields[field] = strings.ToLower(strings.TrimSpace(args.String(arg)))
		case "password":
			fields[field] = args.String(arg)
		default:
			fields[field] = strings.TrimSpace(args.String(arg))
		}
	}
	return fields
}

// ddclientCheckOptions refuses values of the option fields OPNsense does not offer (an unknown service is refused
// by OPNsense with the misleading "A service type is required.")
func ddclientCheckOptions(api *ddclient.DdclientApi, fields ddclient.AccountFields) error {
	var given bool
	for _, field := range []string{"service", "checkip", "interface"} {
		if _, found := fields[field]; found {
			given = true
		}
	}
	if !given {
		return nil
	}
	var options, err = api.AccountOptions()
	if err != nil {
		return err
	}
	for _, check := range [][2]string{{"service", "service"}, {"checkip", "check-ip"}, {"interface", "interface"}} {
		var value, found = fields[check[0]]
		if !found || value == "" {
			continue
		}
		var known bool
		for _, option := range options[check[0]] {
			known = known || option.Key == value
		}
		if !known {
			return fmt.Errorf("%s: unknown value %q, see \"print options=%s\"", check[1], value, check[1])
		}
	}
	return nil
}

// ddclientCheckInterface refuses the interface check methods without an interface: OPNsense refuses it only for if,
// an if6 account without interface is saved but can never find an address
func ddclientCheckInterface(current ddclient.Account, fields ddclient.AccountFields) error {
	var checkip, interfaceKey = current.Checkip, current.Interface
	if value, found := fields["checkip"]; found {
		checkip = value
	}
	if value, found := fields["interface"]; found {
		interfaceKey = value
	}
	if (checkip == "if" || checkip == "if6") && interfaceKey == "" {
		return fmt.Errorf("check-ip=%s needs an interface, give interface= (a key like wan)", checkip)
	}
	return nil
}

// ddclientAccountCell renders the hostnames list of a table cell
func ddclientAccountCell(list string) string {
	return strings.ReplaceAll(list, ",", ", ")
}

func ddclientAccountPrint(c *Context, args *Args) error {
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	if args.Has("options") {
		return ddclientAccountPrintOptions(c, api, args)
	}
	accounts, raws, err := api.AccountList(args.String("search"))
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
	var uuids = make([]string, len(accounts))
	for i, account := range accounts {
		uuids[i] = account.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(accounts))
		for i, account := range accounts {
			if account.Protocol, err = api.AccountProtocol(account.Uuid); err != nil {
				return err
			}
			details[i] = ddclientAccountDetail(account)
		}
		c.Details(details, uuids)
		return nil
	}
	var rows = make([][]string, len(accounts))
	for i, account := range accounts {
		rows[i] = []string{YesNo(Flag(account.Enabled != "1")), account.Description, account.Service,
			ddclientAccountCell(account.Hostnames), account.Checkip, account.CurrentIp, account.CurrentMtime}
	}
	c.Items([]string{"DISABLED", "DESCRIPTION", "SERVICE", "HOSTNAMES", "CHECK-IP", "CURRENT-IP", "UPDATED"}, rows, uuids)
	return nil
}

func ddclientAccountPrintOptions(c *Context, api *ddclient.DdclientApi, args *Args) error {
	var options, err = api.AccountOptions()
	if err != nil {
		return err
	}
	var field = strings.ToLower(args.String("options"))
	if field == "check-ip" {
		field = "checkip"
	}
	var rows [][]string
	for _, option := range options[field] {
		if option.Key == "" {
			continue
		}
		if args.Bool("json") {
			if err := c.JSON(option); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{option.Key, option.Name})
	}
	if !args.Bool("json") {
		c.Table([]string{"KEY", "NAME"}, rows)
	}
	return nil
}

// ddclientAccountDetail are the fields of show and print detail, named like the arguments; the password only as
// whether one is stored
func ddclientAccountDetail(account ddclient.Account) [][2]string {
	var password = "(none)"
	if account.PasswordSet {
		password = "(set)"
	}
	var checkip = account.Checkip
	if account.CheckipName != "" && account.CheckipName != account.Checkip {
		checkip += " (" + account.CheckipName + ")"
	}
	return [][2]string{
		{"uuid", account.Uuid},
		{"description", account.Description},
		{"disabled", YesNo(Flag(account.Enabled != "1"))},
		{"service", account.Service},
		{"protocol", account.Protocol},
		{"server", account.Server},
		{"resource-id", account.ResourceId},
		{"username", account.Username},
		{"password", password},
		{"wildcard", YesNo(account.Wildcard)},
		{"zone", account.Zone},
		{"hostnames", account.Hostnames},
		{"ttl", account.Ttl},
		{"check-ip", checkip},
		{"interface", account.Interface},
		{"dynamic-ipv6-host", account.Dynipv6host},
		{"check-ip-timeout", account.CheckipTimeout},
		{"force-ssl", YesNo(account.ForceSsl)},
		{"current-ip", account.CurrentIp},
		{"updated", account.CurrentMtime},
	}
}

// ddclientAccountSelect loads the accounts and returns the one the selector refers to
func ddclientAccountSelect(c *Context, api *ddclient.DdclientApi, selector string) (ddclient.Account, []ddclient.Account, error) {
	var accounts, _, err = api.AccountList("")
	if err != nil {
		return ddclient.Account{}, nil, err
	}
	account, err := Select(c, selector, accounts, func(a ddclient.Account) string { return a.Uuid },
		func(a ddclient.Account) []string { return []string{a.Description} })
	return account, accounts, err
}

func ddclientAccountShow(c *Context, args *Args) error {
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	account, _, err := ddclientAccountSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if account.Protocol, err = api.AccountProtocol(account.Uuid); err != nil {
		return err
	}
	c.Fields(ddclientAccountDetail(account))
	return nil
}

// ddclientAccountsNamed returns the uuids of the accounts with this description, except except
func ddclientAccountsNamed(accounts []ddclient.Account, description string, except string) []string {
	var uuids []string
	for _, account := range accounts {
		if account.Uuid != except && strings.EqualFold(strings.TrimSpace(account.Description), strings.TrimSpace(description)) {
			uuids = append(uuids, account.Uuid)
		}
	}
	return uuids
}

func ddclientAccountAdd(c *Context, args *Args) error {
	var fields = ddclientAccountFields(args)
	if err := ddclientCheckInterface(ddclient.Account{}, fields); err != nil {
		return err
	}
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	if err := ddclientCheckOptions(api, fields); err != nil {
		return err
	}
	accounts, _, err := api.AccountList("")
	if err != nil {
		return err
	}
	var existing = ddclientAccountsNamed(accounts, fields["description"], "")
	switch {
	case len(existing) == 0:
	case !args.Bool("replace"):
		return fmt.Errorf("the account %q exists already (%s), change it with set or replace it with add ... replace",
			fields["description"], strings.Join(existing, ", "))
	case len(existing) > 1:
		return fmt.Errorf("several accounts are named %q (%s), change one with set or remove the duplicates",
			fields["description"], strings.Join(existing, ", "))
	default:
		var replacement = ddclient.AccountFields{}
		for name, value := range ddclient.AccountDefaults {
			replacement[name] = value
		}
		for name, value := range fields {
			replacement[name] = value
		}
		if err := api.AccountUpdate(existing[0], replacement); err != nil {
			return err
		}
		c.Infof("replaced the existing account %s", fields["description"])
		c.Println(existing[0])
		return nil
	}
	uuid, err := api.AccountCreate(fields)
	if err != nil {
		return err
	}
	c.Println(uuid)
	return nil
}

func ddclientAccountSet(c *Context, args *Args) error {
	var fields = ddclientAccountFields(args)
	if len(fields) == 0 {
		return errors.New(`set: nothing to change, give at least one field like hostnames= or ttl= (type "set ?" for help)`)
	}
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	account, accounts, err := ddclientAccountSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if description, renamed := fields["description"]; renamed {
		if others := ddclientAccountsNamed(accounts, description, account.Uuid); len(others) > 0 {
			return fmt.Errorf("another account named %q exists already (%s)", description, strings.Join(others, ", "))
		}
	}
	if err := ddclientCheckInterface(account, fields); err != nil {
		return err
	}
	if err := ddclientCheckOptions(api, fields); err != nil {
		return err
	}
	return api.AccountUpdate(account.Uuid, fields)
}

func ddclientAccountRemove(c *Context, args *Args) error {
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	account, _, err := ddclientAccountSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return api.AccountRemove(account.Uuid)
}

func ddclientAccountEnable(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = ddclientApi(c)
		if err != nil {
			return err
		}
		account, _, err := ddclientAccountSelect(c, api, args.String("item"))
		if err != nil {
			return err
		}
		return api.AccountSetEnabled(account.Uuid, enabled)
	}
}

func ddclientAccountRefresh(c *Context, args *Args) error {
	var api, err = ddclientApi(c)
	if err != nil {
		return err
	}
	account, _, err := ddclientAccountSelect(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if account.Enabled != "1" {
		c.Infof("the account %s is disabled, the service does not update it", account.Description)
	}
	return api.AccountForceRefresh(account.Uuid)
}
