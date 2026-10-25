package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
	"os"
	"strings"
)

// /vpn/openvpn/export: VPN > OpenVPN > Client Export. Items are the exportable servers (enabled server instances),
// selected by the # of print, their uuid (the export API calls it vpnid) or description. Each server stores export presets
// (set), download writes a client configuration for one of its accounts (client certificates of the server's CA)

const (
	openvpnExportServerHelp  = "the #, uuid or description of the server"
	openvpnExportAccountHelp = "the # of accounts, the certificate refid, its description or a linked user; none exports without certificate (user/password authentication only)"
	// openvpnExportAccountNone selects the export without client certificate
	openvpnExportAccountNone = "none"
)

// openvpnExportOption maps an argument to its export option
type openvpnExportOption struct {
	arg    string
	option string
}

// openvpnExportOptions are the stored presets, in the order of the GUI
var openvpnExportOptions = []openvpnExportOption{
	{"template", openvpn.ExportOptionTemplate},
	{"hostname", openvpn.ExportOptionHostname},
	{"port", openvpn.ExportOptionLocalPort},
	{"random-local-port", openvpn.ExportOptionRandomLocalPort},
	{"validate-server-cn", openvpn.ExportOptionValidateServerCn},
	{"cryptoapi", openvpn.ExportOptionCryptoapi},
	{"auth-nocache", openvpn.ExportOptionAuthNocache},
	{"static-challenge", openvpn.ExportOptionStaticChallenge},
	{"plain-config", openvpn.ExportOptionPlainConfig},
}

// openvpnExportP12Password is the download only option
var openvpnExportP12Password = openvpnExportOption{"p12-password", openvpn.ExportOptionP12Password}

func openvpnExportOptionArgs() []Arg {
	return []Arg{
		{Name: "template", Complete: openvpnExportCompleteTemplates,
			Help: "export type, see templates: PlainOpenVPN (one .ovpn file), ArchiveOpenVPN (zip with pkcs12), ViscosityVisz"},
		{Name: "hostname", Type: List, Help: "address(es) or host name(s) the client connects to, comma separated"},
		{Name: "port", Validate: ValidatePort, Help: "port the client connects to (empty: the server's port)"},
		{Name: "random-local-port", Type: Bool, Help: "use a random local source port (lport 0), so several clients can run at once"},
		{Name: "validate-server-cn", Type: Bool, Help: "verify the subject of the server certificate (verify-x509-name)"},
		{Name: "cryptoapi", Type: Bool, Help: "load the client certificate from the Windows certificate store"},
		{Name: "auth-nocache", Type: Bool, Help: "do not cache the password in memory (with user authentication)"},
		{Name: "static-challenge", Type: Bool, Help: "ask for the one time password separately"},
		{Name: "plain-config", Help: `custom configuration appended to the file, \n separates lines`},
	}
}

func init() {
	var menu = Root.Menu("vpn/openvpn/export")
	menu.Help = "client export: configuration files for the clients of the OpenVPN servers (VPN > OpenVPN > Client Export)"

	var server = Arg{Name: "item", Positional: true, Required: true, Help: openvpnExportServerHelp, Complete: openvpnExportCompleteServers}
	var printArgs = func(what string) []Arg {
		return []Arg{
			{Name: "json", Type: Bool, Help: "one JSON object per line"},
			{Name: "search", Help: "only " + what + " containing this text (case-insensitive)"},
		}
	}

	menu.Add(
		&Command{
			Name: "print",
			Help: "list the servers configurations can be exported for, with their export presets",
			Long: `Only enabled server instances can be exported (OPNsense lists no disabled ones).`,
			Args: append(printArgs("servers"), Arg{Name: "detail", Type: Bool, Help: "show all export presets of every server"}),
			Run:  openvpnExportPrint,
		},
		&Command{
			Name: "show",
			Help: "show the export presets of a server",
			Args: []Arg{server},
			Run:  openvpnExportShow,
		},
		&Command{
			Name: "accounts",
			Help: "list the accounts of a server: the client certificates of its CA, with the users they belong to",
			Long: `The # refers to this list of the server in download account=.`,
			Args: append([]Arg{server}, printArgs("accounts")...),
			Run:  openvpnExportAccounts,
		},
		&Command{
			Name: "templates",
			Help: "list the export types and the options they use",
			Args: []Arg{{Name: "json", Type: Bool, Help: "one JSON object per line"}},
			Run:  openvpnExportTemplates,
		},
		&Command{
			Name: "set",
			Help: "change export presets of a server, the others are kept",
			Long: `The presets are used by download (and the GUI). A hostname is required before the first download.`,
			Args: append([]Arg{server}, openvpnExportOptionArgs()...),
			Check: func(args *Args) error {
				for _, option := range openvpnExportOptions {
					if args.Has(option.arg) {
						return nil
					}
				}
				return errors.New(`nothing to change, give at least one preset like hostname= (type "set ?" for help)`)
			},
			Run: openvpnExportSet,
		},
		&Command{
			Name: "download",
			Help: "save the client configuration of an account",
			Long: `The file contains the client's private key, so it is written (mode 0600) to the file name OPNsense
suggests (e.g. <server>_<client>.ovpn) in the current directory unless file= is given; file=- writes to
stdout. An existing file is only overwritten with overwrite.

The presets of the server are used, options given here override them. Like the GUI, OPNsense STORES the
options as presets of the server (except p12-password). Without a template preset, PlainOpenVPN is used:
one .ovpn file with the certificates and keys inline.`,
			Args: append(append([]Arg{
				server,
				{Name: "account", Required: true, Help: openvpnExportAccountHelp, Complete: openvpnExportCompleteAccounts},
				{Name: "file", Help: "file to write, - for stdout (default: the name suggested by OPNsense)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			}, openvpnExportOptionArgs()...),
				Arg{Name: "p12-password", Help: "password protecting the pkcs12 file (ArchiveOpenVPN, ViscosityVisz), not stored"}),
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: openvpnExportDownload,
		},
	)
}

// --- servers

func openvpnExportServerNames(server openvpn.ExportServer) []string {
	return []string{server.Description(), server.Name}
}

// openvpnExportSelectServer resolves a server selector against the exportable servers
func openvpnExportSelectServer(c *Context, api *openvpn.OpenVPNApi, selector string) (openvpn.ExportServer, error) {
	var servers, err = api.ExportServers()
	if err != nil {
		return openvpn.ExportServer{}, err
	}
	var server, selectErr = Select(c, selector, servers, func(s openvpn.ExportServer) string { return s.Vpnid }, openvpnExportServerNames)
	if coreapi.IsNotFound(selectErr) {
		return server, fmt.Errorf("%w (only enabled OpenVPN servers can be exported)", selectErr)
	}
	return server, selectErr
}

// openvpnExportAuth renders the authentication mode of a server
func openvpnExportAuth(mode string) string {
	switch mode {
	case "", "server_tls":
		return "certificate"
	case "server_user":
		return "user"
	case "server_tls_user":
		return "certificate+user"
	case "p2p_tls":
		return "p2p certificate"
	case "p2p_shared_key":
		return "p2p shared key"
	}
	return mode
}

// openvpnExportShowValue renders a preset for print / show
func openvpnExportShowValue(option string, value string) string {
	if openvpn.ExportIsBoolean(option) {
		return YesNo(value)
	}
	if option == openvpn.ExportOptionPlainConfig {
		return strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\n", `\n`)
	}
	return value
}

func openvpnExportFields(server openvpn.ExportServer) [][2]string {
	var fields = [][2]string{
		{"uuid", server.Vpnid},
		{"name", server.Name},
		{"auth", openvpnExportAuth(server.Mode)},
	}
	for _, option := range openvpnExportOptions {
		fields = append(fields, [2]string{option.arg, openvpnExportShowValue(option.option, server.Presets[option.option])})
	}
	return fields
}

func openvpnExportPrint(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	servers, err := api.ExportServers()
	if err != nil {
		return err
	}
	if search := strings.ToLower(args.String("search")); search != "" {
		servers = coreapi.Filter(servers, func(server openvpn.ExportServer) bool {
			for _, value := range []string{server.Vpnid, server.Name, server.Presets[openvpn.ExportOptionHostname], server.Presets[openvpn.ExportOptionTemplate]} {
				if strings.Contains(strings.ToLower(value), search) {
					return true
				}
			}
			return false
		})
	}

	var vpnids = make([]string, 0, len(servers))
	for _, server := range servers {
		vpnids = append(vpnids, server.Vpnid)
	}
	switch {
	case args.Bool("json"):
		for _, server := range servers {
			if err := c.JSON(server.Raw); err != nil {
				return err
			}
		}
		return nil
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(servers))
		for _, server := range servers {
			items = append(items, openvpnExportFields(server))
		}
		c.Details(items, vpnids)
	default:
		var rows = make([][]string, 0, len(servers))
		for _, server := range servers {
			rows = append(rows, []string{
				server.Description(),
				server.Listen(),
				openvpnExportAuth(server.Mode),
				server.Presets[openvpn.ExportOptionHostname],
				server.Presets[openvpn.ExportOptionLocalPort],
				server.Presets[openvpn.ExportOptionTemplate],
				server.Vpnid,
			})
		}
		c.Items([]string{"DESCRIPTION", "LISTEN", "AUTH", "HOSTNAME", "PORT", "TEMPLATE", "UUID"}, rows, vpnids)
	}
	if len(servers) == 0 && args.String("search") == "" {
		c.Infof("no exportable servers, only enabled OpenVPN server instances can be exported")
	}
	return nil
}

func openvpnExportShow(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	server, err := openvpnExportSelectServer(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(openvpnExportFields(server))
	return nil
}

// --- accounts

// openvpnExportAccountsContext is c with the accounts of server vpnid as "menu": the # of accounts is remembered
// per server, apart from the # of print (the servers). The framework keys the last print by c.Menu.Path(), so
// this is a menu that is never registered (not in help, completion or navigation), only its path matters:
// /vpn/openvpn/export/accounts/<uuid>. A registered sub menu (Menu.Sub) would show up as an empty menu in help
func openvpnExportAccountsContext(c *Context, vpnid string) *Context {
	var derived = *c
	derived.Menu = &Menu{Name: "accounts/" + vpnid, parent: c.Menu}
	return &derived
}

func openvpnExportAccounts(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	server, err := openvpnExportSelectServer(c, api, args.String("item"))
	if err != nil {
		return err
	}
	accounts, err := api.ExportAccounts(server.Vpnid)
	if err != nil {
		return err
	}
	if search := strings.ToLower(args.String("search")); search != "" {
		accounts = coreapi.Filter(accounts, func(account openvpn.ExportAccount) bool {
			for _, value := range append([]string{account.Certref, account.Description}, account.Users...) {
				if strings.Contains(strings.ToLower(value), search) {
					return true
				}
			}
			return false
		})
	}

	if args.Bool("json") {
		for _, account := range accounts {
			if err := c.JSON(account); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(accounts))
	var certrefs = make([]string, 0, len(accounts))
	for _, account := range accounts {
		rows = append(rows, []string{account.Description, strings.Join(account.Users, ","), account.Certref})
		certrefs = append(certrefs, account.Certref)
	}
	openvpnExportAccountsContext(c, server.Vpnid).Items([]string{"CERTIFICATE", "USERS", "REFID"}, rows, certrefs)
	if len(accounts) == 0 && args.String("search") == "" {
		c.Infof("no client certificates of the server's CA, download account=none exports without certificate")
	}
	return nil
}

// openvpnExportSelectAccount resolves an account selector of server, "" is the export without certificate
func openvpnExportSelectAccount(c *Context, api *openvpn.OpenVPNApi, server openvpn.ExportServer, selector string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(selector), openvpnExportAccountNone) {
		return "", nil
	}
	var accounts, err = api.ExportAccounts(server.Vpnid)
	if err != nil {
		return "", err
	}
	var account, selectErr = Select(openvpnExportAccountsContext(c, server.Vpnid), selector, accounts,
		func(a openvpn.ExportAccount) string { return a.Certref },
		func(a openvpn.ExportAccount) []string { return append([]string{a.Description}, a.Users...) })
	if selectErr != nil {
		if coreapi.IsNotFound(selectErr) {
			return "", fmt.Errorf("account of %s: %w", server.Name, selectErr)
		}
		return "", selectErr
	}
	return account.Certref, nil
}

// --- templates

func openvpnExportArgOf(option string) string {
	for _, known := range append([]openvpnExportOption{openvpnExportP12Password}, openvpnExportOptions...) {
		if known.option == option {
			return known.arg
		}
	}
	return option
}

func openvpnExportTemplates(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	templates, err := api.ExportTemplates()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, template := range templates {
			if err := c.JSON(template); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(templates))
	for _, template := range templates {
		var options = make([]string, 0, len(template.SupportedOptions))
		for _, option := range template.SupportedOptions {
			options = append(options, openvpnExportArgOf(option))
		}
		rows = append(rows, []string{template.Name, template.Description, strings.Join(options, ",")})
	}
	c.Table([]string{"NAME", "DESCRIPTION", "OPTIONS"}, rows)
	return nil
}

// openvpnExportResolveTemplate returns the template named name (case-insensitive)
func openvpnExportResolveTemplate(templates []openvpn.ExportTemplate, name string) (openvpn.ExportTemplate, error) {
	var names = make([]string, 0, len(templates))
	for _, template := range templates {
		if strings.EqualFold(template.Name, strings.TrimSpace(name)) {
			return template, nil
		}
		names = append(names, template.Name)
	}
	return openvpn.ExportTemplate{}, fmt.Errorf("template: unknown export type %q, use one of %s", name, strings.Join(names, ", "))
}

// --- set / download

// openvpnExportGivenOptions collects the given option arguments (of options) as export options
func openvpnExportGivenOptions(args *Args, options []openvpnExportOption) openvpn.ExportOptions {
	var given = openvpn.ExportOptions{}
	for _, option := range options {
		if !args.Has(option.arg) {
			continue
		}
		var value = args.String(option.arg)
		switch {
		case openvpn.ExportIsBoolean(option.option):
			value = Flag(args.Bool(option.arg))
		case option.option == openvpn.ExportOptionHostname:
			value = strings.Join(args.List(option.arg), ",")
		case option.option == openvpn.ExportOptionPlainConfig:
			value = strings.ReplaceAll(value, `\n`, "\n")
		}
		given[option.option] = value
	}
	return given
}

// openvpnExportCanonicalTemplate replaces a given template by its name as OPNsense spells it, template= (clearing
// the preset) is kept
func openvpnExportCanonicalTemplate(templates []openvpn.ExportTemplate, options openvpn.ExportOptions) error {
	if name := options[openvpn.ExportOptionTemplate]; name != "" {
		var template, err = openvpnExportResolveTemplate(templates, name)
		if err != nil {
			return err
		}
		options[openvpn.ExportOptionTemplate] = template.Name
	}
	return nil
}

// openvpnExportCheckOptions checks that the given options apply to the template the download uses (e.g.
// p12-password does not apply to PlainOpenVPN)
func openvpnExportCheckOptions(templates []openvpn.ExportTemplate, options openvpn.ExportOptions, preset string) error {
	var name = options[openvpn.ExportOptionTemplate]
	if name == "" {
		name = preset
	}
	if name == "" {
		name = openvpn.ExportDefaultTemplate
	}
	var template, err = openvpnExportResolveTemplate(templates, name)
	if err != nil {
		return nil // a stale preset, OPNsense reports it
	}
	for option := range options {
		var appliesSomewhere = false
		for _, other := range templates {
			appliesSomewhere = appliesSomewhere || other.Supports(option)
		}
		if appliesSomewhere && !template.Supports(option) {
			return fmt.Errorf("%s does not apply to the template %s", openvpnExportArgOf(option), template.Name)
		}
	}
	return nil
}

// openvpnExportError renames the option names of a validation error to the argument names
func openvpnExportError(err error) error {
	var validation *coreapi.ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	var renamed = make(map[string]string, len(validation.Validations))
	for field, message := range validation.Validations {
		renamed[openvpnExportArgOf(field)] = message
	}
	return &coreapi.ValidationError{Validations: renamed}
}

func openvpnExportSet(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	server, err := openvpnExportSelectServer(c, api, args.String("item"))
	if err != nil {
		return err
	}
	var options = openvpnExportGivenOptions(args, openvpnExportOptions)
	if options[openvpn.ExportOptionTemplate] != "" {
		var templates, templatesErr = api.ExportTemplates()
		if templatesErr != nil {
			return templatesErr
		}
		if err := openvpnExportCanonicalTemplate(templates, options); err != nil {
			return err
		}
	}
	_, err = api.ExportStorePresets(server.Vpnid, options)
	return openvpnExportError(err)
}

func openvpnExportDownload(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	server, err := openvpnExportSelectServer(c, api, args.String("item"))
	if err != nil {
		return err
	}
	certref, err := openvpnExportSelectAccount(c, api, server, args.String("account"))
	if err != nil {
		return err
	}
	var options = openvpnExportGivenOptions(args, append(append([]openvpnExportOption{}, openvpnExportOptions...), openvpnExportP12Password))
	if options[openvpn.ExportOptionTemplate] == "" {
		delete(options, openvpn.ExportOptionTemplate) // template= is the preset
	}
	templates, err := api.ExportTemplates()
	if err != nil {
		return err
	}
	if err := openvpnExportCanonicalTemplate(templates, options); err != nil {
		return err
	}
	if err := openvpnExportCheckOptions(templates, options, server.Presets[openvpn.ExportOptionTemplate]); err != nil {
		return err
	}

	file, err := api.ExportDownload(server.Vpnid, certref, options)
	if err != nil {
		return openvpnExportError(err)
	}
	if file.PresetsChanged {
		c.Infof("the export options were stored as presets of %s", server.Name)
	}

	var output = args.String("file")
	if output == "-" {
		_, err = c.Out.Write(file.Content)
		return err
	}
	var filename = file.Filename
	if output != "" {
		filename = output
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	handle, err := os.OpenFile(filename, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := handle.Write(file.Content); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(file.Content))
	return nil
}

// --- completion, errors are ignored

func openvpnExportCompleteServers(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var servers, listErr = api.ExportServers()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, server.Description())
	}
	return names
}

// openvpnExportCompleteAccounts completes the accounts of all servers (the completion does not know the server)
func openvpnExportCompleteAccounts(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var servers, listErr = api.ExportServers()
	if listErr != nil {
		return nil
	}
	var names = []string{openvpnExportAccountNone}
	var seen = map[string]bool{openvpnExportAccountNone: true}
	for _, server := range servers {
		var accounts, accountsErr = api.ExportAccounts(server.Vpnid)
		if accountsErr != nil {
			continue
		}
		for _, account := range accounts {
			for _, name := range append([]string{account.Description}, account.Users...) {
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func openvpnExportCompleteTemplates(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var templates, listErr = api.ExportTemplates()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(templates))
	for _, template := range templates {
		names = append(names, template.Name)
	}
	return names
}
