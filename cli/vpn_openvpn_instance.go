package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// /vpn/openvpn/instance: the OpenVPN servers and clients of VPN > OpenVPN > Instances. Items are selected by
// the # of print, the uuid or the description (the natural key of add). References to the trust store (ca,
// cert, crl), groups, authentication servers and CARP addresses are given by their name (or key) and resolved
// with the option lists of instances/get, tls-key by the description of a static key. Passwords and the
// auth token secret are never shown, not even in json

const (
	openvpnInstanceItemHelp  = "the #, uuid or description of the instance"
	openvpnInstanceApplyHint = `Changes are only saved, run "/vpn/openvpn/instance apply" to apply them.`
	openvpnInstanceMasked    = "********"
)

// how an argument value maps to the API value
type openvpnInstanceKind int

const (
	openvpnInstancePlain     openvpnInstanceKind = iota
	openvpnInstanceFlag                          // yes/no as 1/0
	openvpnInstanceList                          // comma separated
	openvpnInstanceRef                           // option key, given by key or option description (trust store, groups, ...)
	openvpnInstanceRefList                       // several option keys, like openvpnInstanceRef
	openvpnInstanceStaticKey                     // static key uuid, given by uuid or description
	openvpnInstanceStrictCN                      // no / yes / case-insensitive as 0 / 1 / 2
	openvpnInstanceDisabled                      // the disabled argument for the enabled field
	openvpnInstanceSecret                        // plain, never shown
)

type openvpnInstanceField struct {
	Arg
	field string
	kind  openvpnInstanceKind
}

var (
	openvpnInstanceDigests = []string{"BLAKE2b512", "BLAKE2s256", "MD4", "MD5", "MD5-SHA1", "RIPEMD160", "SHA1", "SHA224",
		"SHA256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHA384", "SHA512", "SHA512-224", "SHA512-256",
		"SHAKE128", "SHAKE256", "whirlpool", "none"}
	openvpnInstanceCiphers = []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305",
		"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "AES-128-CFB", "AES-192-CFB", "AES-256-CFB", "AES-128-CFB1",
		"AES-192-CFB1", "AES-256-CFB1", "AES-128-CFB8", "AES-192-CFB8", "AES-256-CFB8", "AES-128-OFB", "AES-192-OFB",
		"AES-256-OFB"}
	openvpnInstanceStrictCNValues = []string{"no", "yes", "case-insensitive"}
)

// openvpnInstanceFields are the field arguments of add and set, in the order of show
func openvpnInstanceFields(add bool) []openvpnInstanceField {
	var required = func(arg Arg) Arg {
		arg.Required = add
		return arg
	}
	return []openvpnInstanceField{
		{required(Arg{Name: "description", Help: "description, also the name of the instance", Validate: openvpnInstanceValidateDescription(add)}), "description", openvpnInstancePlain},
		{Arg{Name: "disabled", Type: Bool, Help: "keep the instance, but don't run it"}, "enabled", openvpnInstanceDisabled},
		{Arg{Name: "role", Values: []string{"server", "client"}, Validate: openvpnInstanceNotEmpty, Help: "server (default) or client"}, "role", openvpnInstancePlain},
		{Arg{Name: "vpn-id", Type: Int, Help: "the instance number, used in the device name (ovpns<id>); assigned on add",
			Validate: openvpnInstanceValidateVpnId}, "vpnid", openvpnInstancePlain},
		{Arg{Name: "protocol", Values: []string{"udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"}, Validate: openvpnInstanceNotEmpty, Help: "transport protocol, default udp"}, "proto", openvpnInstancePlain},
		{Arg{Name: "port", Type: Int, Help: "port to listen on (server) or bind to (client), empty for the default", Validate: ValidatePort}, "port", openvpnInstancePlain},
		{Arg{Name: "local", Help: "IP address to bind to, empty for all", Validate: ValidateIP}, "local", openvpnInstancePlain},
		{Arg{Name: "remote", Type: List, Help: "client: servers to connect to, host or host:port"}, "remote", openvpnInstanceList},
		{Arg{Name: "dev-type", Values: []string{"tun", "tap", "ovpn"}, Validate: openvpnInstanceNotEmpty, Help: "tun (default), tap or ovpn (DCO)"}, "dev_type", openvpnInstancePlain},
		{Arg{Name: "topology", Values: []string{"subnet", "net30", "p2p"}, Validate: openvpnInstanceNotEmpty, Help: "tunnel topology, default subnet"}, "topology", openvpnInstancePlain},
		{Arg{Name: "tunnel-network", Help: "server: IPv4 tunnel network in CIDR notation (e.g. 10.8.0.0/24)", Validate: openvpnInstanceValidateNetwork(4)}, "server", openvpnInstancePlain},
		{Arg{Name: "tunnel-network6", Help: "server: IPv6 tunnel network in CIDR notation (e.g. fd00:8::/64)", Validate: openvpnInstanceValidateNetwork(6)}, "server_ipv6", openvpnInstancePlain},
		{Arg{Name: "no-pool", Type: Bool, Help: "server: no address pool for the clients"}, "nopool", openvpnInstanceFlag},
		{Arg{Name: "bridge-gateway", Help: "tap server: bridge gateway in CIDR notation"}, "bridge_gateway", openvpnInstancePlain},
		{Arg{Name: "bridge-pool", Help: "tap server: bridge DHCP range, e.g. 10.0.0.100-10.0.0.200"}, "bridge_pool", openvpnInstancePlain},
		{Arg{Name: "remote-networks", Type: List, Help: "networks behind the peer, routed through the tunnel (CIDR)", Validate: openvpnInstanceValidateNetworks}, "route", openvpnInstanceList},
		{Arg{Name: "local-networks", Type: List, Help: "server: networks behind the server, pushed to the clients as routes (CIDR)", Validate: openvpnInstanceValidateNetworks}, "push_route", openvpnInstanceList},
		{Arg{Name: "excluded-networks", Type: List, Help: "server: networks the clients should not route through the tunnel (CIDR)",
			Validate: openvpnInstanceValidateNetworks}, "push_excluded_routes", openvpnInstanceList},
		{Arg{Name: "ca", Help: "certificate authority (its description), empty to use the one of the certificate",
			Complete: openvpnInstanceRefNames("ca")}, "ca", openvpnInstanceRef},
		{Arg{Name: "cert", Help: "certificate (its description)", Complete: openvpnInstanceRefNames("cert")}, "cert", openvpnInstanceRef},
		{Arg{Name: "crl", Help: "certificate revocation list (its description)", Complete: openvpnInstanceRefNames("crl")}, "crl", openvpnInstanceRef},
		{Arg{Name: "cert-depth", Values: []string{"1", "2", "3", "4", "5"}, Help: "server: maximum client certificate chain depth, empty: don't check"}, "cert_depth", openvpnInstancePlain},
		{Arg{Name: "verify-client-cert", Values: []string{"none", "require"}, Validate: openvpnInstanceNotEmpty, Help: "server: require a client certificate (default require)"}, "verify_client_cert", openvpnInstancePlain},
		{Arg{Name: "remote-cert-tls", Type: Bool, Help: "require the peer certificate to be signed for the other role"}, "remote_cert_tls", openvpnInstanceFlag},
		{Arg{Name: "use-ocsp", Type: Bool, Help: "check the peer certificate with OCSP"}, "use_ocsp", openvpnInstanceFlag},
		{Arg{Name: "tls-key", Help: "static key (its description) for tls-auth / tls-crypt, empty for none", Complete: openvpnStaticKeyNames}, "tls_key", openvpnInstanceStaticKey},
		{Arg{Name: "auth", Values: openvpnInstanceDigests, Help: "message digest for packet authentication, empty for the OpenVPN default"}, "auth", openvpnInstancePlain},
		{Arg{Name: "data-ciphers", Type: List, Values: openvpnInstanceCiphers, Help: "allowed data channel ciphers, empty for the default"}, "data-ciphers", openvpnInstanceList},
		{Arg{Name: "data-ciphers-fallback", Values: openvpnInstanceCiphers, Help: "cipher for peers without cipher negotiation"}, "data-ciphers-fallback", openvpnInstancePlain},
		{Arg{Name: "authentication", Type: List, Help: "server: authentication servers for user authentication, e.g. \"Local Database\"",
			Complete: openvpnInstanceRefNames("authmode")}, "authmode", openvpnInstanceRefList},
		{Arg{Name: "local-group", Help: "server: only members of this group may connect", Complete: openvpnInstanceRefNames("local_group")}, "local_group", openvpnInstanceRef},
		{Arg{Name: "username-as-cn", Type: Bool, Help: "server: use the authenticated username as common name"}, "username_as_common_name", openvpnInstanceFlag},
		{Arg{Name: "strict-user-cn", Values: openvpnInstanceStrictCNValues, Validate: openvpnInstanceNotEmpty, Help: "server: the username must match the certificate common name"}, "strictusercn", openvpnInstanceStrictCN},
		{Arg{Name: "provision-exclusive", Type: Bool, Help: "server: require the tunnel address to come from a client specific override or the auth server"}, "provision_exclusive", openvpnInstanceFlag},
		{Arg{Name: "username", Help: "client: username for the server", Validate: openvpnInstanceValidateText}, "username", openvpnInstancePlain},
		{Arg{Name: "password", Help: "client: password for the server (never shown)", Validate: openvpnInstanceValidateText}, "password", openvpnInstanceSecret},
		{Arg{Name: "max-clients", Type: Int, Help: "server: maximum number of concurrent clients", Validate: openvpnInstanceValidateMin(1)}, "maxclients", openvpnInstancePlain},
		{Arg{Name: "keepalive-interval", Type: Int, Help: "seconds between pings, needs keepalive-timeout", Validate: openvpnInstanceValidateMin(0)}, "keepalive_interval", openvpnInstancePlain},
		{Arg{Name: "keepalive-timeout", Type: Int, Help: "seconds without answer until the peer is down, at least twice the interval",
			Validate: openvpnInstanceValidateMin(1)}, "keepalive_timeout", openvpnInstancePlain},
		{Arg{Name: "reneg-sec", Type: Int, Help: "seconds until the data channel key is renegotiated, 0 to disable", Validate: openvpnInstanceValidateMin(0)}, "reneg-sec", openvpnInstancePlain},
		{Arg{Name: "auth-gen-token", Type: Int, Help: "server: lifetime of the generated auth tokens in seconds", Validate: openvpnInstanceValidateMin(0)}, "auth-gen-token", openvpnInstancePlain},
		{Arg{Name: "auth-gen-token-renewal", Type: Int, Help: "server: auth token renewal time in seconds", Validate: openvpnInstanceValidateMin(0)}, "auth-gen-token-renewal", openvpnInstancePlain},
		{Arg{Name: "auth-gen-token-secret", Help: "server: auth token secret (never shown)", Validate: openvpnInstanceValidateKey}, "auth-gen-token-secret", openvpnInstanceSecret},
		{Arg{Name: "redirect-gateway", Type: List, Values: []string{"local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4"},
			Help: "server: redirect the default gateway of the clients through the tunnel"}, "redirect_gateway", openvpnInstanceList},
		{Arg{Name: "route-metric", Type: Int, Help: "client: metric of the routes", Validate: ValidateRange(0, 65535)}, "route_metric", openvpnInstancePlain},
		{Arg{Name: "register-dns", Type: Bool, Help: "server: make Windows clients register in DNS"}, "register_dns", openvpnInstanceFlag},
		{Arg{Name: "dns-domain", Type: List, Help: "server: DNS default domain pushed to the clients", Validate: openvpnClientOverrideValidateHostnames}, "dns_domain", openvpnInstanceList},
		{Arg{Name: "dns-domain-search", Type: List, Help: "server: DNS search domains pushed to the clients", Validate: openvpnClientOverrideValidateHostnames}, "dns_domain_search", openvpnInstanceList},
		{Arg{Name: "dns-servers", Type: List, Help: "server: DNS servers pushed to the clients", Validate: ValidateIPList}, "dns_servers", openvpnInstanceList},
		{Arg{Name: "ntp-servers", Type: List, Help: "server: NTP servers pushed to the clients", Validate: ValidateIPList}, "ntp_servers", openvpnInstanceList},
		{Arg{Name: "flags", Type: List, Values: []string{"block-ipv6", "client-to-client", "duplicate-cn", "float", "passtos",
			"persist-remote-ip", "remote-random", "route-noexec", "route-nopull", "explicit-exit-notify", "fast-io"},
			Help: "OpenVPN options to set"}, "various_flags", openvpnInstanceList},
		{Arg{Name: "push-flags", Type: List, Values: []string{"block-ipv6", "block-outside-dns", "register-dns", "explicit-exit-notify"},
			Help: "server: options pushed to the clients"}, "various_push_flags", openvpnInstanceList},
		{Arg{Name: "push-inactive", Type: Int, Help: "server: seconds of inactivity until clients disconnect", Validate: openvpnInstanceValidateMin(0)}, "push_inactive", openvpnInstancePlain},
		{Arg{Name: "tun-mtu", Type: Int, Help: "MTU of the tunnel device", Validate: ValidateRange(60, 65535)}, "tun_mtu", openvpnInstancePlain},
		{Arg{Name: "fragment", Type: Int, Help: "fragment UDP packets larger than this size, 0 to disable", Validate: ValidateRange(0, 65528)}, "fragment", openvpnInstancePlain},
		{Arg{Name: "mssfix", Type: Bool, Help: "limit the TCP MSS to the tunnel MTU"}, "mssfix", openvpnInstanceFlag},
		{Arg{Name: "port-share", Help: "tcp server: forward non OpenVPN traffic to this ip:port"}, "port-share", openvpnInstancePlain},
		{Arg{Name: "http-proxy", Help: "client: connect through this HTTP proxy host:port"}, "http-proxy", openvpnInstancePlain},
		{Arg{Name: "verify-x509-name", Help: "client: accept only a server certificate with this name", Validate: openvpnInstanceValidateText}, "verify-x509-name", openvpnInstancePlain},
		{Arg{Name: "carp-depend-on", Help: "client: run only while this CARP address is master", Complete: openvpnInstanceRefNames("carp_depend_on")}, "carp_depend_on", openvpnInstanceRef},
		{Arg{Name: "ifconfig-pool-persist", Type: Bool, Help: "server: keep the client addresses over restarts"}, "ifconfig-pool-persist", openvpnInstanceFlag},
		{Arg{Name: "compress-migrate", Type: Bool, Help: "server: migrate clients with compression to no compression"}, "compress_migrate", openvpnInstanceFlag},
		{Arg{Name: "verbosity", Type: Int, Help: "log verbosity 0-11, default 3", Validate: openvpnInstanceValidateVerbosity}, "verb", openvpnInstancePlain},
	}
}

func openvpnInstanceArgs(fields []openvpnInstanceField) []Arg {
	var args = make([]Arg, len(fields))
	for i, field := range fields {
		args[i] = field.Arg
	}
	return args
}

func init() {
	var menu = Root.Menu("vpn/openvpn/instance")
	menu.Help = "OpenVPN servers and clients (VPN > OpenVPN > Instances)"
	var item = Arg{Name: "item", Help: openvpnInstanceItemHelp, Positional: true, Required: true, Complete: openvpnInstanceItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the instances", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every instance"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (secrets masked)"},
			{Name: "search", Help: "only instances where any field contains this text"},
		}, Run: openvpnInstancePrint},
		&Command{Name: "show", Help: "show all fields of one instance", Args: []Arg{item}, Run: openvpnInstanceShow},
		&Command{Name: "add", Help: "add an instance, prints its uuid",
			Long: `Fields not given get the OPNsense defaults (role=server, protocol=udp, dev-type=tun, topology=subnet,
verify-client-cert=require, enabled). A server needs a tunnel network (tunnel-network= or tunnel-network6=) and a certificate
or authentication= with verify-client-cert=none; a client needs remote= and a ca= or cert=. The description names
the instance: if it exists already, add fails unless replace is given, then that instance is replaced completely
(fields not given are reset to the defaults, the vpn-id is kept).
` + openvpnInstanceApplyHint,
			Args:  append(openvpnInstanceArgs(openvpnInstanceFields(true)), Arg{Name: "replace", Type: Bool, Help: "replace the instance with the same description"}),
			Check: openvpnInstanceCheck,
			Run:   openvpnInstanceAdd},
		&Command{Name: "set", Help: "change fields of an instance, the others are kept",
			Long: `description= renames the instance, an empty value clears a field (e.g. tls-key= or local-networks=).
` + openvpnInstanceApplyHint,
			Args:  append([]Arg{item}, openvpnInstanceArgs(openvpnInstanceFields(false))...),
			Check: openvpnInstanceCheck,
			Run:   openvpnInstanceSet},
		&Command{Name: "remove", Help: "remove an instance, refused while client specific overrides use it",
			Long: "A running instance is stopped by apply.\n" + openvpnInstanceApplyHint,
			Args: []Arg{item}, Run: openvpnInstanceRemove},
		&Command{Name: "enable", Help: "enable an instance", Long: openvpnInstanceApplyHint, Args: []Arg{item}, Run: openvpnInstanceEnabler(true)},
		&Command{Name: "disable", Help: "disable an instance", Long: openvpnInstanceApplyHint, Args: []Arg{item}, Run: openvpnInstanceEnabler(false)},
		&Command{Name: "start", Help: "start an enabled instance", Args: []Arg{item}, Run: openvpnInstanceService("start")},
		&Command{Name: "stop", Help: "stop an enabled instance (until the next apply or restart)", Args: []Arg{item},
			Confirm: "This stops the OpenVPN instance and disconnects its tunnels.", Run: openvpnInstanceService("stop")},
		&Command{Name: "restart", Help: "restart an enabled instance", Args: []Arg{item},
			Confirm: "This restarts the OpenVPN instance and briefly disconnects its tunnels.", Run: openvpnInstanceService("restart")},
		&Command{Name: "apply", Help: "apply the saved instances: (re)start changed and enabled ones, stop the others",
			Run: openvpnInstanceApply},
	)
}

// --- validation

func openvpnInstanceValidateText(value string) error {
	for _, char := range value {
		if char < ' ' || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func openvpnInstanceNotEmpty(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	return nil
}

// openvpnInstanceValidateDescription demands a description for add (it names the instance), set may clear it
func openvpnInstanceValidateDescription(add bool) func(string) error {
	return func(value string) error {
		if add && strings.TrimSpace(value) == "" {
			return errors.New("must not be empty, it names the instance")
		}
		return openvpnInstanceValidateText(value)
	}
}

func openvpnInstanceValidateVpnId(value string) error {
	if value == "" {
		return errors.New("must not be empty, leave it out to keep the current one")
	}
	return openvpnInstanceValidateMin(1)(value)
}

func openvpnInstanceValidateVerbosity(value string) error {
	if value == "" {
		return errors.New("must not be empty, the default is 3")
	}
	return ValidateRange(0, 11)(value)
}

// openvpnInstanceValidateMin accepts whole numbers >= min (or "" to clear)
func openvpnInstanceValidateMin(min int) func(string) error {
	return func(value string) error {
		if err := ValidateRange(min, 1<<31-1)(value); err != nil {
			return fmt.Errorf("must be a number of at least %d, got %q", min, value)
		}
		return nil
	}
}

// openvpnInstanceValidateNetwork accepts a network in CIDR notation of the IP version (4 or 6), "" clears
func openvpnInstanceValidateNetwork(version int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var ip, _, err = net.ParseCIDR(value)
		if err != nil || (ip.To4() != nil) != (version == 4) {
			return fmt.Errorf("must be an IPv%d network in CIDR notation like %s, got %q", version,
				map[int]string{4: "10.8.0.0/24", 6: "fd00:8::/64"}[version], value)
		}
		return nil
	}
}

// openvpnInstanceValidateNetworks accepts comma separated IPv4/IPv6 networks in CIDR notation
func openvpnInstanceValidateNetworks(value string) error {
	for _, element := range splitList(value) {
		if _, _, err := net.ParseCIDR(element); err != nil {
			return fmt.Errorf("must be networks in CIDR notation like 10.0.0.0/24, got %q", element)
		}
	}
	return nil
}

// openvpnInstanceValidateKey accepts what OPNsense accepts for keys and the auth token secret
func openvpnInstanceValidateKey(value string) error {
	if !openvpn.StaticKeyPattern.MatchString(value) {
		return errors.New("may only contain letters, digits, whitespace and # - = + /")
	}
	return nil
}

// openvpnInstanceCheck checks the keepalive pair when both are given (OPNsense also demands both or none)
func openvpnInstanceCheck(args *Args) error {
	if args.Has("keepalive-interval") && args.Has("keepalive-timeout") {
		var interval, timeout = args.String("keepalive-interval"), args.String("keepalive-timeout")
		if (interval == "") != (timeout == "") {
			return errors.New("keepalive-interval and keepalive-timeout must be given both or cleared both")
		}
		if interval != "" && args.Int("keepalive-timeout") < 2*args.Int("keepalive-interval") {
			return fmt.Errorf("keepalive-timeout must be at least twice keepalive-interval (%d), got %s", 2*args.Int("keepalive-interval"), timeout)
		}
	}
	return nil
}

// --- lookups

// openvpnInstanceSearch returns the matching instances in API order with the raw rows for json
func openvpnInstanceSearch(api *openvpn.OpenVPNApi, searchPhrase string) ([]openvpn.Instance, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("openvpn", "instances", "search")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var instances = make([]openvpn.Instance, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &instances[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected openvpn instance from OPNsense: %w", err)
		}
	}
	return instances, rows, nil
}

func openvpnInstanceSelect(c *Context, api *openvpn.OpenVPNApi, selector string) (openvpn.Instance, []openvpn.Instance, error) {
	var instances, _, err = openvpnInstanceSearch(api, "")
	if err != nil {
		return openvpn.Instance{}, nil, err
	}
	var instance, selectErr = Select(c, selector, instances,
		func(instance openvpn.Instance) string { return instance.Uuid },
		func(instance openvpn.Instance) []string { return []string{instance.Description} })
	return instance, instances, selectErr
}

func openvpnInstanceItemNames(c *Context) []string {
	var api, err = openvpnApi(c)
	if err != nil {
		return nil
	}
	var instances, listErr = api.InstanceList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, instance := range instances {
		if instance.Description != "" {
			names = append(names, instance.Description)
		}
	}
	return names
}

// openvpnInstanceRefNames completes a reference argument with the option names of instances/get
func openvpnInstanceRefNames(field string) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = openvpnApi(c)
		if err != nil {
			return nil
		}
		var form, formErr = api.InstanceForm("")
		if formErr != nil {
			return nil
		}
		var names []string
		for _, option := range form[field].Options {
			if option.Key != "" {
				names = append(names, option.Description)
			}
		}
		return names
	}
}

// openvpnInstanceResolveRef maps a reference given by key or option description to the option key
func openvpnInstanceResolveRef(form openvpn.Form, field string, argName string, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	var options = form[field].Options
	for _, option := range options {
		if option.Key != "" && strings.EqualFold(option.Key, value) {
			return option.Key, nil
		}
	}
	var matches []openvpn.Option
	for _, option := range options {
		if option.Key != "" && strings.EqualFold(strings.TrimSpace(option.Description), value) {
			matches = append(matches, option)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Key, nil
	case 0:
		var names []string
		for _, option := range options {
			if option.Key != "" {
				names = append(names, fmt.Sprintf("%q", option.Description))
			}
		}
		if len(names) == 0 {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, there is nothing to choose from", argName, value)}
		}
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, valid are: %s", argName, value, strings.Join(names, ", "))}
	default:
		var keys = make([]string, len(matches))
		for i, match := range matches {
			keys[i] = match.Key
		}
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, give the key instead", argName, value, strings.Join(keys, ", "))}
	}
}

// openvpnInstanceCanonical returns value in the spelling of values (the API keys are case-sensitive)
func openvpnInstanceCanonical(values []string, value string) string {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return candidate
		}
	}
	return value
}

// openvpnInstanceFieldsOf returns the given field arguments as API fields, references resolved
func openvpnInstanceFieldsOf(c *Context, api *openvpn.OpenVPNApi, args *Args, specs []openvpnInstanceField) (openvpn.InstanceFields, error) {
	var fields = openvpn.InstanceFields{}
	var form openvpn.Form
	for _, spec := range specs {
		if !args.Has(spec.Name) {
			continue
		}
		var value = args.String(spec.Name)
		switch spec.kind {
		case openvpnInstanceFlag:
			fields[spec.field] = Flag(args.Bool(spec.Name))
		case openvpnInstanceDisabled:
			fields[spec.field] = Flag(!args.Bool(spec.Name))
		case openvpnInstanceList:
			var elements = args.List(spec.Name)
			for i := range elements {
				elements[i] = openvpnInstanceCanonical(spec.Values, elements[i])
			}
			fields[spec.field] = strings.Join(elements, ",")
		case openvpnInstanceStrictCN:
			fields[spec.field] = fmt.Sprint(slices.IndexFunc(openvpnInstanceStrictCNValues, func(v string) bool { return strings.EqualFold(v, value) }))
		case openvpnInstanceStaticKey:
			var uuid, err = openvpnStaticKeyResolve(c, api, value)
			if err != nil {
				return nil, err
			}
			fields[spec.field] = uuid
		case openvpnInstanceRef, openvpnInstanceRefList:
			if form == nil && value != "" {
				var err error
				if form, err = api.InstanceForm(""); err != nil {
					return nil, err
				}
			}
			var elements = []string{strings.TrimSpace(value)}
			if spec.kind == openvpnInstanceRefList {
				elements = args.List(spec.Name)
			}
			var keys []string
			for _, element := range elements {
				var key, err = openvpnInstanceResolveRef(form, spec.field, spec.Name, element)
				if err != nil {
					return nil, err
				}
				if key != "" {
					keys = append(keys, key)
				}
			}
			fields[spec.field] = strings.Join(keys, ",")
		default:
			fields[spec.field] = openvpnInstanceCanonical(spec.Values, strings.TrimSpace(value))
		}
	}
	return fields, nil
}

// --- output

func openvpnInstanceDisabledText(instance openvpn.Instance) string {
	if instance.Enabled == "0" {
		return "yes"
	}
	return "no"
}

func openvpnInstanceMask(value string) string {
	if value == "" {
		return ""
	}
	return openvpnInstanceMasked
}

// openvpnInstanceRefText renders option keys by their description (static keys without the " [mode]" suffix)
func openvpnInstanceRefText(form openvpn.Form, field string, value string) string {
	if value == "" {
		return ""
	}
	var texts []string
	for _, key := range strings.Split(value, ",") {
		var text = key
		for _, option := range form[field].Options {
			if option.Key == key && strings.TrimSpace(option.Description) != "" {
				text = strings.TrimSpace(option.Description)
				if field == "tls_key" {
					if cut := strings.LastIndex(text, " ["); cut > 0 {
						text = text[:cut]
					}
				}
				break
			}
		}
		texts = append(texts, text)
	}
	return strings.Join(texts, ",")
}

// openvpnInstanceDetail are the fields of show and print detail, named like the arguments
func openvpnInstanceDetail(instance openvpn.Instance, form openvpn.Form) [][2]string {
	var raw = map[string]string{}
	var encoded, _ = json.Marshal(instance)
	_ = json.Unmarshal(encoded, &raw)

	var fields = [][2]string{{"uuid", instance.Uuid}}
	for _, spec := range openvpnInstanceFields(false) {
		var value = raw[spec.field]
		switch spec.kind {
		case openvpnInstanceFlag:
			value = YesNo(value)
		case openvpnInstanceDisabled:
			value = openvpnInstanceDisabledText(instance)
		case openvpnInstanceSecret:
			value = openvpnInstanceMask(value)
		case openvpnInstanceStrictCN:
			if index := slices.Index([]string{"0", "1", "2"}, value); index >= 0 {
				value = openvpnInstanceStrictCNValues[index]
			}
		case openvpnInstanceRef, openvpnInstanceRefList, openvpnInstanceStaticKey:
			value = openvpnInstanceRefText(form, spec.field, value)
		}
		fields = append(fields, [2]string{spec.Name, value})
	}
	return fields
}

// openvpnInstanceMaskedRow returns a raw search row with the secrets masked
func openvpnInstanceMaskedRow(row json.RawMessage) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(row, &object); err != nil {
		return nil, err
	}
	for _, field := range openvpn.InstanceSecretFields {
		if value, isString := object[field].(string); isString && value != "" {
			object[field] = openvpnInstanceMasked
		}
	}
	return object, nil
}

func openvpnInstancePrint(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var instances, raw, searchErr = openvpnInstanceSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}
	var uuids = make([]string, len(instances))
	for i, instance := range instances {
		uuids[i] = instance.Uuid
	}

	switch {
	case args.Bool("json"):
		for _, row := range raw {
			var masked, maskErr = openvpnInstanceMaskedRow(row)
			if maskErr != nil {
				return maskErr
			}
			if err := c.JSON(masked); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var form, formErr = api.InstanceForm("")
		if formErr != nil {
			return formErr
		}
		var items = make([][][2]string, len(instances))
		for i, instance := range instances {
			items[i] = openvpnInstanceDetail(instance, form)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(instances))
		for i, instance := range instances {
			var tunnel = strings.Trim(instance.Server+","+instance.ServerIpv6, ",")
			rows[i] = []string{openvpnInstanceDisabledText(instance), instance.Vpnid, instance.Role, instance.Proto, instance.Port,
				instance.DevType, tunnel, instance.Remote, instance.Description}
		}
		c.Items([]string{"DISABLED", "VPNID", "ROLE", "PROTOCOL", "PORT", "DEV", "TUNNEL", "REMOTE", "DESCRIPTION"}, rows, uuids)
	}
	return nil
}

func openvpnInstanceShow(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var instance, _, selectErr = openvpnInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var form, formErr = api.InstanceForm("")
	if formErr != nil {
		return formErr
	}
	c.Fields(openvpnInstanceDetail(instance, form))
	return nil
}

// --- changes

func openvpnInstanceAdd(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = openvpnInstanceFieldsOf(c, api, args, openvpnInstanceFields(true))
	if fieldsErr != nil {
		return fieldsErr
	}

	var description = fields["description"]
	var instances, _, searchErr = openvpnInstanceSearch(api, "")
	if searchErr != nil {
		return searchErr
	}
	var existing = coreapi.Filter(instances, func(instance openvpn.Instance) bool {
		return strings.EqualFold(instance.Description, description)
	})
	switch {
	case len(existing) == 0:
		var uuid, createErr = api.InstanceCreate(fields)
		if createErr != nil {
			return openvpnInstanceError(createErr)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, instance := range existing {
			uuids[i] = instance.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d instances with description %q (%s), change or remove them with set or remove",
			len(existing), description, strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("an instance with description %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Description, existing[0].Uuid)
	}

	// replace: the defaults of a new instance, overwritten by the given fields; the vpnid is kept unless given
	var defaults, formErr = api.InstanceForm("")
	if formErr != nil {
		return formErr
	}
	var replacement = openvpn.InstanceFields{}
	for name, value := range defaults.Values() {
		if slices.Contains(openvpn.InstanceFieldNames, name) && name != "vpnid" {
			replacement[name] = value
		}
	}
	for name, value := range fields {
		replacement[name] = value
	}
	if err := api.InstanceUpdate(existing[0].Uuid, replacement); err != nil {
		return openvpnInstanceError(err)
	}
	c.Infof("replaced the existing instance %q", existing[0].Description)
	c.Println(existing[0].Uuid)
	return nil
}

func openvpnInstanceSet(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var fields, fieldsErr = openvpnInstanceFieldsOf(c, api, args, openvpnInstanceFields(false))
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like port= or description= (type \"set ?\" for help)")
	}
	var instance, instances, selectErr = openvpnInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if description, renamed := fields["description"]; renamed && description != "" {
		for _, other := range instances {
			if other.Uuid != instance.Uuid && strings.EqualFold(other.Description, description) {
				return fmt.Errorf("another instance with description %q exists already (%s)", description, other.Uuid)
			}
		}
	}
	return openvpnInstanceError(api.InstanceUpdate(instance.Uuid, fields))
}

func openvpnInstanceRemove(c *Context, args *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	var instance, _, selectErr = openvpnInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	// OPNsense removes instances client specific overrides refer to, the overrides keep the dangling uuid
	var overrides, overridesErr = api.ClientOverridesForServer(instance.Uuid)
	if overridesErr != nil {
		return overridesErr
	}
	if len(overrides) > 0 {
		var names = make([]string, len(overrides))
		for i, override := range overrides {
			names[i] = fmt.Sprintf("%s (%s)", override.CommonName, override.Uuid)
		}
		return fmt.Errorf("the instance %q is used by the client specific overrides %s, change their servers= or remove them first",
			instance.Description, strings.Join(names, ", "))
	}
	return api.InstanceRemove(instance.Uuid)
}

// openvpnInstanceError names the fields of an OPNsense validation error by their argument names
func openvpnInstanceError(err error) error {
	return openvpnValidationArgs(err, "instance.", func(field string) string {
		for _, spec := range openvpnInstanceFields(false) {
			if spec.field == field {
				return spec.Name
			}
		}
		return ""
	})
}

func openvpnInstanceEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = openvpnApi(c)
		if err != nil {
			return err
		}
		var instance, _, selectErr = openvpnInstanceSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.InstanceSetEnabled(instance.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("instance %q is already %s", instance.Description, EnabledWord(enabled))
		}
		return nil
	}
}

// openvpnInstanceService starts, stops or restarts one instance. OPNsense answers ok for anything and only acts
// on enabled instances, so disabled ones are refused here
func openvpnInstanceService(action string) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = openvpnApi(c)
		if err != nil {
			return err
		}
		var instance, _, selectErr = openvpnInstanceSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		if instance.Enabled == "0" {
			return fmt.Errorf("the instance %q is disabled, OPNsense only %ss enabled instances (enable it and apply)", instance.Description, action)
		}
		switch action {
		case "start":
			return api.InstanceStart(instance.Uuid)
		case "stop":
			return api.InstanceStop(instance.Uuid)
		default:
			return api.InstanceRestart(instance.Uuid)
		}
	}
}

func openvpnInstanceApply(c *Context, _ *Args) error {
	var api, err = openvpnApi(c)
	if err != nil {
		return err
	}
	return api.InstancesReconfigure()
}
