package cli

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/wireguard"
)

// /vpn/wireguard/peer: the remote WireGuard peers of VPN > WireGuard > Peers (api/wireguard/client) and the peer
// generator. Items are selected by the # of print, the uuid or the name (the natural key of add). instances= links a
// peer to instances by their names. The pre-shared key is never shown (also not in json).
//
// The peer generator of the GUI is JavaScript: it asks the API for a key pair and the instance defaults
// (get_server_info), stores the peer and renders the client configuration in the browser. generate does the same
// with the same API calls and renders the configuration here; the private key of the peer only ends up in that
// file (26.7 does not store it). config renders the configuration of an existing peer, which needs the private key
// newer OPNsense versions can store with the peer

const wireguardPeerItemHelp = "the #, uuid or name of the peer"

// wireguardPeerFields are the field arguments of add and set, in the order of show
func wireguardPeerFields(add bool) []wireguardField {
	var required = func(arg Arg) Arg {
		arg.Required = add
		return arg
	}
	var name = Arg{Name: "name", Required: add, Validate: wireguardValidateName,
		Help: "name of the peer: letters, digits, . _ - (at most 64)"}
	if !add {
		name.Help = "rename the peer"
	}
	return []wireguardField{
		{name, "name", wireguardPlain},
		{Arg{Name: "disabled", Type: Bool, Help: "keep the peer, but don't use it"}, "enabled", wireguardDisabled},
		{required(Arg{Name: "public-key", Validate: wireguard.ValidateKey, Help: "the public key of the peer"}), "pubkey", wireguardPlain},
		{Arg{Name: "psk", Validate: wireguardValidateKey, Help: "pre-shared key (never shown), empty for none"}, "psk", wireguardSecret},
		{required(Arg{Name: "tunnel-address", Type: List, Validate: wireguardValidateNetworks,
			Help: "allowed IPs: the networks of the peer (CIDR), at least its tunnel address like 10.9.0.2/32"}), "tunneladdress", wireguardList},
		{Arg{Name: "endpoint-address", Validate: wireguardValidateHost,
			Help: "address or host name of the peer, empty for peers that connect to the firewall"}, "serveraddress", wireguardPlain},
		{Arg{Name: "endpoint-port", Type: Int, Validate: ValidatePort, Help: "port of the peer"}, "serverport", wireguardPlain},
		{Arg{Name: "keepalive", Type: Int, Validate: ValidateRange(1, 65535), Help: "persistent keepalive interval in seconds, empty for none"}, "keepalive", wireguardPlain},
		{Arg{Name: "instances", Type: List, Complete: wireguardInstanceItemNames,
			Help: "the instances (names or uuids) of the peer, replaces the list; instance= for one"}, "servers", wireguardRef},
	}
}

// wireguardPeerConfigArgs are the arguments generate and config share
func wireguardPeerConfigArgs() []Arg {
	return []Arg{
		{Name: "allowed-ips", Type: List, Validate: wireguardValidateNetworks,
			Help: "the networks the peer routes through the tunnel (default: the instance default, else 0.0.0.0/0,::/0)"},
		{Name: "endpoint", Validate: wireguardValidateEndpoint,
			Help: "host:port the peer connects to (default: the peer generator endpoint of the instance)"},
		{Name: "dns", Type: List, Validate: ValidateIPList, Help: "DNS servers of the peer (default: those of the instance), empty for none"},
		{Name: "file", Help: "file to write, - for stdout (default: <name>.conf)"},
		{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
	}
}

func init() {
	var menu = Root.Menu("vpn/wireguard/peer")
	menu.Help = "WireGuard peers and the peer generator (VPN > WireGuard > Peers, Peer generator)"
	var item = Arg{Name: "item", Help: wireguardPeerItemHelp, Positional: true, Required: true, Complete: wireguardPeerItemNames}
	var generatePsk = Arg{Name: "generate-psk", Type: Bool, Help: "let OPNsense generate a pre-shared key"}
	menu.Add(
		&Command{Name: "print", Help: "list the peers", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every peer"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (keys masked)"},
			{Name: "search", Help: "only peers where any field contains this text"},
			{Name: "instance", Help: "only the peers of this instance (name or uuid)", Complete: wireguardInstanceItemNames},
		}, Run: wireguardPeerPrint},
		&Command{Name: "show", Help: "show all fields of one peer", Args: []Arg{item}, Run: wireguardPeerShow},
		&Command{Name: "add", Help: "add a peer, prints its uuid",
			Long: `The peer needs its public key and its tunnel address(es); instance= links it to an instance. Fields not
given get the OPNsense defaults (enabled). The name names the peer: if it exists already, add fails unless replace is
given, then that peer is replaced completely (fields not given are reset to the defaults).

  add name=laptop public-key=... tunnel-address=10.9.0.2/32 instance=wg-office

` + wireguardApplyHint,
			Args: append(append(wireguardArgs(wireguardPeerFields(true)), generatePsk),
				Arg{Name: "replace", Type: Bool, Help: "replace the peer with the same name"}),
			Check: wireguardPeerCheckPsk,
			Run:   wireguardPeerAdd},
		&Command{Name: "set", Help: "change fields of a peer, the others are kept",
			Long: `name= renames the peer, an empty value clears a field (e.g. keepalive= or instances=).
` + wireguardApplyHint,
			Args:  append(append([]Arg{item}, wireguardArgs(wireguardPeerFields(false))...), generatePsk),
			Check: wireguardPeerCheckPsk,
			Run:   wireguardPeerSet},
		&Command{Name: "remove", Help: "remove a peer", Long: wireguardApplyHint, Args: []Arg{item}, Run: wireguardPeerRemove},
		&Command{Name: "enable", Help: "enable a peer", Long: wireguardApplyHint, Args: []Arg{item}, Run: wireguardPeerEnabler(true)},
		&Command{Name: "disable", Help: "disable a peer", Long: wireguardApplyHint, Args: []Arg{item}, Run: wireguardPeerEnabler(false)},
		&Command{Name: "generate", Help: "peer generator: add a peer with a new key pair and save its client configuration",
			Long: `Like the peer generator of the GUI: OPNsense generates a key pair, the peer is added to the instance
with the next free tunnel address (or address=) and the wg-quick configuration of the peer is written to <name>.conf
(mode 0600) or file=. It contains the peer's private key, which OPNsense does not keep: the file is the only copy.
The uuid of the new peer is printed (on stderr with file=-).

The configuration uses the peer generator defaults of the instance (endpoint, peer-dns of /vpn/wireguard/instance);
like the GUI, an endpoint= or dns= given here is stored as the new default of the instance.

  generate name=laptop instance=wg-office endpoint=vpn.example.com:51820 keepalive=25

` + wireguardApplyHint,
			Args: append([]Arg{
				{Name: "name", Required: true, Validate: wireguardValidateName, Help: "name of the new peer"},
				{Name: "instance", Required: true, Complete: wireguardInstanceItemNames, Help: "the instance (name or uuid) the peer connects to"},
				{Name: "address", Type: List, Validate: wireguardValidateNetworks,
					Help: "tunnel address(es) of the peer, e.g. 10.9.0.5/32 (default: the next free address of the instance)"},
				{Name: "keepalive", Type: Int, Validate: ValidateRange(1, 65535), Help: "persistent keepalive interval in seconds"},
				{Name: "generate-psk", Type: Bool, Help: "use a pre-shared key, generated by OPNsense"},
				{Name: "disabled", Type: Bool, Help: "add the peer disabled"},
			}, wireguardPeerConfigArgs()...),
			Check: wireguardPeerCheckOutput,
			Run:   wireguardPeerGenerate},
		&Command{Name: "config", Help: "save the client configuration of a peer whose private key OPNsense stores",
			Long: `Renders the wg-quick configuration of an existing peer like the peer generator, written to <name>.conf
(mode 0600) or file=. It needs the private key of the peer, which only newer OPNsense versions store (peer generator
with "store private key"); OPNsense 26.7 never stores it, use generate to make a peer with its configuration.`,
			Args: append([]Arg{item, {Name: "instance", Complete: wireguardInstanceItemNames,
				Help: "the instance the configuration connects to, needed when the peer has several"}}, wireguardPeerConfigArgs()...),
			Check: wireguardPeerCheckOutput,
			Run:   wireguardPeerConfig},
	)
}

func wireguardPeerCheckPsk(args *Args) error {
	if args.Has("psk") && args.Bool("generate-psk") {
		return errors.New("give psk= or generate-psk, not both")
	}
	return nil
}

func wireguardPeerCheckOutput(args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}

// --- lookups

func wireguardPeerSelect(c *Context, api *wireguard.WireguardApi, selector string) (wireguard.Peer, []wireguard.Peer, error) {
	var peers, err = api.PeerList("")
	if err != nil {
		return wireguard.Peer{}, nil, err
	}
	var peer, selectErr = Select(c, selector, peers, wireguardPeerUuid, func(peer wireguard.Peer) []string { return []string{peer.Name} })
	return peer, peers, selectErr
}

func wireguardPeerItemNames(c *Context) []string {
	var api, err = wireguardApi(c)
	if err != nil {
		return nil
	}
	var peers, listErr = api.PeerList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, peer := range peers {
		names = append(names, peer.Name)
	}
	return names
}

// wireguardResolveInstance returns the uuid of the instance given by name or uuid
func wireguardResolveInstance(api *wireguard.WireguardApi, selector string) (wireguard.Instance, error) {
	var instances, err = api.InstanceList("")
	if err != nil {
		return wireguard.Instance{}, err
	}
	uuids, err := wireguardResolve("instance", []string{selector}, instances, wireguardInstanceUuid, wireguardInstanceName)
	if err != nil {
		return wireguard.Instance{}, err
	}
	for _, instance := range instances {
		if instance.Uuid == uuids[0] {
			return instance, nil
		}
	}
	return wireguard.Instance{}, &coreapi.NotFoundError{Name: "instance " + selector}
}

// wireguardPeerFieldsOf returns the given field arguments as API fields, instances resolved and a pre-shared
// key generated for generate-psk
func wireguardPeerFieldsOf(api *wireguard.WireguardApi, args *Args, specs []wireguardField) (wireguard.PeerFields, error) {
	var fields = wireguard.PeerFields(wireguardFieldValues(args, specs))
	if args.Has("instances") {
		var uuids []string
		if selectors := args.List("instances"); len(selectors) > 0 {
			var instances, err = api.InstanceList("")
			if err != nil {
				return nil, err
			}
			if uuids, err = wireguardResolve("instance", selectors, instances, wireguardInstanceUuid, wireguardInstanceName); err != nil {
				return nil, err
			}
		}
		fields["servers"] = strings.Join(uuids, ",")
	}
	if args.Bool("generate-psk") {
		var psk, err = api.PresharedKey()
		if err != nil {
			return nil, err
		}
		fields["psk"] = psk
	}
	return fields, nil
}

// --- output

// wireguardPeerEndpoint renders the endpoint of a peer as host:port
func wireguardPeerEndpoint(peer wireguard.Peer) string {
	switch {
	case peer.ServerAddress == "":
		return ""
	case peer.ServerPort == "":
		return peer.ServerAddress
	default:
		return net.JoinHostPort(peer.ServerAddress, peer.ServerPort)
	}
}

func wireguardPeerDetail(peer wireguard.Peer, instances []wireguard.Instance) [][2]string {
	return [][2]string{
		{"uuid", peer.Uuid},
		{"name", peer.Name},
		{"disabled", wireguardDisabledText(peer.Enabled)},
		{"public-key", peer.PublicKey},
		{"psk", wireguardMask(peer.Psk)},
		{"tunnel-address", peer.TunnelAddress},
		{"endpoint-address", peer.ServerAddress},
		{"endpoint-port", peer.ServerPort},
		{"keepalive", peer.Keepalive},
		{"instances", wireguardNames(peer.Servers, instances, wireguardInstanceUuid, wireguardInstanceName)},
		{"private-key", wireguardMask(peer.PrivateKey)},
	}
}

func wireguardPeerPrint(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var raw, peers, listErr = api.PeerListRaw(args.String("search"))
	if listErr != nil {
		return listErr
	}
	instances, err := api.InstanceList("")
	if err != nil {
		return err
	}
	if args.Has("instance") {
		var instance, resolveErr = wireguardResolveInstance(api, args.String("instance"))
		if resolveErr != nil {
			return resolveErr
		}
		var keptRaw = raw[:0:0]
		var kept []wireguard.Peer
		for i, peer := range peers {
			if slices.Contains(peer.InstanceUuids(), instance.Uuid) {
				kept = append(kept, peer)
				keptRaw = append(keptRaw, raw[i])
			}
		}
		raw, peers = keptRaw, kept
	}

	var uuids = make([]string, len(peers))
	for i, peer := range peers {
		uuids[i] = peer.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			var masked, maskErr = wireguardMaskedRow(row, wireguard.PeerSecretFields)
			if maskErr != nil {
				return maskErr
			}
			if err := c.JSON(masked); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(peers))
		for i, peer := range peers {
			items[i] = wireguardPeerDetail(peer, instances)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(peers))
		for i, peer := range peers {
			rows[i] = []string{wireguardDisabledText(peer.Enabled), peer.Name,
				wireguardNames(peer.Servers, instances, wireguardInstanceUuid, wireguardInstanceName),
				peer.TunnelAddress, wireguardPeerEndpoint(peer), peer.Keepalive}
		}
		c.Items([]string{"DISABLED", "NAME", "INSTANCES", "TUNNEL-ADDRESS", "ENDPOINT", "KEEPALIVE"}, rows, uuids)
	}
	return nil
}

func wireguardPeerShow(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var peer, _, selectErr = wireguardPeerSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	instances, err := api.InstanceList("")
	if err != nil {
		return err
	}
	c.Fields(wireguardPeerDetail(peer, instances))
	return nil
}

// --- changes

// wireguardPeerDefaults are the values of a new peer (model defaults), the base of add ... replace
var wireguardPeerDefaults = wireguard.PeerFields{"enabled": "1", "psk": "", "serveraddress": "", "serverport": "",
	"keepalive": "", "servers": ""}

func wireguardPeerAdd(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var specs = wireguardPeerFields(true)
	var fields, fieldsErr = wireguardPeerFieldsOf(api, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	var peers, listErr = api.PeerList("")
	if listErr != nil {
		return listErr
	}
	var existing = coreapi.Filter(peers, func(peer wireguard.Peer) bool { return strings.EqualFold(peer.Name, fields["name"]) })
	switch {
	case len(existing) == 0:
		var uuid, createErr = api.PeerCreate(fields)
		if createErr != nil {
			return wireguardError(createErr, "client.", specs)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, peer := range existing {
			uuids[i] = peer.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d peers named %q (%s), change or remove them with set or remove",
			len(existing), fields["name"], strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a peer named %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Name, existing[0].Uuid)
	}

	var replacement = wireguard.PeerFields{}
	for name, value := range wireguardPeerDefaults {
		replacement[name] = value
	}
	for name, value := range fields {
		replacement[name] = value
	}
	if err := api.PeerUpdate(existing[0].Uuid, replacement); err != nil {
		return wireguardError(err, "client.", specs)
	}
	c.Infof("replaced the existing peer %q", existing[0].Name)
	c.Println(existing[0].Uuid)
	return nil
}

func wireguardPeerSet(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var specs = wireguardPeerFields(false)
	var fields, fieldsErr = wireguardPeerFieldsOf(api, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like keepalive= or name= (type \"set ?\" for help)")
	}
	var peer, peers, selectErr = wireguardPeerSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if name, renamed := fields["name"]; renamed {
		for _, other := range peers {
			if other.Uuid != peer.Uuid && strings.EqualFold(other.Name, name) {
				return fmt.Errorf("another peer named %q exists already (%s)", name, other.Uuid)
			}
		}
	}
	return wireguardError(api.PeerUpdate(peer.Uuid, fields), "client.", specs)
}

func wireguardPeerRemove(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var peer, _, selectErr = wireguardPeerSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.PeerRemove(peer.Uuid)
}

func wireguardPeerEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = wireguardApi(c)
		if err != nil {
			return err
		}
		var peer, _, selectErr = wireguardPeerSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.PeerSetEnabled(peer.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("peer %q is already %s", peer.Name, EnabledWord(enabled))
		}
		return nil
	}
}

// --- peer generator

// wireguardPeerClientConfig fills the instance side of a client configuration from the arguments and the
// instance's peer generator defaults
func wireguardPeerClientConfig(args *Args, instance wireguard.Instance, info wireguard.ServerInfo) (wireguard.ClientConfig, error) {
	var config = wireguard.ClientConfig{ServerPublicKey: info.PublicKey, Mtu: info.Mtu, Endpoint: info.Endpoint, Dns: info.PeerDns}
	if args.Has("endpoint") {
		config.Endpoint = args.String("endpoint")
	}
	if args.Has("dns") {
		config.Dns = strings.Join(args.List("dns"), ",")
	}
	config.AllowedIps = strings.Join(args.List("allowed-ips"), ",")
	if config.AllowedIps == "" {
		config.AllowedIps = info.AllowedIps
	}
	if config.AllowedIps == "" {
		config.AllowedIps = wireguard.DefaultAllowedIps
	}
	if config.Endpoint == "" {
		return config, fmt.Errorf("the instance %q has no peer generator endpoint, give endpoint=host:port (generate stores it on the instance)", instance.Name)
	}
	if config.ServerPublicKey == "" {
		return config, fmt.Errorf("the instance %q has no public key, give it a key pair with \"/vpn/wireguard/instance set %s new-keys\"", instance.Name, instance.Name)
	}
	return config, nil
}

func wireguardPeerGenerate(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var output = args.String("file")
	if err := wireguardCheckOutput(output, name+".conf", args.Bool("overwrite")); err != nil {
		return err
	}
	peers, err := api.PeerList("")
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if strings.EqualFold(peer.Name, name) {
			return fmt.Errorf("a peer named %q exists already (%s), choose another name", peer.Name, peer.Uuid)
		}
	}
	instance, err := wireguardResolveInstance(api, args.String("instance"))
	if err != nil {
		return err
	}
	info, err := api.InstanceServerInfo(instance.Uuid)
	if err != nil {
		return err
	}
	config, err := wireguardPeerClientConfig(args, instance, info)
	if err != nil {
		return err
	}
	config.Address = strings.Join(args.List("address"), ",")
	if config.Address == "" {
		config.Address = info.Address
	}
	if config.Address == "" {
		return fmt.Errorf("the instance %q has no tunnel address to take a free address from, give address=", instance.Name)
	}
	config.Keepalive = args.String("keepalive")

	pair, err := api.KeyPair()
	if err != nil {
		return err
	}
	config.PrivateKey = pair.PrivateKey
	if args.Bool("generate-psk") {
		if config.PresharedKey, err = api.PresharedKey(); err != nil {
			return err
		}
	}
	if err := config.Validate(); err != nil {
		return err
	}

	var uuid, createErr = api.PeerCreate(wireguard.PeerFields{
		"enabled": Flag(!args.Bool("disabled")), "name": name, "pubkey": pair.PublicKey, "psk": config.PresharedKey,
		"tunneladdress": config.Address, "keepalive": config.Keepalive, "servers": instance.Uuid,
	})
	if createErr != nil {
		return openvpnValidationArgs(createErr, "client.", func(field string) string {
			return map[string]string{"tunneladdress": "address", "pubkey": "public-key"}[field]
		})
	}

	// like the GUI: a changed endpoint or DNS becomes the new default of the instance
	var defaults = wireguard.InstanceFields{}
	if config.Endpoint != info.Endpoint {
		defaults["endpoint"] = config.Endpoint
	}
	if args.Has("dns") && config.Dns != info.PeerDns {
		defaults["peer_dns"] = config.Dns
	}
	if len(defaults) > 0 {
		if err := api.InstanceUpdate(instance.Uuid, defaults); err != nil {
			c.Infof("warning: could not store the peer generator defaults on the instance %q: %v", instance.Name, err)
		}
	}

	if output == "-" {
		c.Infof("added the peer %q (%s)", name, uuid)
	} else {
		c.Println(uuid)
	}
	return wireguardWriteOutput(c, output, name+".conf", []byte(config.String()), args.Bool("overwrite"))
}

func wireguardPeerConfig(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var peer, _, selectErr = wireguardPeerSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if peer.PrivateKey == "" {
		return fmt.Errorf("OPNsense does not store the private key of the peer %q, so its configuration can not be made "+
			"(OPNsense 26.7 never stores it); generate adds a peer and saves its configuration", peer.Name)
	}
	var output = args.String("file")
	if err := wireguardCheckOutput(output, peer.Name+".conf", args.Bool("overwrite")); err != nil {
		return err
	}

	var instanceUuid string
	switch linked := peer.InstanceUuids(); {
	case args.Has("instance"):
		var instance, resolveErr = wireguardResolveInstance(api, args.String("instance"))
		if resolveErr != nil {
			return resolveErr
		}
		if !slices.Contains(linked, instance.Uuid) {
			return fmt.Errorf("the peer %q does not belong to the instance %q", peer.Name, instance.Name)
		}
		instanceUuid = instance.Uuid
	case len(linked) == 1:
		instanceUuid = linked[0]
	case len(linked) == 0:
		return fmt.Errorf("the peer %q belongs to no instance, link it with set %s instance=<name>", peer.Name, peer.Name)
	default:
		return fmt.Errorf("the peer %q belongs to several instances (%s), choose one with instance=", peer.Name, peer.ServerNames)
	}
	instance, err := api.InstanceGet(instanceUuid)
	if err != nil {
		return err
	}
	info, err := api.InstanceServerInfo(instanceUuid)
	if err != nil {
		return err
	}
	config, err := wireguardPeerClientConfig(args, instance, info)
	if err != nil {
		return err
	}
	config.PrivateKey, config.Address, config.PresharedKey, config.Keepalive = peer.PrivateKey, peer.TunnelAddress, peer.Psk, peer.Keepalive
	if err := config.Validate(); err != nil {
		return err
	}
	return wireguardWriteOutput(c, output, peer.Name+".conf", []byte(config.String()), args.Bool("overwrite"))
}
