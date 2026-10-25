package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/wireguard"
)

// /vpn/wireguard/instance: the local WireGuard interfaces of VPN > WireGuard > Instances (api/wireguard/server).
// Items are selected by the # of print, the uuid or the name (the natural key of add). The private key is never
// shown (also not in json), add lets OPNsense generate a key pair unless private-key= is given; the public key is
// always derived from the private key

const wireguardInstanceItemHelp = "the #, uuid or name of the instance"

// wireguardInstanceFields are the field arguments of add and set, in the order of show
func wireguardInstanceFields(add bool) []wireguardField {
	var name = Arg{Name: "name", Required: add, Validate: wireguardValidateName,
		Help: "name of the instance: letters, digits, . _ - (at most 64)"}
	if !add {
		name.Help = "rename the instance"
	}
	return []wireguardField{
		{name, "name", wireguardPlain},
		{Arg{Name: "disabled", Type: Bool, Help: "keep the instance, but don't run it"}, "enabled", wireguardDisabled},
		{Arg{Name: "private-key", Validate: wireguard.ValidateKey,
			Help: "private key (never shown), the public key is derived from it; add generates a key pair when not given"}, "privkey", wireguardSecret},
		{Arg{Name: "port", Type: Int, Validate: ValidatePort, Help: "UDP port to listen on, empty for a random one"}, "port", wireguardPlain},
		{Arg{Name: "tunnel-address", Type: List, Validate: wireguardValidateAddresses,
			Help: "addresses of the instance in the tunnel with prefix length, e.g. 10.9.0.1/24,fd00:9::1/64"}, "tunneladdress", wireguardList},
		{Arg{Name: "peers", Type: List, Complete: wireguardPeerItemNames,
			Help: "the peers of the instance (names or uuids), replaces the list; the peers' instances= changes it too"}, "peers", wireguardRef},
		{Arg{Name: "mtu", Type: Int, Validate: ValidateRange(1, 9300), Help: "MTU of the interface, empty for the default"}, "mtu", wireguardPlain},
		{Arg{Name: "dns", Type: List, Validate: ValidateIPList, Help: "DNS servers of the instance"}, "dns", wireguardList},
		{Arg{Name: "disable-routes", Type: Bool, Help: "don't add routes for the tunnel addresses of the peers"}, "disableroutes", wireguardFlag},
		{Arg{Name: "gateway", Validate: ValidateIP, Help: "gateway address of the tunnel, needs disable-routes"}, "gateway", wireguardPlain},
		{Arg{Name: "carp-depend-on", Complete: wireguardInstanceCarpNames,
			Help: "run only while this CARP address is master (its name), empty for always"}, "carp_depend_on", wireguardRef},
		{Arg{Name: "debug", Type: Bool, Help: "log debug messages"}, "debug", wireguardFlag},
		{Arg{Name: "endpoint", Validate: wireguardValidateEndpoint,
			Help: "peer generator default: the host:port the peers connect to"}, "endpoint", wireguardPlain},
		{Arg{Name: "peer-dns", Type: List, Validate: ValidateIPList, Help: "peer generator default: the DNS servers of the peers"}, "peer_dns", wireguardList},
	}
}

func init() {
	var menu = Root.Menu("vpn/wireguard/instance")
	menu.Help = "WireGuard instances: the local tunnel interfaces wg0, wg1, ... (VPN > WireGuard > Instances)"
	var item = Arg{Name: "item", Help: wireguardInstanceItemHelp, Positional: true, Required: true, Complete: wireguardInstanceItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the instances", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every instance"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (private key masked)"},
			{Name: "search", Help: "only instances where any field contains this text"},
		}, Run: wireguardInstancePrint},
		&Command{Name: "show", Help: "show all fields of one instance", Args: []Arg{item}, Run: wireguardInstanceShow},
		&Command{Name: "add", Help: "add an instance, prints its uuid",
			Long: `Without private-key= OPNsense generates a key pair, the public key is shown by show (the peers need
it). Fields not given get the OPNsense defaults (enabled, a random port). The name names the instance: if it exists
already, add fails unless replace is given, then that instance is replaced completely (fields not given are reset
to the defaults, the keys are kept unless private-key= is given).

  add name=wg-office port=51820 tunnel-address=10.9.0.1/24 disabled

` + wireguardApplyHint,
			Args: append(wireguardArgs(wireguardInstanceFields(true)),
				Arg{Name: "replace", Type: Bool, Help: "replace the instance with the same name"}),
			Run: wireguardInstanceAdd},
		&Command{Name: "set", Help: "change fields of an instance, the others are kept",
			Long: `name= renames the instance, an empty value clears a field (e.g. dns=). new-keys lets OPNsense generate
a new key pair: every peer then needs the new public key.
` + wireguardApplyHint,
			Args: append(append([]Arg{item}, wireguardArgs(wireguardInstanceFields(false))...),
				Arg{Name: "new-keys", Type: Bool, Help: "generate a new key pair"}),
			Check: wireguardInstanceCheckSet,
			Run:   wireguardInstanceSet},
		&Command{Name: "remove", Help: "remove an instance, its peers are kept",
			Long: "The peers of the instance are kept, they are no longer linked to it.\n" + wireguardApplyHint,
			Args: []Arg{item}, Run: wireguardInstanceRemove},
		&Command{Name: "enable", Help: "enable an instance", Long: wireguardApplyHint, Args: []Arg{item}, Run: wireguardInstanceEnabler(true)},
		&Command{Name: "disable", Help: "disable an instance", Long: wireguardApplyHint, Args: []Arg{item}, Run: wireguardInstanceEnabler(false)},
	)
}

func wireguardInstanceCheckSet(args *Args) error {
	if args.Has("private-key") && args.Bool("new-keys") {
		return errors.New("give private-key= or new-keys, not both")
	}
	return nil
}

// --- lookups

func wireguardInstanceSelect(c *Context, api *wireguard.WireguardApi, selector string) (wireguard.Instance, []wireguard.Instance, error) {
	var instances, err = api.InstanceList("")
	if err != nil {
		return wireguard.Instance{}, nil, err
	}
	var instance, selectErr = Select(c, selector, instances, wireguardInstanceUuid,
		func(instance wireguard.Instance) []string { return []string{instance.Name} })
	return instance, instances, selectErr
}

func wireguardInstanceItemNames(c *Context) []string {
	var api, err = wireguardApi(c)
	if err != nil {
		return nil
	}
	var instances, listErr = api.InstanceList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, instance := range instances {
		names = append(names, instance.Name)
	}
	return names
}

func wireguardInstanceCarpNames(c *Context) []string {
	var api, err = wireguardApi(c)
	if err != nil {
		return nil
	}
	var options, optionsErr = api.InstanceOptions()
	if optionsErr != nil {
		return nil
	}
	var names []string
	for _, option := range options["carp_depend_on"] {
		if option.Key != "" {
			names = append(names, option.Description)
		}
	}
	return names
}

// wireguardResolveOption maps an option given by key or description (case-insensitive) to its key, "" is ""
func wireguardResolveOption(options []wireguard.Option, argName string, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	var matches []string
	for _, option := range options {
		if option.Key == "" {
			continue
		}
		if strings.EqualFold(option.Key, value) {
			return option.Key, nil
		}
		if strings.EqualFold(strings.TrimSpace(option.Description), value) {
			matches = append(matches, option.Key)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
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
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, give the key instead", argName, value, strings.Join(matches, ", "))}
	}
}

// wireguardInstanceFieldsOf returns the given field arguments as API fields, references resolved and the public
// key derived from a given private key
func wireguardInstanceFieldsOf(api *wireguard.WireguardApi, args *Args, specs []wireguardField) (wireguard.InstanceFields, error) {
	var fields = wireguard.InstanceFields(wireguardFieldValues(args, specs))
	if args.Has("peers") {
		var uuids []string
		if selectors := args.List("peers"); len(selectors) > 0 {
			var peers, err = api.PeerList("")
			if err != nil {
				return nil, err
			}
			if uuids, err = wireguardResolve("peer", selectors, peers, wireguardPeerUuid, wireguardPeerName); err != nil {
				return nil, err
			}
		}
		fields["peers"] = strings.Join(uuids, ",")
	}
	if value := strings.TrimSpace(args.String("carp-depend-on")); args.Has("carp-depend-on") {
		var key string
		if value != "" {
			var options, err = api.InstanceOptions()
			if err != nil {
				return nil, err
			}
			if key, err = wireguardResolveOption(options["carp_depend_on"], "carp-depend-on", value); err != nil {
				return nil, err
			}
		}
		fields["carp_depend_on"] = key
	}
	if privateKey, given := fields["privkey"]; given {
		var publicKey, err = wireguard.PublicKeyOf(privateKey)
		if err != nil {
			return nil, err
		}
		fields["pubkey"] = publicKey
	}
	return fields, nil
}

// wireguardInstanceNewKeys asks OPNsense for a key pair and stores it in fields
func wireguardInstanceNewKeys(c *Context, api *wireguard.WireguardApi, fields wireguard.InstanceFields) error {
	var pair, err = api.KeyPair()
	if err != nil {
		return err
	}
	fields["privkey"] = pair.PrivateKey
	fields["pubkey"] = pair.PublicKey
	c.Infof("generated a new key pair, public key %s", pair.PublicKey)
	return nil
}

// --- output

// wireguardInstanceDetail are the fields of show and print detail, named like the arguments
func wireguardInstanceDetail(instance wireguard.Instance, options map[string][]wireguard.Option) [][2]string {
	var carp = instance.CarpDependOn
	for _, option := range options["carp_depend_on"] {
		if carp != "" && option.Key == carp {
			carp = option.Description
		}
	}
	return [][2]string{
		{"uuid", instance.Uuid},
		{"name", instance.Name},
		{"disabled", wireguardDisabledText(instance.Enabled)},
		{"device", instance.Interface},
		{"public-key", instance.PublicKey},
		{"private-key", wireguardMask(instance.PrivateKey)},
		{"port", instance.Port},
		{"tunnel-address", instance.TunnelAddress},
		{"peers", strings.ReplaceAll(instance.PeerNames, ", ", ",")},
		{"mtu", instance.Mtu},
		{"dns", instance.Dns},
		{"disable-routes", YesNo(instance.DisableRoutes)},
		{"gateway", instance.Gateway},
		{"carp-depend-on", carp},
		{"debug", YesNo(instance.Debug)},
		{"endpoint", instance.Endpoint},
		{"peer-dns", instance.PeerDns},
	}
}

// wireguardInstanceOptionsFor loads the option lists only when an instance refers to a CARP address
func wireguardInstanceOptionsFor(api *wireguard.WireguardApi, instances ...wireguard.Instance) (map[string][]wireguard.Option, error) {
	for _, instance := range instances {
		if instance.CarpDependOn != "" {
			return api.InstanceOptions()
		}
	}
	return nil, nil
}

// wireguardMaskedRow returns a raw search row with the secret fields masked
func wireguardMaskedRow(row json.RawMessage, secrets []string) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(row, &object); err != nil {
		return nil, err
	}
	for _, field := range secrets {
		if value, isString := object[field].(string); isString && value != "" {
			object[field] = wireguardMasked
		}
	}
	return object, nil
}

func wireguardInstancePrint(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var raw, instances, listErr = api.InstanceListRaw(args.String("search"))
	if listErr != nil {
		return listErr
	}
	var uuids = make([]string, len(instances))
	for i, instance := range instances {
		uuids[i] = instance.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			var masked, maskErr = wireguardMaskedRow(row, wireguard.InstanceSecretFields)
			if maskErr != nil {
				return maskErr
			}
			if err := c.JSON(masked); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var options, optionsErr = wireguardInstanceOptionsFor(api, instances...)
		if optionsErr != nil {
			return optionsErr
		}
		var items = make([][][2]string, len(instances))
		for i, instance := range instances {
			items[i] = wireguardInstanceDetail(instance, options)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(instances))
		for i, instance := range instances {
			rows[i] = []string{wireguardDisabledText(instance.Enabled), instance.Name, instance.Interface, instance.Port,
				instance.TunnelAddress, strings.ReplaceAll(instance.PeerNames, ", ", ",")}
		}
		c.Items([]string{"DISABLED", "NAME", "DEVICE", "PORT", "TUNNEL-ADDRESS", "PEERS"}, rows, uuids)
	}
	return nil
}

func wireguardInstanceShow(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var instance, _, selectErr = wireguardInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var options, optionsErr = wireguardInstanceOptionsFor(api, instance)
	if optionsErr != nil {
		return optionsErr
	}
	c.Fields(wireguardInstanceDetail(instance, options))
	return nil
}

// --- changes

// wireguardInstanceDefaults are the values of a new instance (model defaults), the base of add ... replace
var wireguardInstanceDefaults = wireguard.InstanceFields{"enabled": "1", "port": "", "mtu": "", "dns": "", "tunneladdress": "",
	"disableroutes": "0", "gateway": "", "carp_depend_on": "", "peers": "", "debug": "0", "endpoint": "", "peer_dns": ""}

func wireguardInstanceAdd(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var specs = wireguardInstanceFields(true)
	var fields, fieldsErr = wireguardInstanceFieldsOf(api, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	var instances, listErr = api.InstanceList("")
	if listErr != nil {
		return listErr
	}
	var existing = coreapi.Filter(instances, func(instance wireguard.Instance) bool {
		return strings.EqualFold(instance.Name, fields["name"])
	})
	switch {
	case len(existing) == 0:
		if _, given := fields["privkey"]; !given {
			if err := wireguardInstanceNewKeys(c, api, fields); err != nil {
				return err
			}
		}
		var uuid, createErr = api.InstanceCreate(fields)
		if createErr != nil {
			return wireguardError(createErr, "server.", specs)
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, instance := range existing {
			uuids[i] = instance.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d instances named %q (%s), change or remove them with set or remove",
			len(existing), fields["name"], strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("an instance named %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Name, existing[0].Uuid)
	}

	var replacement = wireguard.InstanceFields{}
	for name, value := range wireguardInstanceDefaults {
		replacement[name] = value
	}
	for name, value := range fields {
		replacement[name] = value
	}
	if err := api.InstanceUpdate(existing[0].Uuid, replacement); err != nil {
		return wireguardError(err, "server.", specs)
	}
	c.Infof("replaced the existing instance %q", existing[0].Name)
	c.Println(existing[0].Uuid)
	return nil
}

func wireguardInstanceSet(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var specs = wireguardInstanceFields(false)
	var fields, fieldsErr = wireguardInstanceFieldsOf(api, args, specs)
	if fieldsErr != nil {
		return fieldsErr
	}
	if len(fields) == 0 && !args.Bool("new-keys") {
		return errors.New("set: nothing to change, give at least one field like port= or name= (type \"set ?\" for help)")
	}
	var instance, instances, selectErr = wireguardInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if name, renamed := fields["name"]; renamed {
		for _, other := range instances {
			if other.Uuid != instance.Uuid && strings.EqualFold(other.Name, name) {
				return fmt.Errorf("another instance named %q exists already (%s)", name, other.Uuid)
			}
		}
	}
	if args.Bool("new-keys") {
		if err := wireguardInstanceNewKeys(c, api, fields); err != nil {
			return err
		}
	}
	return wireguardError(api.InstanceUpdate(instance.Uuid, fields), "server.", specs)
}

func wireguardInstanceRemove(c *Context, args *Args) error {
	var api, err = wireguardApi(c)
	if err != nil {
		return err
	}
	var instance, _, selectErr = wireguardInstanceSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.InstanceRemove(instance.Uuid)
}

func wireguardInstanceEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = wireguardApi(c)
		if err != nil {
			return err
		}
		var instance, _, selectErr = wireguardInstanceSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.InstanceSetEnabled(instance.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("instance %q is already %s", instance.Name, EnabledWord(enabled))
		}
		return nil
	}
}
