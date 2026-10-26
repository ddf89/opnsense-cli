package cli

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"opnsense-cli/opnsense/api/interfaces"
)

// /interface/address: the address configuration of the assigned interfaces (Interfaces > [LAN], [optN] in the GUI,
// api/interfaces/assignment of OPNsense 26.7, the same records as /interface/assignment). Like an assignment
// change, every address change is staged and takes effect with "/interface/assignment apply"; there is no apply
// here.
//
// Access protection: changing the address settings of lan, wan and the interface the API connection goes through
// asks for confirmation (Command.ConfirmIf, confirm=yes skips it), like relinking them in /interface/assignment

const interfaceAddressItemHelp = "the #, identifier (opt1), description or device of the interface"

const interfaceAddressApplyHint = `Changes are staged, run "/interface/assignment apply" to apply them (it applies all staged assignment and
address changes).`

const interfaceAddressProtectedHelp = `Changing the address settings of lan, wan or of the interface the API connection goes through (when its
address is one of the firewall's addresses) asks for confirmation: that can cut off the access to the firewall.`

// the address types: CLI name and OPNsense key
var (
	interfaceAddressTypes4 = [][2]string{{"none", interfaces.AddressType4None}, {"static", interfaces.AddressType4Static},
		{"dhcp", interfaces.AddressType4DHCP}, {"pppoe", "pppoe"}, {"ppp", "ppp"}, {"pptp", "pptp"}, {"l2tp", "l2tp"}}
	// 6rd is only shown, it needs settings (prefix, border relay) that are not offered here
	interfaceAddressTypes6 = [][2]string{{"none", interfaces.AddressType6None}, {"static", interfaces.AddressType6Static},
		{"dhcp6", interfaces.AddressType6DHCP}, {"slaac", interfaces.AddressType6SLAAC}, {"linklocal", interfaces.AddressType6LinkOnly},
		{"6to4", "6to4"}, {"idassoc6", interfaces.AddressType6IDAssoc}, {"track6", interfaces.AddressType6Track}, {"pppoev6", "pppoev6"}}
)

// interfaceAddressFieldArgs are the arguments of set, the others (item) are not fields
var interfaceAddressFieldArgs = []string{"ipv4-type", "ipv4", "gateway4", "ipv6-type", "ipv6", "gateway6", "track6-interface",
	"track6-prefix-id", "mtu", "mss", "mac", "block-private", "block-bogons", "dhcp-hostname", "dhcp-reject-from"}

func init() {
	var menu = Root.Menu("interface/address")
	menu.Help = "address configuration of the assigned interfaces: IPv4/IPv6 type, addresses, gateways, MTU (Interfaces > [name])"
	var item = Arg{Name: "item", Help: interfaceAddressItemHelp, Positional: true, Required: true, Complete: interfaceCompleteIdentifiers}
	menu.Add(
		&Command{Name: "print", Help: "list the address configuration of the assigned interfaces",
			Long: `Shows the configured values, a staged change included: PENDING is the staged change apply will make
(update, relink), the running addresses are in "/interface/overview print". A hint on stderr tells when
changes wait for "/interface/assignment apply".`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every interface"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only interfaces where any field contains this text"},
			}, Run: interfaceAddressPrint},
		&Command{Name: "show", Help: "show the address configuration of one interface", Args: []Arg{item}, Run: interfaceAddressShow},
		&Command{Name: "set", Help: "change the address configuration of an interface, the other fields are kept",
			ConfirmHelp: "Asks for confirmation before changing the address settings of " + interfaceAssignmentProtected +
				": that can cut off the access to the firewall, and there is no rollback.",
			ConfirmIf: interfaceAddressConfirmSet,
			Long: `ipv4= and gateway4= need ipv4-type=static, ipv6= and gateway6= need ipv6-type=static, track6-interface= and
track6-prefix-id= need ipv6-type=track6 or idassoc6, dhcp-hostname= and dhcp-reject-from= need ipv4-type=dhcp
(given or configured). A type other than static clears the static address and gateway of that family.
Clearing a type (none) or the MTU is applied to the configuration, but OPNsense 26.7 leaves the running
addresses and MTU on the device until it is reset (unassigned, relinked or rebooted); a new static address
replaces the old one.
The PPP types (pppoe, ppp, pptp, l2tp, pppoev6) only work with a PPP device, 6rd is not offered (it needs
settings of the GUI). Gateways are the configured gateways of this interface ("/system/gateway print").
` + interfaceAddressProtectedHelp + `
` + interfaceAddressApplyHint + `

  set opt1 ipv4-type=static ipv4=192.0.2.1/24 ipv6-type=track6 track6-interface=wan track6-prefix-id=0x1
  set guests mtu=1400 block-bogons
  set opt1 ipv4-type=none`,
			Args: []Arg{item,
				{Name: "ipv4-type", Help: "how the interface gets its IPv4 address", Values: interfaceAddressNames(interfaceAddressTypes4)},
				{Name: "ipv4", Help: "the static IPv4 address with prefix length, like 192.0.2.1/24", Validate: interfaceAddressValidateCIDR(4)},
				{Name: "gateway4", Help: "the upstream IPv4 gateway (a gateway name of this interface, empty: none)", Validate: interfaceAddressValidateGateway,
					Complete: interfaceAddressCompleteChoices(func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Gateway4 })},
				{Name: "ipv6-type", Help: "how the interface gets its IPv6 address", Values: interfaceAddressNames(interfaceAddressTypes6)},
				{Name: "ipv6", Help: "the static IPv6 address with prefix length, like 2001:db8::1/64", Validate: interfaceAddressValidateCIDR(6)},
				{Name: "gateway6", Help: "the upstream IPv6 gateway (a gateway name of this interface, empty: none)", Validate: interfaceAddressValidateGateway,
					Complete: interfaceAddressCompleteChoices(func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Gateway6 })},
				{Name: "track6-interface", Help: "the parent interface whose delegated prefix track6/idassoc6 use (like wan)", Validate: interfaceValidateName,
					Complete: interfaceAddressCompleteChoices(func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Track6Interface })},
				{Name: "track6-prefix-id", Help: "the prefix ID taken from the delegated prefix, hex like 0x1 (empty: default)", Validate: interfaceAddressValidateHex},
				{Name: "mtu", Help: "the MTU, 576-65535 (empty: the device default)", Validate: ValidateRange(576, 65535)},
				{Name: "mss", Help: "the TCP MSS clamping, 576-65535 (empty: none)", Validate: ValidateRange(576, 65535)},
				{Name: "mac", Help: "the MAC address that replaces the device's own one (empty: none)", Validate: interfaceAddressValidateMAC},
				{Name: "block-private", Type: Bool, Help: "block traffic from private networks (RFC 1918) and loopback addresses"},
				{Name: "block-bogons", Type: Bool, Help: "block traffic from reserved and unassigned networks"},
				{Name: "dhcp-hostname", Help: "the hostname the DHCP client sends (empty: none)", Validate: interfaceAddressValidateHostname},
				{Name: "dhcp-reject-from", Type: List, Help: "IPv4 addresses of DHCP servers the client ignores", Validate: interfaceAddressValidateIPv4List},
			},
			Check: interfaceAddressCheckSet, Run: interfaceAddressSet},
	)
}

// --- names and validation

func interfaceAddressNames(types [][2]string) []string {
	var names = make([]string, len(types))
	for i, entry := range types {
		names[i] = entry[0]
	}
	return names
}

// interfaceAddressTypeKey returns the OPNsense key of a CLI type name
func interfaceAddressTypeKey(types [][2]string, name string) string {
	for _, entry := range types {
		if strings.EqualFold(entry[0], name) {
			return entry[1]
		}
	}
	return name
}

// interfaceAddressTypeName returns the CLI name of an OPNsense type key (the key itself when unknown, like 6rd)
func interfaceAddressTypeName(types [][2]string, key string) string {
	for _, entry := range types {
		if entry[1] == key {
			return entry[0]
		}
	}
	return key
}

func interfaceAddressValidateCIDR(family int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var example, bits = "192.0.2.1/24", 32
		if family == 6 {
			example, bits = "2001:db8::1/64", 128
		}
		var ip, network, err = net.ParseCIDR(value)
		if err != nil || (ip.To4() != nil) != (family == 4) || strings.Contains(value, ":") != (family == 6) {
			return fmt.Errorf("must be an IPv%d address with prefix length like %s, got %q", family, example, value)
		}
		if ones, _ := network.Mask.Size(); ones < 1 || ones > bits {
			return fmt.Errorf("the prefix length must be 1-%d, got %q", bits, value)
		}
		return nil
	}
}

func interfaceAddressValidateGateway(value string) error {
	if interfaceValidateName(value) != nil {
		return fmt.Errorf("must be a gateway name like LAN_GW, got %q", value)
	}
	return nil
}

var interfaceAddressHexPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{1,30}$`)

func interfaceAddressValidateHex(value string) error {
	if value != "" && !interfaceAddressHexPattern.MatchString(value) {
		return fmt.Errorf("must be a hex number like 0x1, got %q", value)
	}
	return nil
}

func interfaceAddressValidateMAC(value string) error {
	if value == "" {
		return nil
	}
	if mac, err := net.ParseMAC(value); err != nil || len(mac) != 6 {
		return fmt.Errorf("must be a MAC address like 02:00:5e:10:00:01, got %q", value)
	}
	return nil
}

var interfaceAddressHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func interfaceAddressValidateHostname(value string) error {
	if value != "" && (!interfaceAddressHostnamePattern.MatchString(value) || net.ParseIP(value) != nil) {
		return fmt.Errorf("must be a host name like fw1 or fw1.example.com, got %q", value)
	}
	return nil
}

func interfaceAddressValidateIPv4List(value string) error {
	for _, element := range splitList(value) {
		if ip := net.ParseIP(element); ip == nil || ip.To4() == nil || strings.Contains(element, ":") {
			return fmt.Errorf("must be IPv4 addresses, got %q", element)
		}
	}
	return nil
}

// interfaceAddressNeeds checks that the fields given with a non-empty value fit the address types; type4 and type6
// are the given or configured types (CLI names), unknown "" skips the check of that family
func interfaceAddressNeeds(args *Args, type4 string, type6 string) error {
	var given = func(name string) bool {
		return args.Has(name) && strings.TrimSpace(args.String(name)) != ""
	}
	var rules = []struct {
		field string
		known string
		ok    bool
		need  string
	}{
		{"ipv4", type4, type4 == "static", "ipv4-type=static"},
		{"gateway4", type4, type4 == "static", "ipv4-type=static"},
		{"dhcp-hostname", type4, type4 == "dhcp", "ipv4-type=dhcp"},
		{"dhcp-reject-from", type4, type4 == "dhcp", "ipv4-type=dhcp"},
		{"ipv6", type6, type6 == "static", "ipv6-type=static"},
		{"gateway6", type6, type6 == "static", "ipv6-type=static"},
		{"track6-interface", type6, type6 == "track6" || type6 == "idassoc6", "ipv6-type=track6 or idassoc6"},
		{"track6-prefix-id", type6, type6 == "track6" || type6 == "idassoc6", "ipv6-type=track6 or idassoc6"},
	}
	for _, rule := range rules {
		if given(rule.field) && rule.known != "" && !rule.ok {
			return fmt.Errorf("%s= needs %s (the type is %s)", rule.field, rule.need, rule.known)
		}
	}
	return nil
}

func interfaceAddressCheckSet(args *Args) error {
	var anything = false
	for _, name := range interfaceAddressFieldArgs {
		anything = anything || args.Has(name)
	}
	if !anything {
		return errors.New("set: nothing to change, give at least one field (type \"set ?\" for help)")
	}
	var type4, type6 = "", ""
	if args.Has("ipv4-type") {
		type4 = strings.ToLower(args.String("ipv4-type"))
		if type4 == "static" && args.Has("ipv4") && args.String("ipv4") == "" {
			return errors.New("ipv4-type=static needs an address, ipv4= can not be empty")
		}
	}
	if args.Has("ipv6-type") {
		type6 = strings.ToLower(args.String("ipv6-type"))
		if type6 == "static" && args.Has("ipv6") && args.String("ipv6") == "" {
			return errors.New("ipv6-type=static needs an address, ipv6= can not be empty")
		}
	}
	return interfaceAddressNeeds(args, type4, type6)
}

// --- lookups

func interfaceAddressIdentifier(address interfaces.Address) string {
	return address.Identifier
}

func interfaceAddressSelect(c *Context, list []interfaces.Address, selector string) (interfaces.Address, error) {
	return Select(c, selector, list, interfaceAddressIdentifier, func(address interfaces.Address) []string {
		return interfaceAssignmentNames(address.Assignment)
	})
}

func interfaceAddressCompleteChoices(pick func(interfaces.AddressChoices) []interfaces.Option) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = interfaceApi(c)
		if err != nil {
			return nil
		}
		var choices, choicesErr = api.AddressChoices("")
		if choicesErr != nil {
			return nil
		}
		var names []string
		for _, option := range pick(choices) {
			if option.Key != "" {
				names = append(names, option.Key)
			}
		}
		return names
	}
}

// interfaceAddressCheckChoice fails when value is not one of the offered choices
func interfaceAddressCheckChoice(arg string, value string, options []interfaces.Option, what string) error {
	var keys []string
	for _, option := range options {
		if option.Key == value {
			return nil
		}
		if option.Key != "" {
			keys = append(keys, option.Key)
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("%s: OPNsense offers no %s", arg, what)
	}
	return fmt.Errorf("%s: %q is not offered, OPNsense offers: %s", arg, value, strings.Join(keys, ", "))
}

// --- access protection

// interfaceAddressConfirmSet warns before changing the address settings of lan, wan and the interface the API
// connection goes through, unknown items fail before anything is asked
func interfaceAddressConfirmSet(c *Context, args *Args) (string, error) {
	var api, err = interfaceApi(c)
	if err != nil {
		return "", err
	}
	var list, listErr = api.Addresses()
	if listErr != nil {
		return "", listErr
	}
	var address, selectErr = interfaceAddressSelect(c, list, args.String("item"))
	if selectErr != nil {
		return "", selectErr
	}
	var guard, guardErr = interfaceAssignmentGuardFor(c, api)
	if guardErr != nil {
		return "", guardErr
	}
	return guard.warning(address.Identifier, "changing the address settings of"), nil
}

// --- print and show

func interfaceAddressGateways(address interfaces.Address) string {
	var gateways []string
	for _, gateway := range []string{address.Gateway4, address.Gateway6} {
		if gateway != "" {
			gateways = append(gateways, gateway)
		}
	}
	return strings.Join(gateways, ",")
}

func interfaceAddressDetail(address interfaces.Address) [][2]string {
	return [][2]string{
		{"identifier", address.Identifier},
		{"description", address.Description},
		{"device", address.Device},
		{"disabled", YesNo(Flag(!address.Enabled))},
		{"pending", address.PendingAction},
		{"ipv4-type", interfaceAddressTypeName(interfaceAddressTypes4, address.Type4)},
		{"ipv4", address.IPv4},
		{"gateway4", address.Gateway4},
		{"ipv6-type", interfaceAddressTypeName(interfaceAddressTypes6, address.Type6)},
		{"ipv6", address.IPv6},
		{"gateway6", address.Gateway6},
		{"track6-interface", address.Track6Interface},
		{"track6-prefix-id", address.Track6PrefixID},
		{"mtu", address.MTU},
		{"mss", address.MSS},
		{"mac", address.SpoofMAC},
		{"block-private", YesNo(Flag(address.BlockPrivate))},
		{"block-bogons", YesNo(Flag(address.BlockBogons))},
		{"dhcp-hostname", address.DHCPHostname},
		{"dhcp-reject-from", strings.Join(address.DHCPRejectFrom, ",")},
	}
}

func interfaceAddressStagedHint(c *Context, api *interfaces.InterfacesApi) {
	if pending, err := api.AssignmentPending(); err == nil && pending {
		c.Infof(`assignment or address changes are staged, run "/interface/assignment apply" to apply them`)
	}
}

func interfaceAddressPrint(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var addresses, listErr = api.AddressSearch(args.String("search"))
	if listErr != nil {
		return listErr
	}
	var identifiers = make([]string, len(addresses))
	for i, address := range addresses {
		identifiers[i] = address.Identifier
	}
	switch {
	case args.Bool("json"):
		for _, address := range addresses {
			if err := c.JSON(address.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(addresses))
		for i, address := range addresses {
			blocks[i] = interfaceAddressDetail(address)
		}
		c.Details(blocks, identifiers)
	default:
		var rows = make([][]string, len(addresses))
		for i, address := range addresses {
			rows[i] = []string{address.Identifier, address.Description,
				interfaceAddressTypeName(interfaceAddressTypes4, address.Type4), address.IPv4, interfaceAddressGateways(address),
				interfaceAddressTypeName(interfaceAddressTypes6, address.Type6), address.IPv6, address.MTU, address.PendingAction}
		}
		c.Items([]string{"IDENTIFIER", "DESCRIPTION", "IPV4-TYPE", "IPV4", "GATEWAY", "IPV6-TYPE", "IPV6", "MTU", "PENDING"}, rows, identifiers)
	}
	interfaceAddressStagedHint(c, api)
	return nil
}

func interfaceAddressShow(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Addresses()
	if listErr != nil {
		return listErr
	}
	var address, selectErr = interfaceAddressSelect(c, list, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var fields = interfaceAddressDetail(address)
	if guard, guardErr := interfaceAssignmentGuardFor(c, api); guardErr == nil {
		var protected = "no"
		if reason, found := guard.protected[address.Identifier]; found {
			protected = "yes, " + reason
		}
		fields = append(fields, [2]string{"protected", protected})
	}
	c.Fields(fields)
	return nil
}

// --- set

func interfaceAddressChange(args *Args) interfaces.AddressChange {
	var change interfaces.AddressChange
	var text = func(name string, target **string) {
		if args.Has(name) {
			var value = strings.TrimSpace(args.String(name))
			*target = &value
		}
	}
	var flag = func(name string, target **bool) {
		if args.Has(name) {
			var value = args.Bool(name)
			*target = &value
		}
	}
	if args.Has("ipv4-type") {
		var key = interfaceAddressTypeKey(interfaceAddressTypes4, args.String("ipv4-type"))
		change.Type4 = &key
	}
	if args.Has("ipv6-type") {
		var key = interfaceAddressTypeKey(interfaceAddressTypes6, args.String("ipv6-type"))
		change.Type6 = &key
	}
	text("ipv4", &change.IPv4)
	text("gateway4", &change.Gateway4)
	text("ipv6", &change.IPv6)
	text("gateway6", &change.Gateway6)
	text("track6-interface", &change.Track6Interface)
	text("track6-prefix-id", &change.Track6PrefixID)
	text("mtu", &change.MTU)
	text("mss", &change.MSS)
	text("mac", &change.SpoofMAC)
	text("dhcp-hostname", &change.DHCPHostname)
	flag("block-private", &change.BlockPrivate)
	flag("block-bogons", &change.BlockBogons)
	if args.Has("dhcp-reject-from") {
		var servers = args.List("dhcp-reject-from")
		change.DHCPRejectFrom = &servers
	}
	return change
}

// interfaceAddressCheckTypes checks the change against the configured types of the interface
func interfaceAddressCheckTypes(args *Args, address interfaces.Address, change interfaces.AddressChange) error {
	var type4, type6 = address.Type4, address.Type6
	if change.Type4 != nil {
		type4 = *change.Type4
	}
	if change.Type6 != nil {
		type6 = *change.Type6
	}
	var name4, name6 = interfaceAddressTypeName(interfaceAddressTypes4, type4), interfaceAddressTypeName(interfaceAddressTypes6, type6)
	if err := interfaceAddressNeeds(args, name4, name6); err != nil {
		return err
	}
	var ipv4, ipv6, track = address.IPv4, address.IPv6, address.Track6Interface
	if change.IPv4 != nil {
		ipv4 = *change.IPv4
	}
	if change.IPv6 != nil {
		ipv6 = *change.IPv6
	}
	if change.Track6Interface != nil {
		track = *change.Track6Interface
	}
	switch {
	case type4 == interfaces.AddressType4Static && ipv4 == "":
		return fmt.Errorf("ipv4-type=static needs an address, give ipv4=address/bits")
	case type6 == interfaces.AddressType6Static && ipv6 == "":
		return fmt.Errorf("ipv6-type=static needs an address, give ipv6=address/bits")
	case (type6 == interfaces.AddressType6Track || type6 == interfaces.AddressType6IDAssoc) && track == "":
		return fmt.Errorf("ipv6-type=%s needs a parent interface, give track6-interface=", name6)
	}
	return nil
}

// interfaceAddressCheckChoices checks gateways and the track6 parent against what OPNsense offers the interface
func interfaceAddressCheckChoices(api *interfaces.InterfacesApi, identifier string, change interfaces.AddressChange) error {
	var checks = []struct {
		arg   string
		value *string
		pick  func(interfaces.AddressChoices) []interfaces.Option
		what  string
	}{
		{"gateway4", change.Gateway4, func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Gateway4 },
			`IPv4 gateways (add one with "/system/gateway add")`},
		{"gateway6", change.Gateway6, func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Gateway6 },
			`IPv6 gateways (add one with "/system/gateway add")`},
		{"track6-interface", change.Track6Interface, func(choices interfaces.AddressChoices) []interfaces.Option { return choices.Track6Interface },
			"parent interfaces (an enabled interface with ipv6-type dhcp6, 6rd or 6to4)"},
	}
	var choices *interfaces.AddressChoices
	for _, check := range checks {
		if check.value == nil || *check.value == "" {
			continue
		}
		if choices == nil {
			var loaded, err = api.AddressChoices(identifier)
			if err != nil {
				return err
			}
			choices = &loaded
		}
		if err := interfaceAddressCheckChoice(check.arg, *check.value, check.pick(*choices), check.what); err != nil {
			return err
		}
	}
	return nil
}

// interfaceAddressTranslate renames the fields of an OPNsense validation error (interface.ipaddr) to the arguments
func interfaceAddressTranslate(err error) error {
	var fields []interfaceField
	for _, pair := range [][2]string{{"ipv4-type", "type4"}, {"ipv4", "ipaddr"}, {"gateway4", "gateway"}, {"ipv6-type", "type6"},
		{"ipv6", "ipaddrv6"}, {"gateway6", "gatewayv6"}, {"track6-interface", "track6-interface"}, {"track6-prefix-id", "track6-prefix-id"},
		{"mtu", "mtu"}, {"mss", "mss"}, {"mac", "spoofmac"}, {"block-private", "blockpriv"}, {"block-bogons", "blockbogons"},
		{"dhcp-hostname", "dhcphostname"}, {"dhcp-reject-from", "dhcprejectfrom"}} {
		fields = append(fields, interfaceField{Arg: Arg{Name: pair[0]}, api: pair[1]})
	}
	return (&interfaceSpec{fields: fields}).translate(err)
}

func interfaceAddressSet(c *Context, args *Args) error {
	var api, err = interfaceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = api.Addresses()
	if listErr != nil {
		return listErr
	}
	var address, selectErr = interfaceAddressSelect(c, list, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var change = interfaceAddressChange(args)
	if err := interfaceAddressCheckTypes(args, address, change); err != nil {
		return err
	}
	if err := interfaceAddressCheckChoices(api, address.Identifier, change); err != nil {
		return err
	}
	return interfaceAddressTranslate(api.AddressUpdate(address.Identifier, change))
}
