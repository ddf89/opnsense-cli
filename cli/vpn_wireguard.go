package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/wireguard"
)

// Shared parts of the /vpn/wireguard menus: instance, peer, settings, status, service (VPN > WireGuard)

const (
	wireguardApplyHint = `Changes are only saved, run "/vpn/wireguard/service reconfigure" to apply them.`
	wireguardMasked    = "********"
)

func init() {
	Root.Menu("vpn/wireguard").Help = "WireGuard instances, peers, settings, status and service (VPN > WireGuard)"
}

// wireguardApi returns the WireGuard API on the session's connection
func wireguardApi(c *Context) (*wireguard.WireguardApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &wireguard.WireguardApi{OPNsense: opn}, nil
}

// how an argument value maps to the API value
type wireguardFieldKind int

const (
	wireguardPlain    wireguardFieldKind = iota
	wireguardFlag                        // yes/no as 1/0
	wireguardDisabled                    // the disabled argument for the enabled field
	wireguardList                        // comma separated
	wireguardSecret                      // plain, never shown
	wireguardRef                         // names resolved to uuids or option keys
)

// wireguardField is a field argument of add / set and the API field it is stored in
type wireguardField struct {
	Arg
	field string
	kind  wireguardFieldKind
}

func wireguardArgs(fields []wireguardField) []Arg {
	var args = make([]Arg, len(fields))
	for i, field := range fields {
		args[i] = field.Arg
	}
	return args
}

// wireguardFieldValues returns the given plain, flag, list and secret arguments as API fields; references are
// left to the caller
func wireguardFieldValues(args *Args, specs []wireguardField) map[string]string {
	var fields = map[string]string{}
	for _, spec := range specs {
		if !args.Has(spec.Name) {
			continue
		}
		switch spec.kind {
		case wireguardFlag:
			fields[spec.field] = Flag(args.Bool(spec.Name))
		case wireguardDisabled:
			fields[spec.field] = Flag(!args.Bool(spec.Name))
		case wireguardList:
			fields[spec.field] = strings.Join(args.List(spec.Name), ",")
		case wireguardPlain, wireguardSecret:
			fields[spec.field] = strings.TrimSpace(args.String(spec.Name))
		}
	}
	return fields
}

// wireguardError names the fields of an OPNsense validation error ("server.port") by their argument names
func wireguardError(err error, prefix string, specs []wireguardField) error {
	return openvpnValidationArgs(err, prefix, func(field string) string {
		for _, spec := range specs {
			if spec.field == field {
				return spec.Name
			}
		}
		return ""
	})
}

func wireguardMask(value string) string {
	if value == "" {
		return ""
	}
	return wireguardMasked
}

func wireguardDisabledText(enabled string) string {
	return YesNo(Flag(enabled == "0"))
}

// --- validation

var wireguardNamePattern = regexp.MustCompile(`^[0-9a-zA-Z._\-]{1,64}$`)

// wireguardValidateName accepts what OPNsense accepts for instance and peer names
func wireguardValidateName(value string) error {
	if !wireguardNamePattern.MatchString(value) {
		return fmt.Errorf("must be 1 to 64 letters, digits, dots, dashes or underscores, got %q", value)
	}
	return nil
}

// wireguardValidateKey accepts a WireGuard key, "" clears
func wireguardValidateKey(value string) error {
	if value == "" {
		return nil
	}
	return wireguard.ValidateKey(value)
}

// wireguardValidateAddresses accepts comma separated addresses with or without prefix length (10.0.0.1/24)
func wireguardValidateAddresses(value string) error {
	for _, element := range splitList(value) {
		if net.ParseIP(element) == nil {
			if _, _, err := net.ParseCIDR(element); err != nil {
				return fmt.Errorf("must be addresses like 10.0.0.1/24 or fd00::1/64, got %q", element)
			}
		}
	}
	return nil
}

// wireguardValidateNetworks accepts comma separated networks in CIDR notation (10.0.0.2/32)
func wireguardValidateNetworks(value string) error {
	for _, element := range splitList(value) {
		if _, _, err := net.ParseCIDR(element); err != nil {
			return fmt.Errorf("must be networks in CIDR notation like 10.0.0.2/32 or 0.0.0.0/0, got %q", element)
		}
	}
	return nil
}

var wireguardHostPattern = regexp.MustCompile(`^[0-9a-zA-Z]([0-9a-zA-Z\-]{0,61}[0-9a-zA-Z])?(\.[0-9a-zA-Z]([0-9a-zA-Z\-]{0,61}[0-9a-zA-Z])?)*\.?$`)

// wireguardValidateHost accepts an IP address or a host name, "" clears
func wireguardValidateHost(value string) error {
	if value == "" || net.ParseIP(value) != nil || wireguardHostPattern.MatchString(value) {
		return nil
	}
	return fmt.Errorf("must be an IP address or host name, got %q", value)
}

// wireguardValidateEndpoint accepts host:port or [ipv6]:port, "" clears
func wireguardValidateEndpoint(value string) error {
	if value == "" {
		return nil
	}
	var host, port, err = net.SplitHostPort(value)
	if err == nil {
		err = wireguardValidateHost(host)
	}
	if number, convErr := strconv.Atoi(port); err != nil || convErr != nil || number < 1 || number > 65535 || host == "" {
		return fmt.Errorf("must be host:port like vpn.example.com:51820 or [2001:db8::1]:51820, got %q", value)
	}
	return nil
}

// --- references

// wireguardResolve maps each selector (a uuid or a name, case-insensitive) to the uuid of an item. what names the
// items in errors ("instance"), list the valid names
func wireguardResolve[T any](what string, selectors []string, items []T, uuidOf func(T) string, nameOf func(T) string) ([]string, error) {
	var uuids []string
	for _, selector := range selectors {
		var matches []string
		for _, item := range items {
			if strings.EqualFold(uuidOf(item), selector) {
				matches = []string{uuidOf(item)}
				break
			}
			if strings.EqualFold(nameOf(item), selector) {
				matches = append(matches, uuidOf(item))
			}
		}
		switch len(matches) {
		case 1:
			uuids = append(uuids, matches[0])
		case 0:
			var names []string
			for _, item := range items {
				names = append(names, nameOf(item))
			}
			if len(names) == 0 {
				return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, there are no %ss", what, selector, what)}
			}
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, valid are: %s", what, selector, strings.Join(names, ", "))}
		default:
			return nil, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, give the uuid instead", what, selector, strings.Join(matches, ", "))}
		}
	}
	return uuids, nil
}

// wireguardNames renders a comma separated uuid list by the names of the items, unknown uuids as they are
func wireguardNames[T any](uuids string, items []T, uuidOf func(T) string, nameOf func(T) string) string {
	var names []string
	for _, uuid := range splitList(uuids) {
		var name = uuid
		for _, item := range items {
			if uuidOf(item) == uuid {
				name = nameOf(item)
				break
			}
		}
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

func wireguardInstanceUuid(instance wireguard.Instance) string { return instance.Uuid }
func wireguardInstanceName(instance wireguard.Instance) string { return instance.Name }
func wireguardPeerUuid(peer wireguard.Peer) string             { return peer.Uuid }
func wireguardPeerName(peer wireguard.Peer) string             { return peer.Name }

// --- files

// wireguardWriteOutput writes content to stdout (output "-") or to a file with mode 0600 (output, else
// defaultName); an existing file is only replaced with overwrite
func wireguardWriteOutput(c *Context, output string, defaultName string, content []byte, overwrite bool) error {
	if output == "-" {
		_, err := c.Out.Write(content)
		return err
	}
	var filename = defaultName
	if output != "" {
		filename = output
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	var file, err = os.OpenFile(filename, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s", filename)
	return nil
}

// wireguardCheckOutput fails early when the output file exists and overwrite is not given, before anything is
// changed on the firewall
func wireguardCheckOutput(output string, defaultName string, overwrite bool) error {
	if output == "-" || overwrite {
		return nil
	}
	var filename = defaultName
	if output != "" {
		filename = output
	}
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
