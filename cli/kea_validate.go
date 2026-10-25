package cli

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Argument validators of the DHCP menus (/kea, /dhcrelay, /radvd). Like the framework validators they accept ""
// (it clears a field), use Required to demand a value

var (
	keaHexIdPattern  = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$`)
	keaDomainPattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$`)
)

func keaVersionOf(address netip.Addr) int {
	if address.Is4() {
		return 4
	}
	return 6
}

func keaFamily(version int) string {
	if version == 0 {
		return "IPv4 or IPv6"
	}
	return fmt.Sprintf("IPv%d", version)
}

// keaValidateAddress accepts one IP address of version (4, 6, or 0 for both)
func keaValidateAddress(version int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var address, err = netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || (version != 0 && keaVersionOf(address) != version) {
			return fmt.Errorf("must be an %s address, got %q", keaFamily(version), value)
		}
		return nil
	}
}

// keaValidateAddresses accepts comma separated IP addresses of version
func keaValidateAddresses(version int) func(string) error {
	return func(value string) error {
		for _, element := range splitList(value) {
			if err := keaValidateAddress(version)(element); err != nil {
				return err
			}
		}
		return nil
	}
}

// keaValidateNetwork accepts a network in CIDR notation of version
func keaValidateNetwork(version int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var prefix, err = netip.ParsePrefix(value)
		if err != nil || (version != 0 && keaVersionOf(prefix.Addr()) != version) {
			var example = map[int]string{0: "198.51.100.0/24", 4: "198.51.100.0/24", 6: "2001:db8::/64"}[version]
			return fmt.Errorf("must be an %s network in CIDR notation like %s, got %q", keaFamily(version), example, value)
		}
		return nil
	}
}

// keaValidateNetworks accepts comma separated networks of version
func keaValidateNetworks(version int) func(string) error {
	return func(value string) error {
		for _, element := range splitList(value) {
			if err := keaValidateNetwork(version)(element); err != nil {
				return err
			}
		}
		return nil
	}
}

// keaValidatePools accepts comma separated pools: ranges first-last or networks in CIDR notation of version
func keaValidatePools(version int) func(string) error {
	return func(value string) error {
		for _, element := range splitList(value) {
			if first, last, isRange := strings.Cut(element, "-"); isRange {
				var from, fromErr = netip.ParseAddr(strings.TrimSpace(first))
				var to, toErr = netip.ParseAddr(strings.TrimSpace(last))
				if fromErr == nil && toErr == nil && keaVersionOf(from) == version && keaVersionOf(to) == version && from.Compare(to) <= 0 {
					continue
				}
			} else if keaValidateNetwork(version)(element) == nil {
				continue
			}
			var example = map[int]string{4: "198.51.100.10-198.51.100.99 or 198.51.100.128/25", 6: "2001:db8::100-2001:db8::1ff or 2001:db8::/112"}[version]
			return fmt.Errorf("must be %s ranges or networks like %s, got %q", keaFamily(version), example, element)
		}
		return nil
	}
}

// keaValidateText rejects control characters like newlines (OPNsense masks)
func keaValidateText(value string) error {
	for _, char := range value {
		if char < ' ' || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

// keaValidateOptionText rejects control characters and double quotes (Kea option strings)
func keaValidateOptionText(value string) error {
	if strings.Contains(value, `"`) {
		return fmt.Errorf("must not contain double quotes, got %q", value)
	}
	return keaValidateText(value)
}

// keaValidateMAC accepts one MAC address
func keaValidateMAC(value string) error {
	if value == "" {
		return nil
	}
	if hw, err := net.ParseMAC(value); err != nil || len(hw) != 6 {
		return fmt.Errorf("must be a MAC address like 02:00:5e:10:00:01, got %q", value)
	}
	return nil
}

// keaValidateHexId accepts a client id or DUID: colon separated hex bytes like 01:02:f3
func keaValidateHexId(value string) error {
	if value != "" && !keaHexIdPattern.MatchString(value) {
		return fmt.Errorf("must be colon separated hex bytes like 01:02:f3, got %q", value)
	}
	return nil
}

// keaValidateDomain accepts one domain or host name
func keaValidateDomain(value string) error {
	if value != "" && (len(value) > 253 || !keaDomainPattern.MatchString(value)) {
		return fmt.Errorf("must be a domain name like example.com, got %q", value)
	}
	return nil
}

// keaValidateDomains accepts comma separated domain names
func keaValidateDomains(value string) error {
	for _, element := range splitList(value) {
		if err := keaValidateDomain(element); err != nil {
			return err
		}
	}
	return nil
}

// keaValidateMin accepts whole numbers >= min
func keaValidateMin(min int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		if number, err := strconv.Atoi(value); err != nil || number < min {
			return fmt.Errorf("must be a number of at least %d, got %q", min, value)
		}
		return nil
	}
}

// keaValidateLifetime accepts 1 to 4294967295 seconds
func keaValidateLifetime(value string) error {
	if value == "" {
		return nil
	}
	if number, err := strconv.ParseUint(value, 10, 64); err != nil || number < 1 || number > 4294967295 {
		return fmt.Errorf("must be a number of seconds from 1 to 4294967295, got %q", value)
	}
	return nil
}

// keaValidateStaticRoutes accepts destination,router address pairs (option 33): 10.1.0.1,198.51.100.1,...
func keaValidateStaticRoutes(value string) error {
	var elements = splitList(value)
	if len(elements)%2 != 0 {
		return errors.New("must be pairs of destination,router addresses like 10.1.0.1,198.51.100.1")
	}
	return keaValidateAddresses(4)(value)
}

// keaValidateClasslessRoutes accepts network-router pairs (option 121): 10.0.0.0/8-198.51.100.1,...
func keaValidateClasslessRoutes(value string) error {
	for _, element := range splitList(value) {
		var network, router, found = strings.Cut(element, "-")
		if !found || keaValidateNetwork(4)(strings.TrimSpace(network)) != nil || keaValidateAddress(4)(strings.TrimSpace(router)) != nil ||
			strings.TrimSpace(router) == "" || strings.TrimSpace(network) == "" {
			return fmt.Errorf("must be network-router pairs like 10.0.0.0/8-198.51.100.1, got %q", element)
		}
	}
	return nil
}

// keaValidateURL accepts an http(s) URL
func keaValidateURL(value string) error {
	if value == "" {
		return nil
	}
	if parsed, err := url.Parse(value); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("must be a URL like http://198.51.100.2:8000/, got %q", value)
	}
	return nil
}

// keaSameNetwork compares two networks in CIDR notation semantically
func keaSameNetwork(a string, b string) bool {
	var prefixA, errA = netip.ParsePrefix(strings.TrimSpace(a))
	var prefixB, errB = netip.ParsePrefix(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return prefixA.Masked() == prefixB.Masked()
}

// keaSameAddress compares two IP addresses semantically
func keaSameAddress(a string, b string) bool {
	var addressA, errA = netip.ParseAddr(strings.TrimSpace(a))
	var addressB, errB = netip.ParseAddr(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return addressA == addressB
}

// keaSameMAC compares MAC addresses in any notation (02:00:5e:10:00:01, 02-00-5E-10-00-01)
func keaSameMAC(a string, b string) bool {
	var macA, errA = net.ParseMAC(a)
	var macB, errB = net.ParseMAC(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(a, b)
	}
	return macA.String() == macB.String()
}

// keaNetworkContains tells whether the network in CIDR notation contains the address
func keaNetworkContains(network string, address string) bool {
	var prefix, prefixErr = netip.ParsePrefix(network)
	var addr, addrErr = netip.ParseAddr(address)
	return prefixErr == nil && addrErr == nil && prefix.Contains(addr)
}
