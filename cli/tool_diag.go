package cli

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Helpers shared by the interactive diagnostics of /tool (ping, traceroute, port-probe, dns-lookup, sniffer),
// Interfaces > Diagnostics in the GUI (api/diagnostics/{ping,traceroute,portprobe,dns_diagnostics,packet_capture})

// toolDiagAddressArg is the positional target of ping, traceroute and port-probe
func toolDiagAddressArg(help string) Arg {
	return Arg{Name: "address", Positional: true, Required: true, Help: help, Validate: toolDiagValidateHost}
}

var toolDiagFamilyArg = Arg{Name: "family", Values: []string{"ipv4", "ipv6"},
	Help: "address family, default ipv6 for an IPv6 address and ipv4 otherwise"}

var toolDiagSourceArg = Arg{Name: "source", Help: "the address of the firewall to send from", Validate: ValidateIP}

// toolDiagValidateHost accepts a host name or address, things OPNsense would refuse anyway are refused before
// anything is sent
func toolDiagValidateHost(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if strings.ContainsAny(value, " \t/\\?#%@,;'\"") {
		return fmt.Errorf("must be a host name or an IP address, got %q", value)
	}
	return nil
}

// toolDiagIsIPv6 tells whether value is an IPv6 address
func toolDiagIsIPv6(value string) bool {
	var ip = net.ParseIP(value)
	return ip != nil && ip.To4() == nil
}

// toolDiagFamily returns the family argument or the one of the address (ipv4 or ipv6)
func toolDiagFamily(args *Args) string {
	if args.Has("family") {
		return strings.ToLower(args.String("family"))
	}
	if toolDiagIsIPv6(args.String("address")) || toolDiagIsIPv6(args.String("source")) {
		return "ipv6"
	}
	return "ipv4"
}

// toolDiagCheckFamily refuses addresses that do not match the family (Command.Check)
func toolDiagCheckFamily(args *Args) error {
	var family = toolDiagFamily(args)
	for _, name := range []string{"address", "source"} {
		var ip = net.ParseIP(args.String(name))
		if ip == nil {
			continue
		}
		if isIPv6 := ip.To4() == nil; isIPv6 != (family == "ipv6") {
			return fmt.Errorf("%s %s is not an %s address", name, args.String(name), family)
		}
	}
	return nil
}

// toolDiagInet maps the family to the ipproto values of traceroute and portprobe (inet, inet6)
func toolDiagInet(family string) string {
	if family == "ipv6" {
		return "inet6"
	}
	return "inet"
}

// toolDiagMs renders a round trip time in milliseconds, "" for nil
func toolDiagMs(value *float64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%.3fms", *value)
}
