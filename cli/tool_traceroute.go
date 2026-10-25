package cli

import (
	"strings"

	"opnsense-cli/opnsense/api/diagnostics"
)

// /tool traceroute: Interfaces > Diagnostics > Traceroute (api/diagnostics/traceroute/set runs traceroute on the
// firewall and answers the hops when it finished, after up to 20 seconds)

func init() {
	Root.Menu("tool").Add(&Command{
		Name: "traceroute",
		Help: "trace the route from the firewall to a host",
		Long: `Runs traceroute on the firewall (one probe per hop, 2 seconds wait per probe, at most 20 seconds in
total) and prints the hops when it finished. Hops that did not answer are not listed by OPNsense. Ctrl-C stops
waiting for the result.

  traceroute 192.168.1.10
  traceroute fd00::1 protocol=icmp`,
		Args: []Arg{
			toolDiagAddressArg("host name or address to trace"),
			{Name: "protocol", Default: "udp", Values: []string{"udp", "icmp"}, Help: "probe protocol"},
			toolDiagSourceArg,
			toolDiagFamilyArg,
			{Name: "json", Type: Bool, Help: "print the raw result as one JSON object"},
		},
		Check: toolDiagCheckFamily,
		Run:   toolTracerouteRun,
	})
}

func toolTracerouteRun(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var options = diagnostics.TracerouteOptions{
		Hostname:      args.String("address"),
		Family:        toolDiagInet(toolDiagFamily(args)),
		Protocol:      strings.ToLower(args.String("protocol")),
		SourceAddress: args.String("source"),
	}
	result, err := systemActivityAwait(c, func() (diagnostics.TracerouteResult, error) { return api.Traceroute(options) })
	if c.Err() != nil {
		return nil // Ctrl-C
	}
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(result.Raw)
	}
	if result.Notice != "" {
		c.Infof("%s", result.Notice)
	}
	var rows = make([][]string, 0, len(result.Hops))
	for _, hop := range result.Hops {
		var host = hop.Host
		if host == hop.Address {
			host = ""
		}
		rows = append(rows, []string{hop.TTL, hop.Address, host, hop.AS, hop.Probes})
	}
	c.Table([]string{"HOP", "ADDRESS", "HOST", "AS", "TIME"}, rows)
	if result.Error != "" {
		c.Infof("warning: %s (traceroute was stopped after 20 seconds)", result.Error)
	}
	return nil
}
