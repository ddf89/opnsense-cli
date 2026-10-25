package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
)

// /tool dns-lookup: Interfaces > Diagnostics > DNS Lookup (api/diagnostics/dns_diagnostics/set queries A, AAAA,
// MX and TXT records of a name with drill, or the PTR records of an address with host, on the firewall)

func init() {
	Root.Menu("tool").Add(&Command{
		Name: "dns-lookup",
		Help: "resolve a name (A, AAAA, MX, TXT) or an address (PTR) on the firewall",
		Long: `Queries the DNS from the firewall: a host name is looked up for its A, AAAA, MX and TXT records, an
address for its PTR records (reverse lookup). Without server the resolvers of the firewall (System > Settings >
General) are asked. A name without any of these records is an error (exit code 1).

  dns-lookup opnsense.org
  dns-lookup 192.168.1.1 server=127.0.0.1`,
		Args: []Arg{
			{Name: "name", Positional: true, Required: true, Help: "host name, or address for a reverse lookup", Validate: toolDiagValidateHost},
			{Name: "server", Help: "address of the DNS server to ask (default: the resolvers of the firewall)", Validate: ValidateIP},
			{Name: "json", Type: Bool, Help: "print the raw result as one JSON object"},
		},
		Run: toolDnsLookupRun,
	})
}

func toolDnsLookupRun(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var name, server = args.String("name"), args.String("server")
	result, err := systemActivityAwait(c, func() (diagnostics.DnsLookupResult, error) { return api.DnsLookup(name, server) })
	if c.Err() != nil {
		return nil // Ctrl-C
	}
	if err != nil {
		return err
	}
	if args.Bool("json") {
		if err := c.JSON(result.Raw); err != nil {
			return err
		}
	}
	if result.Error != "" {
		return fmt.Errorf("dns-lookup %s: %s", name, strings.TrimPrefix(result.Error, "Error: "))
	}
	var answers = result.Answers()
	if len(answers) == 0 {
		return fmt.Errorf("dns-lookup %s: no records found", name)
	}
	if args.Bool("json") {
		return nil
	}

	var rows = make([][]string, 0, len(answers))
	for _, answer := range answers {
		rows = append(rows, []string{answer.Type, answer.Name, answer.TTL, answer.Data})
	}
	c.Table([]string{"TYPE", "NAME", "TTL", "DATA"}, rows)
	for _, recordType := range result.Types() {
		var records = result.Records[recordType]
		if records.Server != "" || records.QueryTime != "" {
			c.Infof("%s: answered by %s in %s", recordType, toolDnsLookupOr(records.Server, "?"), toolDnsLookupOr(records.QueryTime, "?"))
		}
	}
	return nil
}

func toolDnsLookupOr(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
