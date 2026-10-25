package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
	"strconv"
	"strings"
)

// Shared parts of the /dnsmasq menus (host, domain, lease, service)

func init() {
	Root.Menu("dnsmasq").Help = "Dnsmasq DNS & DHCP"
}

// dnsmasqApplyHint ends the help of the commands that change the configuration
const dnsmasqApplyHint = `Changes are only saved, run "/dnsmasq/service reconfigure" to apply them.`

// dnsmasqApi returns the Dnsmasq API on the session's connection
func dnsmasqApi(c *Context) (*dnsmasq.DnsmasqApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &dnsmasq.DnsmasqApi{OPNsense: opn}, nil
}

// dnsmasqSearch queries api/dnsmasq/<controller>/<method> and returns the rows both raw (for json output) and
// decoded, in the same (API) order
func dnsmasqSearch[T any](api *dnsmasq.DnsmasqApi, controller string, method string, searchPhrase string) ([]json.RawMessage, []T, error) {
	var endpoint = api.EndpointForPluginControllerMethod("dnsmasq", controller, method)
	var raws, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var items = make([]T, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &items[i]); err != nil {
			return nil, nil, fmt.Errorf("could not decode a row of %s: %w", endpoint, err)
		}
	}
	return raws, items, nil
}

// dnsmasqPrintJSON writes the raw rows as ndjson
func dnsmasqPrintJSON(c *Context, raws []json.RawMessage) error {
	for _, raw := range raws {
		if err := c.JSON(raw); err != nil {
			return err
		}
	}
	return nil
}

// dnsmasqNotEmpty is a validator for string arguments that must not be given empty (host=, domain=)
func dnsmasqNotEmpty(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty")
	}
	return nil
}

// dnsmasqValidateSeconds accepts a non-negative number of seconds
func dnsmasqValidateSeconds(value string) error {
	if value == "" {
		return nil
	}
	if seconds, err := strconv.Atoi(value); err != nil || seconds < 0 {
		return fmt.Errorf("must be a number of seconds, got %q", value)
	}
	return nil
}

// dnsmasqNormalizeIPs returns the addresses in canonical form (fd00:0::1 -> fd00::1) comma joined, the values
// were validated by the argument spec
func dnsmasqNormalizeIPs(values []string) string {
	var normalized = make([]string, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			value = ip.String()
		}
		normalized = append(normalized, value)
	}
	return strings.Join(normalized, ",")
}

// dnsmasqNormalizeMACs returns the MAC addresses in canonical form (AA-BB-.. -> aa:bb:..) comma joined
func dnsmasqNormalizeMACs(values []string) string {
	var normalized = make([]string, 0, len(values))
	for _, value := range values {
		if mac, err := net.ParseMAC(value); err == nil {
			value = mac.String()
		}
		normalized = append(normalized, value)
	}
	return strings.Join(normalized, ",")
}

// dnsmasqSameIP compares two addresses semantically (fd00::1 = FD00:0::1), other values case-insensitively
func dnsmasqSameIP(a string, b string) bool {
	var ipA, ipB = net.ParseIP(a), net.ParseIP(b)
	if ipA != nil && ipB != nil {
		return ipA.Equal(ipB)
	}
	return strings.EqualFold(a, b)
}

// dnsmasqSameName compares domain names case-insensitively, ignoring a trailing dot
func dnsmasqSameName(a string, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(a), "."), strings.TrimSuffix(strings.TrimSpace(b), "."))
}

// dnsmasqListCell renders a comma separated API list for a table cell
func dnsmasqListCell(value string) string {
	return strings.ReplaceAll(value, ",", ", ")
}

// dnsmasqIsIndex tells whether an item selector is a # index
func dnsmasqIsIndex(selector string) bool {
	var _, err = strconv.Atoi(strings.TrimSpace(selector))
	return err == nil
}
