package cli

import (
	"fmt"
	"net/netip"
	"strings"

	"opnsense-cli/opnsense/api/dhcp"
)

// /kea: the Kea DHCP server (Services > Kea DHCP): /kea/dhcp4 and /kea/dhcp6 with settings, subnets,
// reservations, custom options, HA peers, leases and (v6) prefix delegation pools, /kea/ctrl-agent, /kea/ddns and
// /kea/service. Everything is only saved, "/kea/service reconfigure" applies it

const keaApplyHint = `Changes are only saved, run "/kea/service reconfigure" to apply them.`

func init() {
	Root.Menu("kea").Help = "Kea DHCP server: DHCPv4, DHCPv6, control agent, DDNS and the service (Services > Kea DHCP)"
	Root.Menu("kea/dhcp4").Help = "Kea DHCPv4: settings, subnets, reservations, options, HA peers and leases"
	Root.Menu("kea/dhcp6").Help = "Kea DHCPv6: settings, subnets, reservations, prefix delegation pools, options, HA peers and leases"

	keaRegisterSettings(keaDhcpSettings(4))
	keaRegisterSettings(keaDhcpSettings(6))
	keaRegisterSettings(&keaSettings{
		path: "kea/ctrl-agent", help: "the Kea control agent: the REST API of the Kea daemons, used by HA peers (Services > Kea DHCP > Control Agent)",
		long: "The HA peers talk to each other through the control agent, enable it for high availability.",
		hint: keaApplyHint, spec: dhcp.KeaCtrlAgentSettings,
		fields: []keaField{
			{Arg: Arg{Name: "enabled", Type: Bool, Help: "run the control agent"}, api: "general.enabled", kind: keaFlag},
			{Arg: Arg{Name: "http-host", Help: "IPv4 address the agent listens on (default 127.0.0.1)", Validate: keaValidateAddress(4)}, api: "general.http_host"},
			{Arg: Arg{Name: "http-port", Type: Int, Help: "port the agent listens on (default 8000)", Validate: ValidatePort}, api: "general.http_port"},
		},
	})
	keaRegisterSettings(&keaSettings{
		path: "kea/ddns", help: "Kea DHCP-DDNS: dynamic DNS updates for leases (Services > Kea DHCP > DDNS)",
		long: `The zones, DNS servers and TSIG keys are set per subnet (ddns-* of /kea/dhcp4/subnet and /kea/dhcp6/subnet).`,
		hint: keaApplyHint, spec: dhcp.KeaDdnsSettings,
		fields: []keaField{
			{Arg: Arg{Name: "enabled", Type: Bool, Help: "run the DHCP-DDNS daemon"}, api: "general.enabled", kind: keaFlag},
			{Arg: Arg{Name: "manual-config", Type: Bool, Help: "use the hand-written /usr/local/etc/kea/kea-dhcp-ddns.conf instead of these settings"}, api: "general.manual_config", kind: keaFlag},
			{Arg: Arg{Name: "server-ip", Help: "IPv4 address the daemon listens on for the DHCP servers (default 127.0.0.1)", Validate: keaValidateAddress(4)}, api: "general.server_ip"},
			{Arg: Arg{Name: "server-port", Type: Int, Help: "port it listens on (default 53001)", Validate: ValidatePort}, api: "general.server_port"},
		},
	})

	for _, version := range []int{4, 6} {
		var subnets = keaSubnetItems(version)
		var options = keaOptionItems(version)
		subnets.fields = keaSubnetFields(version, keaRefTo(options))
		keaRegisterItems(subnets)
		keaRegisterItems(keaReservationItems(version, keaRefTo(subnets), keaRefTo(options)))
		keaRegisterItems(options)
		keaRegisterItems(keaPeerItems(version))
		if version == 6 {
			keaRegisterItems(keaPdPoolItems(keaRefTo(subnets)))
		}
	}

	keaRegisterService("kea/service", "the kea service (DHCPv4, DHCPv6, control agent and DDNS daemons)", dhcp.KeaService,
		"apply the saved configuration: regenerate it and (re)start Kea when DHCPv4 or DHCPv6 is enabled, else stop it",
		"This stops the Kea DHCP server, clients can not get or renew leases until it is started again.",
		"This restarts the Kea DHCP server, DHCP is unavailable for a moment.")
}

// keaRecordsOf adapts a collection getter to the item menu
func keaRecordsOf(get func(api *dhcp.DhcpApi) keaRecords) func(c *Context) (keaRecords, error) {
	return func(c *Context) (keaRecords, error) {
		var dhcpApi, err = keaApi(c)
		if err != nil {
			return nil, err
		}
		return get(dhcpApi), nil
	}
}

// keaRefTo makes the records of an item menu the target of reference arguments, named like its items
func keaRefTo(spec *keaItems) *keaRefSpec {
	return &keaRefSpec{
		what: spec.noun,
		rows: func(c *Context) ([]dhcp.Row, error) {
			var records, err = spec.records(c)
			if err != nil {
				return nil, err
			}
			var rows, _, rowsErr = records.Rows("")
			return rows, rowsErr
		},
		names: spec.names,
	}
}

func keaRequired(add bool, arg Arg) Arg {
	arg.Required = add
	return arg
}

func keaColumnOf(header string, api string) keaColumn {
	return keaColumn{header: header, value: func(row dhcp.Row) string { return row[api] }}
}

// keaRefColumn shows a relation by the display value OPNsense sends with the row
func keaRefColumn(header string, api string) keaColumn {
	return keaColumn{header: header, value: func(row dhcp.Row) string { return row.Display(api) }}
}

// --- settings

func keaDhcpSettings(version int) *keaSettings {
	var spec, controller = dhcp.KeaDhcp4Settings, "dhcpv4"
	if version == 6 {
		spec, controller = dhcp.KeaDhcp6Settings, "dhcpv6"
	}
	var fields = []keaField{
		{Arg: Arg{Name: "enabled", Type: Bool, Help: "run the DHCPv" + fmt.Sprint(version) + " server"}, api: "general.enabled", kind: keaFlag},
		{Arg: Arg{Name: "interfaces", Type: List, Help: "interfaces to serve (keys like lan), at least one for the server to run"}, api: "general.interfaces", kind: keaList, options: true},
		{Arg: Arg{Name: "manual-config", Type: Bool, Help: "use the hand-written /usr/local/etc/kea/kea-dhcp" + fmt.Sprint(version) + ".conf instead of these settings"}, api: "general.manual_config", kind: keaFlag},
		{Arg: Arg{Name: "valid-lifetime", Type: Int, Help: "default lease time in seconds (4000)", Validate: keaValidateMin(0)}, api: "general.valid_lifetime"},
		{Arg: Arg{Name: "decline-probation-period", Type: Int, Help: "seconds a declined address is not offered again", Validate: keaValidateMin(0)}, api: "general.decline_probation_period"},
		{Arg: Arg{Name: "socket-retries", Type: Int, Help: "how often to retry opening the sockets of the interfaces", Validate: keaValidateMin(0)}, api: "general.service_sockets_max_retries"},
		{Arg: Arg{Name: "socket-retry-wait", Type: Int, Help: "milliseconds between two socket retries", Validate: keaValidateMin(0)}, api: "general.service_sockets_retry_wait_time"},
		{Arg: Arg{Name: "firewall-rules", Type: Bool, Help: "add the firewall rules DHCP needs on the interfaces (default yes)"}, api: "general.fwrules", kind: keaFlag},
	}
	if version == 4 {
		fields = append(fields,
			keaField{Arg: Arg{Name: "socket-type", Values: []string{"raw", "udp"}, Help: "raw (default, also serves clients without an address) or udp (relayed traffic only)"},
				api: "general.dhcp_socket_type"},
			keaField{Arg: Arg{Name: "compatibility", Type: List, Values: []string{"exclude-first-last-24", "ignore-dhcp-server-identifier", "ignore-rai-link-selection", "lenient-option-parsing"},
				Help: "compatibility flags for broken clients"}, api: "general.compatibility", kind: keaList})
	} else {
		fields = append(fields, keaField{Arg: Arg{Name: "mac-sources", Type: List,
			Values: []string{"duid", "ipv6-link-local", "client-link-addr-option", "remote-id", "docsis-cmts", "docsis-modem"},
			Help:   "where to take the MAC address of a client from, in this order (default ipv6-link-local)"}, api: "general.mac_sources", kind: keaList})
	}
	fields = append(fields,
		keaField{Arg: Arg{Name: "hold-reclaimed-time", Type: Int, Help: "seconds expired leases are kept", Validate: keaValidateMin(0)}, api: "lexpire.hold_reclaimed_time"},
		keaField{Arg: Arg{Name: "reclaim-timer-wait-time", Type: Int, Help: "seconds between two reclaim runs", Validate: keaValidateMin(1)}, api: "lexpire.reclaim_timer_wait_time"},
		keaField{Arg: Arg{Name: "flush-reclaimed-timer-wait-time", Type: Int, Help: "seconds between two removals of held leases", Validate: keaValidateMin(0)}, api: "lexpire.flush_reclaimed_timer_wait_time"},
		keaField{Arg: Arg{Name: "max-reclaim-time", Type: Int, Help: "milliseconds one reclaim run may take", Validate: keaValidateMin(0)}, api: "lexpire.max_reclaim_time"},
		keaField{Arg: Arg{Name: "max-reclaim-leases", Type: Int, Help: "leases reclaimed per run", Validate: keaValidateMin(0)}, api: "lexpire.max_reclaim_leases"},
		keaField{Arg: Arg{Name: "unwarned-reclaim-cycles", Type: Int, Help: "incomplete runs before a warning", Validate: keaValidateMin(0)}, api: "lexpire.unwarned_reclaim_cycles"},
		keaField{Arg: Arg{Name: "ha", Type: Bool, Help: "high availability with the peers of /kea/dhcp" + fmt.Sprint(version) + "/peer (needs the control agent)"}, api: "ha.enabled", kind: keaFlag},
		keaField{Arg: Arg{Name: "ha-this-server-name", Help: "name of this server among the peers, empty for the hostname", Validate: keaValidateText}, api: "ha.this_server_name"},
		keaField{Arg: Arg{Name: "ha-max-unacked-clients", Type: Int, Help: "unanswered clients before the partner is considered down (default 2)", Validate: ValidateRange(0, 65535)}, api: "ha.max_unacked_clients"},
	)
	return &keaSettings{
		path: fmt.Sprintf("kea/dhcp%d/settings", version),
		help: fmt.Sprintf("the general DHCPv%d settings (Services > Kea DHCP > Kea DHCPv%d > Settings)", version, version),
		long: fmt.Sprintf(`Kea only serves the interfaces given here; don't let it serve an interface another DHCP server (e.g.
dnsmasq) serves already. The settings are those of api/kea/%s, sections general, lexpire and ha.`, controller),
		hint: keaApplyHint, spec: spec, fields: fields,
	}
}

// --- subnets

func keaSubnetItems(version int) *keaItems {
	var records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaSubnets4() })
	var columns = []keaColumn{
		keaColumnOf("SUBNET", "subnet"),
		{header: "POOLS", value: func(row dhcp.Row) string { return keaLinesText(row["pools"]) }},
		keaColumnOf("ROUTERS", "option_data.routers"),
		keaColumnOf("DNS-SERVERS", "option_data.domain_name_servers"),
		keaColumnOf("DESCRIPTION", "description"),
	}
	var long = `Pools are address ranges first-last or networks in CIDR notation inside the subnet. With auto-options
(the default) OPNsense fills routers, dns-servers and ntp-servers with the firewall's address in the subnet on every
save, give auto-options=no to set them yourself.`
	if version == 6 {
		records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaSubnets6() })
		columns = []keaColumn{
			{header: "SUBNET", value: func(row dhcp.Row) string {
				if row["dynamic_prefix"] == "1" {
					return "dynamic"
				}
				return row["subnet"]
			}},
			keaColumnOf("INTERFACE", "interface"),
			{header: "POOLS", value: func(row dhcp.Row) string { return keaLinesText(row["pools"]) }},
			keaColumnOf("DNS-SERVERS", "option_data.dns_servers"),
			keaColumnOf("DESCRIPTION", "description"),
		}
		long = `A subnet is served on one interface, which must be one of the interfaces of "/kea/dhcp6/settings". With
dynamic-prefix the subnet follows the prefix delegated to the interface (subnet and pools stay empty).`
	}
	return &keaItems{
		path:     fmt.Sprintf("kea/dhcp%d/subnet", version),
		help:     fmt.Sprintf("DHCPv%d subnets with their pools and options (Services > Kea DHCP > Kea DHCPv%d > Subnets)", version, version),
		noun:     "subnet",
		itemHelp: "the #, uuid, network or description of the subnet",
		addLong:  long,
		hint:     keaApplyHint,
		records:  records,
		columns:  columns,
		names: func(row dhcp.Row) []string {
			var names = []string{row["subnet"], row["description"]}
			if row["dynamic_prefix"] == "1" {
				names = append(names, row["interface"])
			}
			return names
		},
		key: "network",
		same: func(row dhcp.Row, fields dhcp.Fields) bool {
			if fields["subnet"] != "" {
				return keaSameNetwork(row["subnet"], fields["subnet"])
			}
			return fields["dynamic_prefix"] == "1" && row["dynamic_prefix"] == "1" && row["interface"] == fields["interface"]
		},
		check: func(add bool, args *Args) error {
			if version == 6 && add && args.String("subnet") == "" && !args.Bool("dynamic-prefix") {
				return fmt.Errorf("add: subnet= is required (or dynamic-prefix)")
			}
			return nil
		},
	}
}

// keaSubnetFields are the field arguments of the subnets, options refers to the custom options
func keaSubnetFields(version int, options *keaRefSpec) func(add bool) []keaField {
	return func(add bool) []keaField {
		var subnet = Arg{Name: "subnet", Help: "the network in CIDR notation, like 198.51.100.0/24", Validate: keaValidateNetwork(4)}
		var fields []keaField
		if version == 4 {
			fields = []keaField{
				{Arg: keaRequired(add, subnet), api: "subnet"},
				{Arg: Arg{Name: "description", Help: "description", Validate: keaValidateText}, api: "description"},
				{Arg: Arg{Name: "pools", Type: List, Help: "address pools: ranges like 198.51.100.10-198.51.100.99 or networks", Validate: keaValidatePools(4)}, api: "pools", kind: keaLines},
				{Arg: Arg{Name: "valid-lifetime", Type: Int, Help: "lease time in seconds, empty for the default of the settings", Validate: keaValidateMin(0)}, api: "valid_lifetime"},
				{Arg: Arg{Name: "auto-options", Type: Bool, Help: "set routers, dns-servers and ntp-servers to the firewall's address in the subnet (default yes)"}, api: "option_data_autocollect", kind: keaFlag},
				{Arg: Arg{Name: "routers", Type: List, Help: "default gateways (option 3)", Validate: keaValidateAddresses(4)}, api: "option_data.routers", kind: keaList},
				{Arg: Arg{Name: "dns-servers", Type: List, Help: "DNS servers (option 6)", Validate: keaValidateAddresses(4)}, api: "option_data.domain_name_servers", kind: keaList},
				{Arg: Arg{Name: "domain-name", Help: "domain name (option 15), empty for the system domain", Validate: keaValidateDomain}, api: "option_data.domain_name"},
				{Arg: Arg{Name: "domain-search", Type: List, Help: "domain search list (option 119)", Validate: keaValidateDomains}, api: "option_data.domain_search", kind: keaList},
				{Arg: Arg{Name: "ntp-servers", Type: List, Help: "NTP servers (option 42)", Validate: keaValidateAddresses(4)}, api: "option_data.ntp_servers", kind: keaList},
				{Arg: Arg{Name: "time-servers", Type: List, Help: "time servers (option 4)", Validate: keaValidateAddresses(4)}, api: "option_data.time_servers", kind: keaList},
				{Arg: Arg{Name: "static-routes", Type: List, Help: "destination,router address pairs (option 33)", Validate: keaValidateStaticRoutes}, api: "option_data.static_routes", kind: keaList},
				{Arg: Arg{Name: "classless-routes", Type: List, Help: "network-router pairs like 10.0.0.0/8-198.51.100.1 (option 121)", Validate: keaValidateClasslessRoutes}, api: "option_data.classless_static_route", kind: keaList},
				{Arg: Arg{Name: "tftp-server", Help: "TFTP server name (option 66)", Validate: keaValidateOptionText}, api: "option_data.tftp_server_name"},
				{Arg: Arg{Name: "boot-file", Help: "boot file name (option 67)", Validate: keaValidateOptionText}, api: "option_data.boot_file_name"},
				{Arg: Arg{Name: "v6-only-preferred", Type: Int, Help: "IPv6-only preferred seconds (option 108, at least 300)", Validate: keaValidateMin(300)}, api: "option_data.v6_only_preferred"},
				{Arg: Arg{Name: "dnr", Help: "encrypted DNS resolvers (option 162), Kea's DNR notation", Validate: keaValidateOptionText}, api: "option_data.v4_dnr"},
				{Arg: Arg{Name: "next-server", Help: "next server address for network boot (siaddr)", Validate: keaValidateAddress(4)}, api: "next_server"},
				{Arg: Arg{Name: "match-client-id", Type: Bool, Help: "identify clients by their client id when they send one (default yes)"}, api: "match-client-id", kind: keaFlag},
				{Arg: Arg{Name: "allocator", Values: []string{"iterative", "random", "flq"}, Help: "address allocation strategy, empty for the default"}, api: "allocator"},
			}
		} else {
			subnet.Help, subnet.Validate = "the network in CIDR notation, like 2001:db8::/64 (empty with dynamic-prefix)", keaValidateNetwork(6)
			fields = []keaField{
				{Arg: subnet, api: "subnet"},
				{Arg: keaRequired(add, Arg{Name: "interface", Help: "the interface to serve the subnet on (key like lan), one of the interfaces of the settings"}),
					api: "interface", options: true},
				{Arg: Arg{Name: "description", Help: "description", Validate: keaValidateText}, api: "description"},
				{Arg: Arg{Name: "pools", Type: List, Help: "address pools: ranges like 2001:db8::100-2001:db8::1ff or networks", Validate: keaValidatePools(6)}, api: "pools", kind: keaLines},
				{Arg: Arg{Name: "dynamic-prefix", Type: Bool, Help: "follow the prefix delegated to the interface, without subnet and pools"}, api: "dynamic_prefix", kind: keaFlag},
				{Arg: Arg{Name: "valid-lifetime", Type: Int, Help: "lease time in seconds, empty for the default of the settings", Validate: keaValidateMin(0)}, api: "valid_lifetime"},
				{Arg: Arg{Name: "auto-options", Type: Bool, Help: "set dns-servers and domain-search automatically (default no)"}, api: "option_data_autocollect", kind: keaFlag},
				{Arg: Arg{Name: "dns-servers", Type: List, Help: "DNS servers (option 23)", Validate: keaValidateAddresses(6)}, api: "option_data.dns_servers", kind: keaList},
				{Arg: Arg{Name: "domain-search", Type: List, Help: "domain search list (option 24)", Validate: keaValidateDomains}, api: "option_data.domain_search", kind: keaList},
				{Arg: Arg{Name: "dnr", Help: "encrypted DNS resolvers (option 144), Kea's DNR notation", Validate: keaValidateOptionText}, api: "option_data.v6_dnr"},
				{Arg: Arg{Name: "allocator", Values: []string{"iterative", "random", "flq"}, Help: "address allocation strategy, empty for the default"}, api: "allocator"},
				{Arg: Arg{Name: "pd-allocator", Values: []string{"iterative", "random", "flq"}, Help: "prefix allocation strategy, empty for the default"}, api: "pd-allocator"},
			}
		}
		fields = append(fields, keaField{Arg: Arg{Name: "options", Type: List, Help: "custom options (their descriptions) sent to the clients of the subnet",
			Complete: keaRefNames(options)}, api: "option", kind: keaRefList, ref: options})
		return append(fields, keaDdnsFields()...)
	}
}

// keaDdnsFields are the dynamic DNS fields of a subnet
func keaDdnsFields() []keaField {
	return []keaField{
		{Arg: Arg{Name: "ddns-forward-zone", Help: "DNS zone to register the leases in (needs ddns-server)", Validate: keaValidateDomain}, api: "ddns_forward_zone"},
		{Arg: Arg{Name: "ddns-reverse-zone", Help: "reverse DNS zone, like 100.51.198.in-addr.arpa", Validate: keaValidateDomain}, api: "ddns_reverse_zone"},
		{Arg: Arg{Name: "ddns-qualifying-suffix", Help: "suffix appended to client names without domain", Validate: keaValidateDomain}, api: "ddns_qualifying_suffix"},
		{Arg: Arg{Name: "ddns-server", Help: "DNS server to send the updates to", Validate: keaValidateAddress(0)}, api: "ddns_dns_server"},
		{Arg: Arg{Name: "ddns-port", Type: Int, Help: "port of the DNS server, empty for 53", Validate: ValidatePort}, api: "ddns_dns_port"},
		{Arg: Arg{Name: "ddns-key-name", Help: "TSIG key name (needs ddns-key-secret)", Validate: keaValidateText}, api: "ddns_domain_key_name"},
		{Arg: Arg{Name: "ddns-key-secret", Help: "TSIG key secret, base64 (never shown)", Validate: keaValidateText}, api: "ddns_domain_key_secret", kind: keaSecret},
		{Arg: Arg{Name: "ddns-key-algorithm", Values: []string{"hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"},
			Help: "TSIG algorithm, required with a secret"}, api: "ddns_domain_key_algorithm"},
		{Arg: Arg{Name: "ddns-override-no-update", Type: Bool, Help: "update DNS even when the client asked not to"}, api: "ddns_override_no_update", kind: keaFlag},
		{Arg: Arg{Name: "ddns-override-client-update", Type: Bool, Help: "update DNS even when the client wants to do it itself"}, api: "ddns_override_client_update", kind: keaFlag},
		{Arg: Arg{Name: "ddns-update-on-renew", Type: Bool, Help: "update DNS on every renewal"}, api: "ddns_update_on_renew", kind: keaFlag},
		{Arg: Arg{Name: "ddns-conflict-resolution", Values: []string{"no-check-with-dhcid", "check-exists-with-dhcid", "no-check-without-dhcid"},
			Help: "conflict resolution mode, empty for check-with-dhcid"}, api: "ddns_conflict_resolution_mode"},
	}
}

// --- reservations

func keaReservationItems(version int, subnets *keaRefSpec, options *keaRefSpec) *keaItems {
	var records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaReservations4() })
	var identifier = func(row dhcp.Row) string {
		if row["hw_address"] != "" {
			return row["hw_address"]
		}
		return row["client_id"]
	}
	var columns = []keaColumn{
		keaRefColumn("SUBNET", "subnet"),
		keaColumnOf("IP-ADDRESS", "ip_address"),
		{header: "MAC/CLIENT-ID", value: identifier},
		keaColumnOf("HOSTNAME", "hostname"),
		keaColumnOf("DESCRIPTION", "description"),
	}
	var names = func(row dhcp.Row) []string {
		return []string{row["hostname"], row["hw_address"], row["ip_address"], row["client_id"], row["description"]}
	}
	var key = "subnet and MAC address or client id"
	var same = func(row dhcp.Row, fields dhcp.Fields) bool {
		return row["subnet"] == fields["subnet"] &&
			(fields["hw_address"] != "" && keaSameMAC(row["hw_address"], fields["hw_address"]) ||
				fields["client_id"] != "" && strings.EqualFold(row["client_id"], fields["client_id"]))
	}
	var idArgs = [2]string{"mac-address", "client-id"}
	if version == 6 {
		records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaReservations6() })
		identifier = func(row dhcp.Row) string {
			if row["duid"] != "" {
				return row["duid"]
			}
			return row["hw_address"]
		}
		columns = []keaColumn{
			keaRefColumn("SUBNET", "subnet"),
			keaColumnOf("IP-ADDRESS", "ip_address"),
			keaColumnOf("PREFIX", "prefix"),
			{header: "DUID/MAC", value: identifier},
			keaColumnOf("HOSTNAME", "hostname"),
			keaColumnOf("DESCRIPTION", "description"),
		}
		names = func(row dhcp.Row) []string {
			return []string{row["hostname"], row["duid"], row["hw_address"], row["ip_address"], row["prefix"], row["description"]}
		}
		key = "subnet and DUID or MAC address"
		same = func(row dhcp.Row, fields dhcp.Fields) bool {
			return row["subnet"] == fields["subnet"] &&
				(fields["duid"] != "" && strings.EqualFold(row["duid"], fields["duid"]) ||
					fields["hw_address"] != "" && keaSameMAC(row["hw_address"], fields["hw_address"]))
		}
		idArgs = [2]string{"duid", "mac-address"}
	}
	return &keaItems{
		path: fmt.Sprintf("kea/dhcp%d/reservation", version),
		help: fmt.Sprintf("DHCPv%d reservations: fixed addresses for clients (Services > Kea DHCP > Kea DHCPv%d > Reservations)", version, version),
		noun: "reservation", itemHelp: "the #, uuid, hostname, MAC address, IP address or description of the reservation",
		addLong: fmt.Sprintf(`A reservation identifies the client by exactly one of %s and %s. Without subnet= the subnet
containing ip-address= is used; the address must be inside the subnet.`, idArgs[0], idArgs[1]),
		hint:    keaApplyHint,
		records: records,
		fields:  keaReservationFields(version, subnets, options),
		columns: columns,
		names:   names,
		key:     key,
		same:    same,
		check: func(add bool, args *Args) error {
			var first, second = args.String(idArgs[0]), args.String(idArgs[1])
			if first != "" && second != "" {
				return fmt.Errorf("give either %s or %s, not both", idArgs[0], idArgs[1])
			}
			if add && first == "" && second == "" {
				return fmt.Errorf("add: %s= or %s= is required", idArgs[0], idArgs[1])
			}
			if add && version == 6 && args.String("ip-address") == "" && args.String("prefix") == "" {
				return fmt.Errorf("add: ip-address= or prefix= is required")
			}
			if add && args.String("subnet") == "" && args.String("ip-address") == "" {
				return fmt.Errorf("add: subnet= is required when no ip-address= is given")
			}
			return nil
		},
		prepare: func(c *Context, add bool, fields dhcp.Fields) error {
			if !add || fields["subnet"] != "" {
				return nil
			}
			var rows, err = subnets.rows(c)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if keaNetworkContains(row["subnet"], fields["ip_address"]) {
					fields["subnet"] = row.Uuid()
					return nil
				}
			}
			return fmt.Errorf("no DHCPv%d subnet contains %s, give subnet=", version, fields["ip_address"])
		},
	}
}

func keaReservationFields(version int, subnets *keaRefSpec, options *keaRefSpec) func(add bool) []keaField {
	return func(add bool) []keaField {
		var fields = []keaField{
			{Arg: Arg{Name: "subnet", Help: "the subnet (its network, description or uuid), default: the one containing ip-address",
				Complete: keaRefNames(subnets)}, api: "subnet", kind: keaRef, ref: subnets},
			{Arg: Arg{Name: "ip-address", Help: "the reserved address", Validate: keaValidateAddress(version)}, api: "ip_address"},
		}
		if version == 4 {
			fields = append(fields,
				keaField{Arg: Arg{Name: "mac-address", Help: "MAC address of the client", Validate: keaValidateMAC}, api: "hw_address"},
				keaField{Arg: Arg{Name: "client-id", Help: "client id of the client, hex bytes like 01:02:f3", Validate: keaValidateHexId}, api: "client_id"},
				keaField{Arg: Arg{Name: "hostname", Help: "host name given to the client", Validate: keaValidateDomain}, api: "hostname"},
				keaField{Arg: Arg{Name: "description", Help: "description", Validate: keaValidateText}, api: "description"},
				keaField{Arg: Arg{Name: "next-server", Help: "next server address for network boot", Validate: keaValidateAddress(4)}, api: "next_server"},
				keaField{Arg: Arg{Name: "routers", Type: List, Help: "default gateways (option 3) instead of the subnet's", Validate: keaValidateAddresses(4)}, api: "option_data.routers", kind: keaList},
				keaField{Arg: Arg{Name: "dns-servers", Type: List, Help: "DNS servers (option 6)", Validate: keaValidateAddresses(4)}, api: "option_data.domain_name_servers", kind: keaList},
				keaField{Arg: Arg{Name: "domain-name", Help: "domain name (option 15)", Validate: keaValidateDomain}, api: "option_data.domain_name"},
				keaField{Arg: Arg{Name: "domain-search", Type: List, Help: "domain search list (option 119)", Validate: keaValidateDomains}, api: "option_data.domain_search", kind: keaList},
				keaField{Arg: Arg{Name: "ntp-servers", Type: List, Help: "NTP servers (option 42)", Validate: keaValidateAddresses(4)}, api: "option_data.ntp_servers", kind: keaList},
				keaField{Arg: Arg{Name: "time-servers", Type: List, Help: "time servers (option 4)", Validate: keaValidateAddresses(4)}, api: "option_data.time_servers", kind: keaList},
				keaField{Arg: Arg{Name: "static-routes", Type: List, Help: "destination,router address pairs (option 33)", Validate: keaValidateStaticRoutes}, api: "option_data.static_routes", kind: keaList},
				keaField{Arg: Arg{Name: "classless-routes", Type: List, Help: "network-router pairs (option 121)", Validate: keaValidateClasslessRoutes}, api: "option_data.classless_static_route", kind: keaList},
				keaField{Arg: Arg{Name: "tftp-server", Help: "TFTP server name (option 66)", Validate: keaValidateOptionText}, api: "option_data.tftp_server_name"},
				keaField{Arg: Arg{Name: "boot-file", Help: "boot file name (option 67)", Validate: keaValidateOptionText}, api: "option_data.boot_file_name"},
			)
		} else {
			fields = append(fields,
				keaField{Arg: Arg{Name: "prefix", Help: "a reserved delegated prefix in CIDR notation, like 2001:db8:0:100::/56", Validate: keaValidateNetwork(6)}, api: "prefix"},
				keaField{Arg: Arg{Name: "duid", Help: "DUID of the client, hex bytes like 00:01:00:01:...", Validate: keaValidateHexId}, api: "duid"},
				keaField{Arg: Arg{Name: "mac-address", Help: "MAC address of the client", Validate: keaValidateMAC}, api: "hw_address"},
				keaField{Arg: Arg{Name: "hostname", Help: "host name given to the client", Validate: keaValidateDomain}, api: "hostname"},
				keaField{Arg: Arg{Name: "domain-search", Type: List, Help: "domain search list (option 24)", Validate: keaValidateDomains}, api: "domain_search", kind: keaList},
				keaField{Arg: Arg{Name: "description", Help: "description", Validate: keaValidateText}, api: "description"},
			)
		}
		return append(fields, keaField{Arg: Arg{Name: "options", Type: List, Help: "custom options (their descriptions) sent to this client",
			Complete: keaRefNames(options)}, api: "option", kind: keaRefList, ref: options})
	}
}

// --- prefix delegation pools

func keaPdPoolItems(subnets *keaRefSpec) *keaItems {
	var prefixText = func(row dhcp.Row) string {
		if row["prefix"] == "" || row["prefix_len"] == "" {
			return row["prefix"]
		}
		return row["prefix"] + "/" + row["prefix_len"]
	}
	return &keaItems{
		path: "kea/dhcp6/pd-pool", help: "DHCPv6 prefix delegation pools (Services > Kea DHCP > Kea DHCPv6 > PD Pools)",
		noun: "pd pool", itemHelp: "the #, uuid, prefix (with or without length) or description of the pool",
		addLong: `The pool prefix (prefix=2001:db8:100::/56 or prefix= with prefix-length=) is split into prefixes of
delegated-length (default 64) for the clients. For a subnet with dynamic-prefix, prefix and prefix-length stay empty.`,
		hint: keaApplyHint, records: keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaPdPools() }),
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "subnet", Help: "the DHCPv6 subnet (its network, description or uuid)", Complete: keaRefNames(subnets)}),
					api: "subnet", kind: keaRef, ref: subnets},
				{Arg: Arg{Name: "prefix", Help: "the pool prefix, address or CIDR like 2001:db8:100::/56", Validate: keaValidatePrefixOrAddress}, api: "prefix"},
				{Arg: Arg{Name: "prefix-length", Type: Int, Help: "length of the pool prefix (taken from prefix= in CIDR notation)", Validate: ValidateRange(1, 128)}, api: "prefix_len"},
				{Arg: Arg{Name: "delegated-length", Type: Int, Help: "length of the prefixes given to the clients (default 64)", Validate: ValidateRange(1, 128)}, api: "delegated_len"},
				{Arg: Arg{Name: "description", Help: "description", Validate: keaValidateText}, api: "description"},
			}
		},
		columns: []keaColumn{keaRefColumn("SUBNET", "subnet"), {header: "PREFIX", value: prefixText},
			keaColumnOf("DELEGATED-LENGTH", "delegated_len"), keaColumnOf("DESCRIPTION", "description")},
		names: func(row dhcp.Row) []string { return []string{prefixText(row), row["prefix"], row["description"]} },
		key:   "subnet and prefix",
		same: func(row dhcp.Row, fields dhcp.Fields) bool {
			return row["subnet"] == fields["subnet"] && fields["prefix"] != "" && keaSameAddress(row["prefix"], fields["prefix"])
		},
		check: func(_ bool, args *Args) error {
			if strings.Contains(args.String("prefix"), "/") && args.Has("prefix-length") {
				return fmt.Errorf("give the length either in prefix= or as prefix-length=, not both")
			}
			return nil
		},
		prepare: func(_ *Context, _ bool, fields dhcp.Fields) error {
			// prefix=2001:db8:100::/56 is sent as prefix and prefix_len
			if address, length, found := strings.Cut(fields["prefix"], "/"); found {
				fields["prefix"], fields["prefix_len"] = address, length
			}
			return nil
		},
	}
}

// keaValidatePrefixOrAddress accepts an IPv6 address or network in CIDR notation
func keaValidatePrefixOrAddress(value string) error {
	if strings.Contains(value, "/") {
		var prefix, err = netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return fmt.Errorf("must be an IPv6 prefix like 2001:db8:100::/56, got %q", value)
		}
		return nil
	}
	return keaValidateAddress(6)(value)
}

// --- custom options

func keaOptionItems(version int) *keaItems {
	var records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaOptions4() })
	var maxCode = 254
	if version == 6 {
		records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaOptions6() })
		maxCode = 65535
	}
	var encodings = []string{"hex", "ipv4-address", "ipv6-address", "uint8", "uint16", "uint32", "int32", "boolean", "string", "fqdn"}
	return &keaItems{
		path: fmt.Sprintf("kea/dhcp%d/option", version),
		help: fmt.Sprintf("custom DHCPv%d options, sent by the subnets and reservations that list them (Services > Kea DHCP > Kea DHCPv%d > Options)", version, version),
		noun: "option", itemHelp: "the #, uuid or description of the option",
		addLong: `The data is given in the encoding (hex by default; OPNsense refuses encodings that do not fit a known
option). With match-code and match-data the option is only sent to clients that sent that option with that value
(e.g. match-code=60 match-encoding=string match-data=PXEClient). Subnets and reservations refer to options by
their description (options=).`,
		hint: keaApplyHint, records: records,
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "description", Help: "description, also the name of the option (unique)", Validate: keaValidateText}), api: "description"},
				{Arg: keaRequired(add, Arg{Name: "code", Type: Int, Help: "the option code", Validate: ValidateRange(0, maxCode)}), api: "code", options: true},
				{Arg: Arg{Name: "encoding", Values: encodings, Help: "encoding of data (default hex)"}, api: "encoding"},
				{Arg: keaRequired(add, Arg{Name: "data", Help: "the value in the encoding, hex like 0a0b0c", Validate: keaValidateOptionText}), api: "data"},
				{Arg: Arg{Name: "force", Type: Bool, Help: "send the option even when the client did not ask for it"}, api: "force", kind: keaFlag},
				{Arg: Arg{Name: "match-code", Type: Int, Help: "only send to clients that sent this option code (with match-data)", Validate: ValidateRange(0, maxCode)}, api: "match_code", options: true},
				{Arg: Arg{Name: "match-encoding", Values: encodings, Help: "encoding of match-data"}, api: "match_encoding"},
				{Arg: Arg{Name: "match-data", Help: "the value the client must have sent in match-code", Validate: keaValidateOptionText}, api: "match_data"},
			}
		},
		columns: []keaColumn{keaColumnOf("CODE", "code"), keaColumnOf("ENCODING", "encoding"), keaColumnOf("DATA", "data"),
			{header: "MATCH", value: func(row dhcp.Row) string {
				if row["match_code"] == "" {
					return ""
				}
				return row["match_code"] + "=" + row["match_data"]
			}},
			keaColumnOf("DESCRIPTION", "description")},
		names: func(row dhcp.Row) []string { return []string{row["description"]} },
		key:   "description",
		same: func(row dhcp.Row, fields dhcp.Fields) bool {
			return strings.EqualFold(row["description"], fields["description"])
		},
		check: func(_ bool, args *Args) error {
			if args.Has("match-code") && args.Has("match-data") && (args.String("match-code") == "") != (args.String("match-data") == "") {
				return fmt.Errorf("match-code and match-data must be given both or cleared both")
			}
			return nil
		},
	}
}

// --- HA peers

func keaPeerItems(version int) *keaItems {
	var records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaPeers4() })
	if version == 6 {
		records = keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.KeaPeers6() })
	}
	return &keaItems{
		path: fmt.Sprintf("kea/dhcp%d/peer", version),
		help: fmt.Sprintf("DHCPv%d high availability peers (Services > Kea DHCP > Kea DHCPv%d > HA Peers)", version, version),
		noun: "peer", itemHelp: "the #, uuid or name of the peer",
		addLong: `List every server of the HA pair, this one included (its name is ha-this-server-name of the settings or
the hostname); the URL is the control agent of the peer.`,
		hint: keaApplyHint, records: records,
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "name", Help: "name of the server (unique)", Validate: keaValidateText}), api: "name"},
				{Arg: Arg{Name: "role", Values: []string{"primary", "standby"}, Help: "role of the server (default primary)"}, api: "role"},
				{Arg: keaRequired(add, Arg{Name: "url", Help: "URL of its control agent, like http://198.51.100.2:8000/", Validate: keaValidateURL}), api: "url"},
			}
		},
		columns: []keaColumn{keaColumnOf("NAME", "name"), keaColumnOf("ROLE", "role"), keaColumnOf("URL", "url")},
		names:   func(row dhcp.Row) []string { return []string{row["name"]} },
		key:     "name",
		same:    func(row dhcp.Row, fields dhcp.Fields) bool { return row["name"] == fields["name"] },
	}
}
