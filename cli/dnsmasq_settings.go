package cli

// /dnsmasq/settings: the general DNS and DHCP settings of Dnsmasq (api/dnsmasq/settings/get|set)

func init() {
	var boolean = func(name string, api string, help string) dnsSetting {
		return dnsSetting{Arg: Arg{Name: name, Type: Bool, Help: help}, Api: api, Kind: dnsBool}
	}
	var number = func(name string, api string, help string, min int, max int) dnsSetting {
		return dnsSetting{Arg: Arg{Name: name, Type: Int, Help: help, Validate: ValidateRange(min, max)}, Api: api}
	}
	var menu = &dnsSettingsMenu{
		Path:      "dnsmasq/settings",
		Help:      "general DNS and DHCP settings of Dnsmasq",
		What:      "Dnsmasq settings",
		ApplyHint: dnsmasqApplyHint,
		SetLong: `Changes the given settings, the others are kept. interface= (listen on all interfaces) and
dhcp-no-interface= take comma separated interface keys (see "print options=interface"), an empty value clears them.

  set dhcp-domain=lan.example dhcp-authoritative
  set cache-size=10000 log-queries=no`,
		Settings: []dnsSetting{
			boolean("enabled", "enable", "run Dnsmasq"),
			{Arg: Arg{Name: "interface", Type: List, Help: "interfaces to listen on, empty for all"}, Api: "interface", Kind: dnsList, Options: true},
			number("port", "port", "DNS port, 0 disables the DNS function, empty for 53", 0, 65535),
			boolean("strict-bind", "strictbind", "bind only to the selected interfaces' addresses"),
			boolean("register-dhcp", "regdhcp", "register DHCP leases in DNS"),
			boolean("register-dhcp-static", "regdhcpstatic", "register static DHCP mappings in DNS"),
			{Arg: Arg{Name: "register-dhcp-domain", Help: "domain of the registered DHCP names, empty for the system domain"}, Api: "regdhcpdomain"},
			boolean("dhcp-first", "dhcpfirst", "answer registered DHCP names before other sources"),
			boolean("strict-order", "strict_order", "ask the upstream servers in the order of resolv.conf"),
			boolean("domain-needed", "domain_needed", "never forward names without a dot"),
			boolean("no-private-reverse", "no_private_reverse", "never forward reverse lookups of private addresses"),
			boolean("no-resolv", "no_resolv", "don't read the upstream servers from resolv.conf"),
			boolean("no-hosts", "no_hosts", "don't read /etc/hosts"),
			boolean("log-queries", "log_queries", "log the DNS queries"),
			boolean("dnssec", "dnssec", "validate DNSSEC"),
			number("dns-forward-max", "dns_forward_max", "maximum concurrent upstream queries, empty for the default", 0, 1<<31-1),
			number("cache-size", "cache_size", "number of cached names, empty for the default", 0, 1<<31-1),
			number("local-ttl", "local_ttl", "TTL of local answers in seconds, empty for 0", 0, 1<<31-1),
			{Arg: Arg{Name: "add-mac", Help: `add the client MAC to forwarded queries: standard, base64, text, "" for no`, Values: []string{"standard", "base64", "text"}},
				Api: "add_mac", Options: true},
			boolean("add-subnet", "add_subnet", "add the client subnet (EDNS client subnet) to forwarded queries"),
			boolean("strip-subnet", "strip_subnet", "remove a client subnet from forwarded queries"),
			boolean("no-ident", "no_ident", "don't answer the CHAOS queries for the version and author"),
			{Arg: Arg{Name: "dhcp-no-interface", Type: List, Help: "interfaces DHCP is disabled on"}, Api: "dhcp.no_interface", Kind: dnsList, Options: true},
			boolean("dhcp-fqdn", "dhcp.fqdn", "register DHCP clients with their FQDN"),
			{Arg: Arg{Name: "dhcp-domain", Help: "domain of the DHCP clients, empty for the system domain"}, Api: "dhcp.domain"},
			boolean("dhcp-local", "dhcp.local", "answer the DHCP domain locally only"),
			number("dhcp-lease-max", "dhcp.lease_max", "maximum number of leases, empty for the default", 0, 1<<31-1),
			boolean("dhcp-authoritative", "dhcp.authoritative", "be the only DHCP server of the networks"),
			boolean("dhcp-default-fw-rules", "dhcp.default_fw_rules", "add the firewall rules DHCP needs"),
			number("dhcp-reply-delay", "dhcp.reply_delay", "seconds to delay the first DHCP reply, 0-60", 0, 60),
			boolean("dhcp-enable-ra", "dhcp.enable_ra", "send IPv6 router advertisements"),
			boolean("dhcp-host-ping", "dhcp.host_ping", "ping an address before leasing it"),
			boolean("dhcp-nosync", "dhcp.nosync", "don't sync the DHCP settings to the HA peer"),
			boolean("dhcp-log", "dhcp.log_dhcp", "log DHCP options and tags"),
			boolean("dhcp-log-quiet", "dhcp.log_quiet", "don't log the routine DHCP messages"),
		},
		Get: func(c *Context) (dnsSettingsValues, error) {
			var api, err = dnsmasqApi(c)
			if err != nil {
				return dnsSettingsValues{}, err
			}
			return api.SettingsGet()
		},
		Set: func(c *Context, patch map[string]string) error {
			var api, err = dnsmasqApi(c)
			if err != nil {
				return err
			}
			return api.SettingsSet(patch)
		},
	}
	menu.register()
}
