package cli

import (
	"fmt"
	"strings"
)

// /unbound/settings and /unbound/advanced: the General and Advanced settings of Unbound (api/unbound/settings/get|set)

const unboundSettingsApplyHint = `Changes are only saved, run "/unbound/service reconfigure general" to apply them.`

func unboundSettingsGet(c *Context) (dnsSettingsValues, error) {
	var api, err = unboundApi(c)
	if err != nil {
		return dnsSettingsValues{}, err
	}
	return api.SettingsGet()
}

func unboundSettingsSet(c *Context, patch map[string]string) error {
	var api, err = unboundApi(c)
	if err != nil {
		return err
	}
	return api.SettingsSet(patch)
}

// unboundSettings builds the settings of one section: the API names get the section prefix
func unboundSettings(section string, settings ...dnsSetting) []dnsSetting {
	for i := range settings {
		settings[i].Api = section + "." + settings[i].Api
	}
	return settings
}

func unboundBool(name string, api string, help string) dnsSetting {
	return dnsSetting{Arg: Arg{Name: name, Type: Bool, Help: help}, Api: api, Kind: dnsBool}
}

func unboundNumber(name string, api string, help string) dnsSetting {
	return dnsSetting{Arg: Arg{Name: name, Type: Int, Help: help, Validate: ValidateRange(0, 1<<31-1)}, Api: api}
}

func unboundList(name string, api string, help string) dnsSetting {
	return dnsSetting{Arg: Arg{Name: name, Type: List, Help: help}, Api: api, Kind: dnsList}
}

// unboundValidateCacheSize accepts a size like 4m, 512k or 1g
func unboundValidateCacheSize(value string) error {
	var number = strings.TrimRight(strings.ToLower(value), "kmg")
	if value == "" {
		return nil
	}
	if err := ValidateRange(0, 1<<31-1)(number); err != nil || number == "" {
		return fmt.Errorf("must be a size like 4m, 512k or 1g, got %q", value)
	}
	return nil
}

func init() {
	(&dnsSettingsMenu{
		Path:      "unbound/settings",
		Help:      "general settings of Unbound",
		What:      "general settings",
		ApplyHint: unboundSettingsApplyHint,
		SetLong: `Changes the given settings, the others are kept. interface= and outgoing-interface= take comma separated
interface keys (see "print options=interface"), empty for all.

  set dnssec register-dhcp-static
  set statistics=yes`,
		Settings: unboundSettings("general",
			unboundBool("enabled", "enabled", "run Unbound"),
			dnsSetting{Arg: Arg{Name: "port", Type: Int, Help: "DNS port", Validate: ValidatePort}, Api: "port"},
			dnsSetting{Arg: Arg{Name: "interface", Type: List, Help: "interfaces to listen on, empty for all"}, Api: "active_interface", Kind: dnsList, Options: true},
			dnsSetting{Arg: Arg{Name: "outgoing-interface", Type: List, Help: "interfaces to send queries from, empty for all"}, Api: "outgoing_interface", Kind: dnsList, Options: true},
			unboundBool("dnssec", "dnssec", "validate DNSSEC"),
			unboundBool("dns64", "dns64", "synthesize AAAA records for IPv4-only names (DNS64)"),
			dnsSetting{Arg: Arg{Name: "dns64-prefix", Help: "the DNS64 prefix, empty for 64:ff9b::/96"}, Api: "dns64prefix"},
			unboundBool("no-a-records", "noarecords", "with DNS64: answer no A records"),
			unboundBool("register-dhcp", "regdhcp", "register the DHCP leases (ISC DHCP) in DNS"),
			dnsSetting{Arg: Arg{Name: "register-dhcp-domain", Help: "domain of the registered DHCP names, empty for the system domain"}, Api: "regdhcpdomain"},
			unboundBool("register-dhcp-static", "regdhcpstatic", "register the static DHCP mappings in DNS"),
			unboundBool("no-register-link-local6", "noreglladdr6", "don't register the IPv6 link-local addresses"),
			unboundBool("no-register-records", "noregrecords", "don't register the firewall's own A/AAAA records"),
			unboundBool("txt-support", "txtsupport", "add the descriptions of host overrides as TXT records"),
			unboundBool("flush-cache", "cacheflush", "flush the DNS cache on every reload"),
			unboundBool("safesearch", "safesearch", "force SafeSearch of the search engines"),
			dnsSetting{Arg: Arg{Name: "local-zone-type", Help: "type of the local domain zone, default transparent"}, Api: "local_zone_type", Options: true},
			unboundBool("wpad", "enable_wpad", "register WPAD / WSPAD records"),
			unboundBool("statistics", "stats", "record query statistics (see /unbound/statistics)"),
		),
		Get: unboundSettingsGet,
		Set: unboundSettingsSet,
	}).register()

	(&dnsSettingsMenu{
		Path:      "unbound/advanced",
		Help:      "advanced settings of Unbound (privacy, caching, logging, tuning)",
		What:      "advanced settings",
		ApplyHint: `Changes are only saved, run "/unbound/service reconfigure" to apply them.`,
		SetLong: `Changes the given settings, the others are kept. Numbers left empty use the Unbound default, the cache
sizes take a unit (4m, 512k).

  set prefetch prefetch-key serve-expired
  set private-domain=lan.example,corp.example`,
		Settings: unboundSettings("advanced",
			unboundBool("hide-identity", "hideidentity", "refuse id.server and hostname.bind queries"),
			unboundBool("hide-version", "hideversion", "refuse version.server and version.bind queries"),
			unboundBool("prefetch", "prefetch", "refresh popular cache entries before they expire"),
			unboundBool("prefetch-key", "prefetchkey", "fetch DNSKEYs early during validation"),
			unboundBool("harden-dnssec-stripped", "dnssecstripped", "require DNSSEC data for trust-anchored zones"),
			unboundBool("harden-below-nxdomain", "belownxdomain", "answer NXDOMAIN below a DNSSEC-secure NXDOMAIN"),
			unboundBool("aggressive-nsec", "aggressivensec", "use the DNSSEC NSEC chain to synthesize answers"),
			unboundBool("serve-expired", "serveexpired", "serve expired cache entries while refreshing them"),
			unboundNumber("serve-expired-reply-ttl", "serveexpiredreplyttl", "TTL of expired answers in seconds"),
			unboundNumber("serve-expired-ttl", "serveexpiredttl", "how long expired entries are served, seconds"),
			unboundBool("serve-expired-ttl-reset", "serveexpiredttlreset", "reset the expired TTL when the upstream fails"),
			unboundNumber("serve-expired-client-timeout", "serveexpiredclienttimeout", "milliseconds to wait for a fresh answer before serving an expired one"),
			unboundBool("qname-minimisation-strict", "qnameminstrict", "strict QNAME minimisation (no fallback)"),
			unboundBool("extended-statistics", "extendedstatistics", "extended unbound-control statistics"),
			unboundBool("log-queries", "logqueries", "log the queries"),
			unboundBool("log-replies", "logreplies", "log the replies"),
			unboundBool("log-tag-query-reply", "logtagqueryreply", "tag logged queries and replies"),
			unboundBool("log-servfail", "logservfail", "log the reasons of SERVFAIL answers"),
			unboundBool("log-local-actions", "loglocalactions", "log the local-zone actions"),
			dnsSetting{Arg: Arg{Name: "log-verbosity", Help: "log level 0-5, default 1"}, Api: "logverbosity", Options: true},
			dnsSetting{Arg: Arg{Name: "val-log-level", Help: "DNSSEC validation log level 0-2, default 0"}, Api: "valloglevel", Options: true},
			unboundList("private-domain", "privatedomain", "domains allowed to answer with private addresses"),
			dnsSetting{Arg: Arg{Name: "private-address", Type: List, Help: "networks removed from public answers (DNS rebinding protection)", Validate: dnsValidateNetworks},
				Api: "privateaddress", Kind: dnsList},
			unboundList("insecure-domain", "insecuredomain", "domains DNSSEC validation is disabled for"),
			dnsSetting{Arg: Arg{Name: "msg-cache-size", Help: "message cache size like 4m", Validate: unboundValidateCacheSize}, Api: "msgcachesize"},
			dnsSetting{Arg: Arg{Name: "rrset-cache-size", Help: "RRset cache size like 8m", Validate: unboundValidateCacheSize}, Api: "rrsetcachesize"},
			unboundNumber("outgoing-num-tcp", "outgoingnumtcp", "outgoing TCP buffers per thread"),
			unboundNumber("incoming-num-tcp", "incomingnumtcp", "incoming TCP buffers per thread"),
			unboundNumber("num-queries-per-thread", "numqueriesperthread", "queries served at once per thread"),
			unboundNumber("outgoing-range", "outgoingrange", "ports opened per thread"),
			unboundNumber("jostle-timeout", "jostletimeout", "milliseconds before a long query may be replaced"),
			unboundNumber("discard-timeout", "discardtimeout", "milliseconds after which a waiting reply is dropped"),
			unboundNumber("cache-max-ttl", "cachemaxttl", "maximum TTL of cached entries, seconds"),
			unboundNumber("cache-max-negative-ttl", "cachemaxnegativettl", "maximum TTL of cached negative answers, seconds"),
			unboundNumber("cache-min-ttl", "cacheminttl", "minimum TTL of cached entries, seconds"),
			unboundNumber("infra-host-ttl", "infrahostttl", "TTL of the infrastructure cache entries, seconds"),
			unboundBool("infra-keep-probing", "infrakeepprobing", "keep probing upstream servers marked down"),
			unboundNumber("infra-cache-numhosts", "infracachenumhosts", "hosts kept in the infrastructure cache"),
			unboundNumber("unwanted-reply-threshold", "unwantedreplythreshold", "unwanted replies before the cache is cleared"),
		),
		Get: unboundSettingsGet,
		Set: unboundSettingsSet,
	}).register()
}
