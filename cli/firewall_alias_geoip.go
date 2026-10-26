package cli

import (
	"errors"
	"net/url"
	"opnsense-cli/opnsense/api/firewall"
	"strconv"
	"strings"
)

// /firewall/alias/geoip: the GeoIP settings of Firewall > Aliases, i.e. where the country networks of the geoip
// aliases come from. The URL usually contains a license key, it is never printed in full

const (
	// firewallAliasGeoipMasked replaces the secret parts of the URL
	firewallAliasGeoipMasked = "***"
	// firewallAliasGeoipKeySegment is the length from which a path segment without a dot counts as a key
	firewallAliasGeoipKeySegment = 24
)

func init() {
	var menu = Root.Menu("firewall/alias/geoip")
	menu.Help = "the GeoIP database the geoip aliases load their country networks from (Firewall > Aliases > GeoIP settings)"
	menu.Add(
		&Command{
			Name: "print",
			Help: "show the GeoIP source and the statistics of the last download",
			Long: `The URL is shown without its secrets: credentials, query values and long key-like path segments
are replaced by ***. aliases is the number of geoip aliases, addresses and files are the networks and country
files of the last download, updated is the date of the downloaded data (of the database files for zip sources).`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "print the settings and statistics as JSON (URL masked)"}},
			Run:  firewallAliasGeoipPrint,
		},
		&Command{
			Name: "set",
			Help: "change the download URL of the GeoIP database",
			Long: `url= takes the download URL of a MaxMind GeoLite2 Country CSV (zip) or an ipinfo country CSV (gz)
database, url= alone clears it. The aliases are not touched.

OPNsense uses a new URL only after "/firewall/alias apply" (until then update and the alias refresh download
from the previous one). The URL usually contains a license key: given on the command line it ends up in the
history of your shell (and in ~/.opn_history in the opn shell); put the command into a script read from stdin
(opn < geoip.opn) to keep it out of both.

  set url=https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=KEY&suffix=zip`,
			Args: []Arg{{Name: "url", Required: true, Validate: firewallAliasGeoipValidateUrl,
				Help: `the http(s) download URL of the GeoIP database, "" for none`}},
			Run: firewallAliasGeoipSet,
		},
		&Command{
			Name: "update",
			Help: "download the GeoIP database now",
			Long: `Downloads from the URL of the last apply and replaces the country files the geoip aliases load (pf
picks them up with the next alias refresh or apply). Fails when the download brought no networks; OPNsense logs
the reason in the system log. Providers limit the number of downloads per day.`,
			Run: firewallAliasGeoipUpdate,
		},
	)
}

// firewallAliasGeoipValidateUrl accepts "" or an http(s) URL with a host; the message never repeats the value,
// it usually contains a license key
func firewallAliasGeoipValidateUrl(value string) error {
	if value == "" {
		return nil
	}
	var parsed, err = url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		strings.ContainsAny(value, " \t\r\n") {
		return errors.New(`must be an http:// or https:// URL with a host (or "" for none)`)
	}
	return nil
}

// firewallAliasGeoipMaskUrl keeps scheme, host and path of a URL and replaces credentials, query values, the
// fragment and long key-like path segments (subscription keys) by ***
func firewallAliasGeoipMaskUrl(raw string) string {
	if raw == "" {
		return ""
	}
	var parsed, err = url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return firewallAliasGeoipMasked
	}
	var masked strings.Builder
	masked.WriteString(parsed.Scheme + "://")
	if parsed.User != nil {
		masked.WriteString(firewallAliasGeoipMasked + "@")
	}
	masked.WriteString(parsed.Host)
	var segments = strings.Split(parsed.EscapedPath(), "/")
	for i, segment := range segments {
		if len(segment) >= firewallAliasGeoipKeySegment && !strings.Contains(segment, ".") {
			segments[i] = firewallAliasGeoipMasked
		}
	}
	masked.WriteString(strings.Join(segments, "/"))
	if parsed.RawQuery != "" || parsed.ForceQuery {
		var params = strings.Split(parsed.RawQuery, "&")
		for i, param := range params {
			if key, _, found := strings.Cut(param, "="); found {
				params[i] = key + "=" + firewallAliasGeoipMasked
			} else if param != "" {
				params[i] = firewallAliasGeoipMasked
			}
		}
		masked.WriteString("?" + strings.Join(params, "&"))
	}
	if parsed.Fragment != "" {
		masked.WriteString("#" + firewallAliasGeoipMasked)
	}
	return masked.String()
}

// firewallAliasGeoipNoSource tells whether nothing can be downloaded: no URL and no business subscription
func firewallAliasGeoipNoSource(geoip firewall.AliasGeoIP) bool {
	return geoip.Url == "" && (geoip.Subscription == nil || !*geoip.Subscription)
}

func firewallAliasGeoipPrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	geoip, err := api.AliasGeoIPGet()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		var masked = geoip
		masked.Url = firewallAliasGeoipMaskUrl(geoip.Url)
		return c.JSON(masked)
	}
	var source = firewallAliasGeoipMaskUrl(geoip.Url)
	if source == "" {
		source = "(none)"
	}
	var updated = strings.Replace(strings.SplitN(geoip.Timestamp, ".", 2)[0], "T", " ", 1)
	if updated == "" {
		updated = "never"
	}
	c.Fields([][2]string{
		{"url", source},
		{"subscription", YesNo(Flag(geoip.Subscription != nil && *geoip.Subscription))},
		{"aliases", strconv.Itoa(geoip.Usages)},
		{"addresses", strconv.Itoa(geoip.AddressCount)},
		{"files", strconv.Itoa(geoip.FileCount)},
		{"updated", updated},
		{"locations-file", geoip.LocationsFilename},
		{"ipv4-file", geoip.AddressSources.IPv4},
		{"ipv6-file", geoip.AddressSources.IPv6},
	})
	if geoip.Usages > 0 && geoip.AddressCount == 0 {
		if firewallAliasGeoipNoSource(geoip) {
			c.Infof(`the geoip aliases have no data: give a source with "set url=", apply and update`)
		} else {
			c.Infof(`the geoip aliases have no data yet: run "update" (after "/firewall/alias apply" when the URL changed)`)
		}
	}
	return nil
}

func firewallAliasGeoipSet(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasGeoIPSetUrl(args.String("url"))
}

func firewallAliasGeoipUpdate(c *Context, _ *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	geoip, err := api.AliasGeoIPGet()
	if err != nil {
		return err
	}
	if firewallAliasGeoipNoSource(geoip) {
		return errors.New(`no GeoIP source: set one with "set url=" and "/firewall/alias apply" first`)
	}
	if geoip, err = api.AliasGeoIPUpdate(); err != nil {
		return err
	}
	if geoip.AddressCount == 0 {
		return errors.New(`the GeoIP download brought no networks: check the URL (a new one is used after "/firewall/alias apply") and the system log`)
	}
	c.Infof("%d networks in %d country files", geoip.AddressCount, geoip.FileCount)
	return nil
}
