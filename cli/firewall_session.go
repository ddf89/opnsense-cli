package cli

import (
	"cmp"
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"slices"
	"strconv"
	"time"
)

// /firewall/session: the pftop view of the connections (Firewall > Diagnostics > Sessions, api/diagnostics/firewall/query_pf_top)

// firewallSessionSortFields are the values of print sort=
var firewallSessionSortFields = []string{"bytes", "packets", "rate", "age", "expire", "protocol", "source", "destination", "state", "rule"}

func init() {
	var menu = Root.Menu("firewall/session")
	menu.Help = "the connections through the firewall with their traffic (pftop)"
	menu.Add(&Command{
		Name: "print",
		Help: "show the connections like pftop, the busiest first",
		Long: `Shows the connections tracked by pf like pftop, by default the 50 with the most bytes. GATEWAY is the
translated (NAT) or gateway endpoint, RATE the average bytes per second, AGE and EXPIRE are durations.
OPNsense caches the pftop output for 30 seconds, so the numbers change at most every 30 seconds.

search= are words: addresses and networks must match the source, destination or gateway, all other words
must occur in any field (case-insensitive). rule= only shows the connections of a rule id (see
/firewall/state rule-ids). json prints the connections as OPNsense returns them, one per line. follow
refreshes the view every interval until Ctrl-C.

  print search=192.168.1.0/24 sort=rate limit=10
  print follow`,
		Args: []Arg{
			{Name: "search", Help: "addresses / networks and words the connections must match"},
			{Name: "rule", Help: "only connections of this rule id", Complete: firewallStateCompleteRule},
			{Name: "sort", Default: "bytes", Help: "order by this column, descending", Values: firewallSessionSortFields},
			{Name: "ascending", Type: Bool, Help: "sort ascending instead"},
			{Name: "limit", Type: Int, Default: "50", Help: "show at most this many connections, 0 for all", Validate: ValidateRange(0, 100000000)},
			{Name: "json", Type: Bool, Help: "print the connections as JSON, one object per line"},
			{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
			{Name: "interval", Type: Duration, Default: "30s", Help: "pause between two refreshes of follow (OPNsense refreshes every 30s)",
				Validate: systemActivityValidateInterval},
		},
		Run: firewallSessionPrint,
	})
}

var firewallSessionHeaders = []string{"PROTO", "DIR", "SOURCE", "DESTINATION", "GATEWAY", "STATE", "AGE", "EXPIRE", "PACKETS", "BYTES", "RATE", "RULE"}

func firewallSessionPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var query = diagnostics.FirewallSessionQuery{Search: args.String("search"), RuleId: args.String("rule")}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)

	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var sessions, listErr = systemActivityAwait(c, func() ([]diagnostics.FirewallSession, error) {
			return api.FirewallSessionList(query)
		})
		if listErr != nil {
			return listErr
		}
		firewallSessionSort(sessions, args.String("sort"), args.Bool("ascending"))
		if limit := args.Int("limit"); limit > 0 && len(sessions) > limit {
			sessions = sessions[:limit]
		}

		if asJSON {
			for _, session := range sessions {
				if err := c.JSON(session.Raw); err != nil {
					return err
				}
			}
			return nil
		}
		refresh()
		var rows = make([][]string, 0, len(sessions))
		for _, s := range sessions {
			var rule = s.Descr
			if rule == "" {
				rule = s.Label
			}
			if rule == "" {
				rule = "@" + s.Rule
			}
			var gateway = ""
			if s.GwAddr != "" {
				gateway = firewallStateEndpoint(s.GwAddr, s.GwPort)
			}
			rows = append(rows, []string{
				s.Proto, s.Dir, firewallStateEndpoint(s.SrcAddr, s.SrcPort), firewallStateEndpoint(s.DstAddr, s.DstPort), gateway,
				s.State, firewallSessionDuration(s.Age), firewallSessionDuration(s.Expire), strconv.FormatInt(s.Pkts, 10),
				ifaceBytes(float64(s.Bytes)), ifaceBytes(float64(s.Avg)) + "/s", rule,
			})
		}
		c.Table(firewallSessionHeaders, rows)
		return nil
	})
}

// firewallSessionDuration renders seconds like pfctl: 00:01:26, hours can exceed 24
func firewallSessionDuration(seconds int64) string {
	var d = time.Duration(seconds) * time.Second
	return fmt.Sprintf("%02d:%02d:%02d", int64(d.Hours()), int64(d.Minutes())%60, seconds%60)
}

// firewallSessionSort orders the sessions by field, descending unless ascending (stable)
func firewallSessionSort(sessions []diagnostics.FirewallSession, field string, ascending bool) {
	var compare func(a, b diagnostics.FirewallSession) int
	switch field {
	case "bytes":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Bytes, b.Bytes) }
	case "packets":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Pkts, b.Pkts) }
	case "rate":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Avg, b.Avg) }
	case "age":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Age, b.Age) }
	case "expire":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Expire, b.Expire) }
	case "protocol":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Proto, b.Proto) }
	case "source":
		compare = func(a, b diagnostics.FirewallSession) int {
			return firewallStateCompareEndpoint(a.SrcAddr, a.SrcPort, b.SrcAddr, b.SrcPort)
		}
	case "destination":
		compare = func(a, b diagnostics.FirewallSession) int {
			return firewallStateCompareEndpoint(a.DstAddr, a.DstPort, b.DstAddr, b.DstPort)
		}
	case "state":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.State, b.State) }
	case "rule":
		compare = func(a, b diagnostics.FirewallSession) int { return cmp.Compare(a.Descr+a.Label, b.Descr+b.Label) }
	default:
		return
	}
	slices.SortStableFunc(sessions, func(a, b diagnostics.FirewallSession) int {
		if ascending {
			return compare(a, b)
		}
		return compare(b, a)
	})
}
