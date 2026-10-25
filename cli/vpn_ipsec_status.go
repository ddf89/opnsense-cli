package cli

import (
	"fmt"
	"sort"
	"strings"

	"opnsense-cli/opnsense/api/ipsec"
)

// /vpn/ipsec/session, sad, spd and lease: the status pages of VPN > IPsec. Sessions (Status Overview) are the
// connections strongSwan has loaded and their IKE SAs (phase 1) with the child SAs (phase 2); they are selected by
// the # of print, the strongSwan connection name (the connection uuid, con<id> for legacy tunnels) or the
// description. SAD and SPD entries are the kernel's security associations and policies, selected by the # of
// print or their id; removing them takes effect immediately and is confirmed

func init() {
	var session = Root.Menu("vpn/ipsec/session")
	session.Help = "IPsec sessions: loaded connections, IKE SAs (phase 1) and child SAs (phase 2) (VPN > IPsec > Status Overview)"
	var sessionItem = Arg{Name: "item", Help: "the #, connection name or description of the session", Positional: true, Required: true,
		Complete: vpnIpsecSessionNames}
	session.Add(
		&Command{Name: "print", Help: "list the sessions (phase 1)", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every session"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "connected", Type: Bool, Help: "only sessions with an IKE SA"},
		}, Run: vpnIpsecSessionPrint},
		&Command{Name: "show", Help: "show all fields of one session", Args: []Arg{sessionItem}, Run: vpnIpsecSessionShow},
		&Command{Name: "phase2", Help: "list the child SAs (phase 2) of a session", Args: []Arg{sessionItem,
			{Name: "detail", Type: Bool, Help: "show all fields of every child SA"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
		}, Run: vpnIpsecSessionPhase2},
		&Command{Name: "connect", Help: "initiate all children of a session's connection",
			Long:    "OPNsense ignores names strongSwan does not know, check the result with print.",
			Confirm: "This initiates the IPsec connection (brings its tunnels up).", Args: []Arg{sessionItem},
			Run: vpnIpsecSessionAction(true)},
		&Command{Name: "disconnect", Help: "terminate the IKE SA of a session and its child SAs",
			Long:    "Depending on the start action of its children the connection may come up again.",
			Confirm: "This terminates the IPsec session, its tunnels go down.", Args: []Arg{sessionItem},
			Run: vpnIpsecSessionAction(false)},
	)

	for _, kind := range []struct {
		menu, help, noun, confirm string
		list                      func(api *ipsec.IPsecApi) ([]ipsec.Record, error)
		remove                    func(api *ipsec.IPsecApi, id string) error
		headers                   []string
		row                       func(r ipsec.Record) []string
	}{
		{"sad", "security associations of the kernel (VPN > IPsec > Security Association Database)", "security association",
			"This removes the security association from the kernel, its traffic stops until it is renegotiated.",
			(*ipsec.IPsecApi).SadList, (*ipsec.IPsecApi).SadRemove,
			[]string{"SRC", "DST", "PROTOCOL", "SPI", "MODE", "REQID", "ENCRYPTION", "AUTH", "BYTES", "CONNECTION", "CHILD"},
			func(r ipsec.Record) []string {
				return []string{r.Value("src"), r.Value("dst"), r.Value("satype"), r.Value("spi"), r.Value("mode"), r.Value("reqid"),
					r.Value("alg_enc"), r.Value("alg_auth"), r.Value("bytes_current"), r.Value("phase1desc"), r.Value("phase2desc")}
			}},
		{"spd", "security policies of the kernel (VPN > IPsec > Security Policy Database)", "security policy",
			"This removes the security policy from the kernel, its traffic is no longer protected or bypassed until it is installed again.",
			(*ipsec.IPsecApi).SpdList, (*ipsec.IPsecApi).SpdRemove,
			[]string{"DIR", "SRC", "DST", "UPPERSPEC", "TYPE", "PROTOCOL", "MODE", "TUNNEL", "REQID", "CONNECTION", "CHILD"},
			func(r ipsec.Record) []string {
				return []string{r.Value("dir"), vpnIpsecHostPort(r.Value("src"), r.Value("src_port")), vpnIpsecHostPort(r.Value("dst"), r.Value("dst_port")),
					r.Value("upperspec"), r.Value("type"), r.Value("proto"), r.Value("mode"), strings.ReplaceAll(r.Value("src-dst"), ",", " - "),
					r.Value("reqid"), r.Value("phase1desc"), r.Value("phase2desc")}
			}},
	} {
		var kind = kind
		var menu = Root.Menu("vpn/ipsec/" + kind.menu)
		menu.Help = kind.help
		var item = Arg{Name: "item", Help: "the # or id of the " + kind.noun, Positional: true, Required: true}
		menu.Add(
			&Command{Name: "print", Help: "list the " + kind.noun + " entries", Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every entry"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only entries where any field contains this text"},
			}, Run: func(c *Context, args *Args) error {
				var api, err = vpnIpsecApi(c)
				if err != nil {
					return err
				}
				var records, listErr = kind.list(api)
				if listErr != nil {
					return listErr
				}
				return vpnIpsecStatusPrint(c, args, vpnIpsecSearch(records, args.String("search")), "id", kind.headers, kind.row)
			}},
			&Command{Name: "remove", Help: "remove a " + kind.noun + " from the kernel", Confirm: kind.confirm, Args: []Arg{item},
				Run: func(c *Context, args *Args) error {
					var api, err = vpnIpsecApi(c)
					if err != nil {
						return err
					}
					var records, listErr = kind.list(api)
					if listErr != nil {
						return listErr
					}
					var record, selectErr = Select(c, args.String("item"), records,
						func(r ipsec.Record) string { return r.Value("id") }, func(ipsec.Record) []string { return nil })
					if selectErr != nil {
						return selectErr
					}
					return kind.remove(api, record.Value("id"))
				}},
		)
	}

	var lease = Root.Menu("vpn/ipsec/lease")
	lease.Help = "addresses leased to mobile clients from the pools (VPN > IPsec > Lease Status)"
	lease.Add(
		&Command{Name: "print", Help: "list the leases", Args: []Arg{
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			{Name: "pool", Help: "only leases of this pool (name)"},
			{Name: "online", Type: Bool, Help: "only leases of connected clients"},
		}, Run: vpnIpsecLeasePrint},
		&Command{Name: "pools", Help: "show the usage of the pools strongSwan has loaded", Args: []Arg{
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
		}, Run: vpnIpsecLeasePools},
	)
}

func vpnIpsecHostPort(host string, port string) string {
	if port == "" || port == "any" {
		return host
	}
	return host + "[" + port + "]"
}

// vpnIpsecAllFields renders every value of a status row sorted by name, without the "%" display fields
func vpnIpsecAllFields(r ipsec.Record) [][2]string {
	var values = r.Values()
	var names = make([]string, 0, len(values))
	for name := range values {
		if !strings.HasPrefix(name, "%") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var fields = make([][2]string, len(names))
	for i, name := range names {
		fields[i] = [2]string{name, values[name]}
	}
	return fields
}

// vpnIpsecStatusPrint prints status rows as a table, numbered blocks (detail) or ndjson; idField identifies a row
func vpnIpsecStatusPrint(c *Context, args *Args, records []ipsec.Record, idField string, headers []string, row func(r ipsec.Record) []string) error {
	var ids = make([]string, len(records))
	for i, record := range records {
		ids[i] = record.Value(idField)
	}
	switch {
	case args.Bool("json"):
		return vpnIpsecPrintJSON(c, records, nil)
	case args.Bool("detail"):
		var details = make([][][2]string, len(records))
		for i, record := range records {
			details[i] = vpnIpsecAllFields(record)
		}
		c.Details(details, ids)
	default:
		var rows = make([][]string, len(records))
		for i, record := range records {
			rows[i] = row(record)
		}
		c.Items(headers, rows, ids)
	}
	return nil
}

// --- sessions

func vpnIpsecSessionNames(c *Context) []string {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return nil
	}
	var sessions, listErr = api.SessionList()
	if listErr != nil {
		return nil
	}
	var names []string
	for _, session := range sessions {
		for _, name := range vpnIpsecSessionSelectNames(session) {
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

func vpnIpsecSessionSelectNames(r ipsec.Record) []string {
	return []string{r.Value("phase1desc")}
}

func vpnIpsecSessionSelect(c *Context, api *ipsec.IPsecApi, selector string) (ipsec.Record, error) {
	var sessions, err = api.SessionList()
	if err != nil {
		return ipsec.Record{}, err
	}
	if len(sessions) == 0 {
		var status, statusErr = api.ServiceStatus()
		if statusErr == nil && status != "running" {
			return ipsec.Record{}, fmt.Errorf("there are no sessions, strongSwan is %s", status)
		}
	}
	return Select(c, selector, sessions, func(r ipsec.Record) string { return r.Value("name") }, vpnIpsecSessionSelectNames)
}

func vpnIpsecSessionLabel(r ipsec.Record) string {
	if description := r.Value("phase1desc"); description != "" {
		return description
	}
	return r.Value("name")
}

func vpnIpsecSessionPrint(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var sessions, listErr = api.SessionList()
	if listErr != nil {
		return listErr
	}
	if args.Bool("connected") {
		var connected []ipsec.Record
		for _, session := range sessions {
			if session.Value("connected") == "1" {
				connected = append(connected, session)
			}
		}
		sessions = connected
	}
	return vpnIpsecStatusPrint(c, args, sessions, "name",
		[]string{"CONNECTED", "SESSION", "VERSION", "LOCAL", "REMOTE", "LOCAL-ID", "REMOTE-ID", "BYTES-IN", "BYTES-OUT"},
		func(r ipsec.Record) []string {
			return []string{YesNo(r.Value("connected")), vpnIpsecSessionLabel(r), r.Value("version"), r.Value("local-addrs"),
				r.Value("remote-addrs"), r.Value("local-id"), r.Value("remote-id"), r.Value("bytes-in"), r.Value("bytes-out")}
		})
}

func vpnIpsecSessionShow(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var session, selectErr = vpnIpsecSessionSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(vpnIpsecAllFields(session))
	return nil
}

func vpnIpsecSessionPhase2(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var session, selectErr = vpnIpsecSessionSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var children, listErr = api.SessionChildren(session.Value("name"))
	if listErr != nil {
		return listErr
	}
	var rows = make([][]string, len(children))
	for i, child := range children {
		rows[i] = []string{vpnIpsecPhase2Label(child), child.Value("state"), child.Value("mode"), child.Value("protocol"),
			child.Value("local-ts"), child.Value("remote-ts"), child.Value("spi-in"), child.Value("spi-out"),
			strings.Trim(child.Value("encr-alg")+"-"+child.Value("encr-keysize"), "-"), child.Value("bytes-in"), child.Value("bytes-out")}
	}
	switch {
	case args.Bool("json"):
		return vpnIpsecPrintJSON(c, children, nil)
	case args.Bool("detail"):
		for i, child := range children {
			if i > 0 {
				c.Println()
			}
			c.Printf("%d\n", i)
			var fields = vpnIpsecAllFields(child)
			for j := range fields {
				fields[j][0] = "  " + fields[j][0]
			}
			c.Fields(fields)
		}
	default:
		c.Table([]string{"CHILD", "STATE", "MODE", "PROTOCOL", "LOCAL-TS", "REMOTE-TS", "SPI-IN", "SPI-OUT", "ENCRYPTION", "BYTES-IN", "BYTES-OUT"}, rows)
	}
	return nil
}

func vpnIpsecPhase2Label(r ipsec.Record) string {
	if description := r.Value("phase2desc"); description != "" {
		return description
	}
	return r.Value("name")
}

func vpnIpsecSessionAction(connect bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = vpnIpsecApi(c)
		if err != nil {
			return err
		}
		var session, selectErr = vpnIpsecSessionSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		if connect {
			return api.SessionConnect(session.Value("name"))
		}
		if session.Value("connected") != "1" {
			c.Infof("the session %s is not connected", vpnIpsecSessionLabel(session))
			return nil
		}
		return api.SessionDisconnect(session.Value("name"))
	}
}

// --- leases

func vpnIpsecLeasePrint(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var leases, listErr = api.LeaseList()
	if listErr != nil {
		return listErr
	}
	var filtered []ipsec.Record
	for _, lease := range leases {
		if args.Has("pool") && !strings.EqualFold(lease.Value("pool"), args.String("pool")) {
			continue
		}
		if args.Bool("online") && lease.Value("online") != "1" {
			continue
		}
		filtered = append(filtered, lease)
	}
	if args.Bool("json") {
		return vpnIpsecPrintJSON(c, filtered, nil)
	}
	var rows = make([][]string, len(filtered))
	for i, lease := range filtered {
		rows[i] = []string{lease.Value("pool"), lease.Value("address"), YesNo(lease.Value("online")), lease.Value("user")}
	}
	c.Table([]string{"POOL", "ADDRESS", "ONLINE", "USER"}, rows)
	return nil
}

func vpnIpsecLeasePools(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var pools, listErr = api.LeasePools()
	if listErr != nil {
		return listErr
	}
	if args.Bool("json") {
		return vpnIpsecPrintJSON(c, pools, nil)
	}
	var rows = make([][]string, len(pools))
	for i, pool := range pools {
		rows[i] = []string{pool.Value("name"), pool.Value("net"), pool.Value("online"), pool.Value("offline"), pool.Value("size")}
	}
	c.Table([]string{"NAME", "NET", "ONLINE", "OFFLINE", "SIZE"}, rows)
	return nil
}
