package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/ntpd"
	"sort"
	"strings"
)

// /system/ntp: the NTP status of Services > Network Time > Status (api/ntpd/service). The NTP settings are legacy
// pages without API

func init() {
	var menu = Root.Menu("system/ntp")
	menu.Help = "NTP status (Services > Network Time > Status)"
	menu.Add(
		&Command{Name: "status", Help: "show the NTP peers (ntpq -p) and the GPS status",
			Long: `STATUS is the tally code of ntpq with its meaning: * active peer (the one the clock follows), + candidate,
# selected, o PPS peer, - outlier, x false ticker, . excess peer, pool for a DNS pool entry. WHEN and POLL are
seconds, REACH is the octal register of the last 8 polls (377 = all answered), DELAY, OFFSET and JITTER are in
milliseconds. A GPS clock is shown below the peers.

follow repeats the query every interval until Ctrl-C.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every peer"},
				{Name: "json", Type: Bool, Help: "one JSON object per peer, as the API returns them"},
				{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "5s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			}, Run: systemNtpStatus},
	)
}

func systemNtpApi(c *Context) (*ntpd.NtpdApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &ntpd.NtpdApi{OPNsense: opn}, nil
}

// systemNtpStatusWord renders a tally code like "* active peer"
func systemNtpStatusWord(status string) string {
	var name = ntpd.PeerStatusNames[status]
	switch {
	case status == "__pool":
		return "pool"
	case name == "":
		return status
	case strings.TrimSpace(status) == "":
		return name
	}
	return status + " " + name
}

func systemNtpPeerFields(peer ntpd.Peer) [][2]string {
	var peerType = peer.Type
	if name, known := ntpd.PeerTypeNames[peer.Type]; known {
		peerType = fmt.Sprintf("%s (%s)", peer.Type, name)
	}
	return [][2]string{
		{"server", peer.Server},
		{"status", systemNtpStatusWord(peer.Status)},
		{"refid", peer.RefId},
		{"stratum", peer.Stratum},
		{"type", peerType},
		{"when", peer.When},
		{"poll", peer.Poll},
		{"reach", peer.Reach},
		{"delay", peer.Delay},
		{"offset", peer.Offset},
		{"jitter", peer.Jitter},
	}
}

func systemNtpStatus(c *Context, args *Args) error {
	var api, err = systemNtpApi(c)
	if err != nil {
		return err
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)
	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var peers, statusErr = systemActivityAwait(c, api.Status)
		if statusErr != nil {
			return statusErr
		}
		var gps, gpsErr = systemActivityAwait(c, api.Gps)
		if gpsErr != nil {
			return gpsErr
		}
		refresh()
		systemNtpShow(c, peers, gps, args)
		return nil
	})
}

func systemNtpShow(c *Context, peers []ntpd.Peer, gps map[string]any, args *Args) {
	switch {
	case args.Bool("json"):
		for _, peer := range peers {
			c.Println(string(peer.Raw))
		}
		return
	case args.Bool("detail"):
		for i, peer := range peers {
			if i > 0 {
				c.Println()
			}
			c.Fields(systemNtpPeerFields(peer))
		}
	default:
		if len(peers) == 0 {
			c.Infof("no NTP peers, ntpd is not running")
		}
		var rows = make([][]string, len(peers))
		for i, peer := range peers {
			rows[i] = []string{peer.Server, systemNtpStatusWord(peer.Status), peer.RefId, peer.Stratum, peer.Type,
				peer.When, peer.Poll, peer.Reach, peer.Delay, peer.Offset, peer.Jitter}
		}
		c.Table([]string{"SERVER", "STATUS", "REFID", "ST", "T", "WHEN", "POLL", "REACH", "DELAY", "OFFSET", "JITTER"}, rows)
	}
	if len(gps) > 0 {
		var keys = make([]string, 0, len(gps))
		for key := range gps {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var fields = make([][2]string, 0, len(keys))
		for _, key := range keys {
			fields = append(fields, [2]string{"gps-" + strings.ReplaceAll(key, "_", "-"), fmt.Sprint(gps[key])})
		}
		c.Println()
		c.Fields(fields)
	}
}
