package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

// /captive-portal/session: the logged in clients of Services > Captive Portal > Sessions
// (api/captiveportal/session). Sessions are selected by the # of print, the session id, the user name or the IP
// address. The admin login of a client (session/connect) is not offered

func init() {
	var menu = Root.Menu("captive-portal/session")
	menu.Help = "logged in clients of the captive portal (Services > Captive Portal > Sessions)"
	menu.Add(
		&Command{Name: "print", Help: "list the sessions, follow refreshes until Ctrl-C",
			Long: `IN / OUT are the bytes received from / sent to the client.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every session"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only sessions where any field contains this text"},
				{Name: "zone", Help: "only the sessions of this zone (description or zone id)", Complete: captivePortalZoneItemNames},
				{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			},
			Run: captivePortalSessionPrint},
		&Command{Name: "disconnect", Aliases: []string{"remove"}, Help: "log a client off, it has to log in again",
			Args: []Arg{{Name: "item", Positional: true, Required: true, Complete: captivePortalSessionNames,
				Help: "the # of print, the session id, the user name or the IP address of the session"}},
			Confirm: "This logs the client off, it has to log in again to get access.",
			Run:     captivePortalSessionDisconnect},
	)
}

// captivePortalSessionZoneIds resolves zone= (a description or zone id) to the zone id
func captivePortalSessionZoneIds(api *captiveportal.CaptivePortalApi, args *Args) ([]string, map[string]string, error) {
	var descriptions, err = api.ZoneDescriptions()
	if err != nil {
		return nil, nil, err
	}
	if !args.Has("zone") {
		return nil, descriptions, nil
	}
	var zone = strings.TrimSpace(args.String("zone"))
	if _, isId := descriptions[zone]; isId {
		return []string{zone}, descriptions, nil
	}
	var matches, names []string
	for id, description := range descriptions {
		names = append(names, fmt.Sprintf("%q", description))
		if strings.EqualFold(description, zone) {
			matches = append(matches, id)
		}
	}
	switch len(matches) {
	case 1:
		return matches, descriptions, nil
	case 0:
		if len(names) == 0 {
			return nil, nil, &coreapi.NotFoundError{Name: fmt.Sprintf("zone %q, there are no zones", zone)}
		}
		return nil, nil, &coreapi.NotFoundError{Name: fmt.Sprintf("zone %q, valid are: %s", zone, strings.Join(names, ", "))}
	default:
		return nil, nil, &coreapi.TooManyFoundError{Name: fmt.Sprintf("zone %q matches the zone ids %s, give the zone id", zone, strings.Join(matches, ", "))}
	}
}

func captivePortalSessionTime(value captiveportal.Value) string {
	if value == "" || value.Int() <= 0 {
		return string(value)
	}
	return time.Unix(value.Int(), 0).Local().Format(time.DateTime)
}

func captivePortalSessionBytes(value captiveportal.Value) string {
	if value == "" {
		return ""
	}
	return ifaceBytes(float64(value.Int()))
}

func captivePortalSessionZone(session captiveportal.Session, descriptions map[string]string) string {
	if description := descriptions[string(session.ZoneId)]; description != "" {
		return description
	}
	return string(session.ZoneId)
}

func captivePortalSessionAddresses(session captiveportal.Session) string {
	var addresses []string
	for _, address := range session.IpAddresses {
		addresses = append(addresses, string(address))
	}
	if len(addresses) == 0 && session.IpAddress != "" {
		addresses = []string{string(session.IpAddress)}
	}
	return strings.Join(addresses, ",")
}

func captivePortalSessionPrint(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	zoneIds, descriptions, err := captivePortalSessionZoneIds(api, args)
	if err != nil {
		return err
	}
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)
	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var sessions, listErr = systemActivityAwait(c, func() ([]captiveportal.Session, error) {
			return api.SessionList(args.String("search"), zoneIds...)
		})
		if listErr != nil {
			return listErr
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
		captivePortalSessionShow(c, sessions, descriptions, args.Bool("detail"))
		return nil
	})
}

func captivePortalSessionShow(c *Context, sessions []captiveportal.Session, descriptions map[string]string, detail bool) {
	var ids = make([]string, len(sessions))
	for i, session := range sessions {
		ids[i] = string(session.SessionId)
	}
	if detail {
		var items = make([][][2]string, len(sessions))
		for i, session := range sessions {
			items[i] = [][2]string{
				{"session-id", string(session.SessionId)},
				{"zone", captivePortalSessionZone(session, descriptions)},
				{"zone-id", string(session.ZoneId)},
				{"user", string(session.UserName)},
				{"authenticated-via", string(session.AuthenticatedVia)},
				{"ip-addresses", captivePortalSessionAddresses(session)},
				{"mac-address", string(session.MacAddress)},
				{"start", captivePortalSessionTime(session.StartTime)},
				{"last-access", captivePortalSessionTime(session.LastAccessed)},
				{"bytes-in", captivePortalSessionBytes(session.BytesIn)},
				{"bytes-out", captivePortalSessionBytes(session.BytesOut)},
				{"packets-in", string(session.PacketsIn)},
				{"packets-out", string(session.PacketsOut)},
				{"session-timeout", string(session.AccSessionTimeout)},
			}
		}
		c.Details(items, ids)
		return
	}
	var rows = make([][]string, len(sessions))
	for i, session := range sessions {
		rows[i] = []string{captivePortalSessionZone(session, descriptions), string(session.UserName), captivePortalSessionAddresses(session),
			string(session.MacAddress), captivePortalSessionTime(session.StartTime), captivePortalSessionTime(session.LastAccessed),
			captivePortalSessionBytes(session.BytesIn), captivePortalSessionBytes(session.BytesOut)}
	}
	c.Items([]string{"ZONE", "USER", "IP-ADDRESS", "MAC-ADDRESS", "START", "LAST-ACCESS", "IN", "OUT"}, rows, ids)
}

func captivePortalSessionNames(c *Context) []string {
	var api, err = captivePortalApi(c)
	if err != nil {
		return nil
	}
	var sessions, listErr = api.SessionList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, session := range sessions {
		if session.UserName != "" {
			names = append(names, string(session.UserName))
		}
	}
	return names
}

func captivePortalSessionDisconnect(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	sessions, err := api.SessionList("")
	if err != nil {
		return err
	}
	session, err := Select(c, args.String("item"), sessions, func(session captiveportal.Session) string { return string(session.SessionId) },
		func(session captiveportal.Session) []string {
			var names = []string{string(session.UserName)}
			for _, address := range session.IpAddresses {
				names = append(names, string(address))
			}
			return append(names, string(session.IpAddress))
		})
	if err != nil {
		return err
	}
	if _, err := api.SessionDisconnect(string(session.SessionId)); err != nil {
		if errors.Is(err, captiveportal.ErrSessionNotFound) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("session %s, it ended in the meantime", session.SessionId), Err: err}
		}
		return err
	}
	return nil
}
