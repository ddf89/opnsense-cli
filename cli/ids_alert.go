package cli

import (
	"errors"
	"fmt"
	"net"
	"opnsense-cli/opnsense/api/ids"
	"strconv"
	"strings"
)

// /ids/alert: the alerts of the Suricata eve log (Alerts), newest first; /ids/alert/log: the alert log files.
// An alert is identified by its position in its log file, show takes the # of the last print or position=

func init() {
	var menu = Root.Menu("ids/alert")
	menu.Help = "Suricata alerts (Alerts)"
	var logArg = Arg{Name: "log", Help: `an older (rotated) alert log by its id, see /ids/alert/log print; "" for the current one`,
		Validate: ids.AlertValidateLogId, Complete: idsAlertLogIds}
	menu.Add(
		&Command{Name: "print", Help: "list the newest alerts",
			Long: `Lists one page of the alerts, newest first (page=2 for older ones). search is a substring match over the
signature, action, source and destination address. follow prints the newest alerts and then every new alert until
Ctrl-C (of the current log; one line per alert, oldest first).`,
			Args: []Arg{
				{Name: "search", Help: "only alerts whose signature, action or address contains this text", Validate: ids.RuleValidateFilter},
				logArg,
				{Name: "limit", Type: Int, Default: "100", Help: "alerts per page", Validate: ValidateRange(1, 10000)},
				{Name: "page", Type: Int, Default: "1", Help: "the page to show", Validate: ValidateRange(1, 1<<30)},
				{Name: "detail", Type: Bool, Help: "show the main fields of every alert"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "follow", Type: Bool, Help: "keep printing new alerts until Ctrl-C"},
				{Name: "interval", Type: Duration, Default: "5s", Help: "how often follow looks for new alerts", Validate: systemActivityValidateInterval},
			},
			Check: idsAlertCheckPrint, Run: idsAlertPrint},
		&Command{Name: "show", Help: "show one alert with all its fields",
			Long: `item is the # of the last print (of the same log), position the position of the alert in its log.`,
			Args: []Arg{
				{Name: "item", Help: "the # of the alert in the last print", Positional: true},
				{Name: "position", Type: Int, Help: "the position of the alert in its log file instead of a #", Validate: ValidateRange(0, 1<<62)},
				logArg,
				{Name: "json", Type: Bool, Help: "print the alert as the API returns it"},
			},
			Check: idsAlertCheckShow, Run: idsAlertShow},
	)

	var logs = Root.Menu("ids/alert/log")
	logs.Help = "the alert log files: the current one and the rotated ones"
	logs.Add(
		&Command{Name: "print", Help: "list the alert logs",
			Long: `ID selects an older log with "/ids/alert print log=<id>", "-" is the current log.`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"}}, Run: idsAlertLogPrint},
		&Command{Name: "remove", Help: "delete a rotated alert log or empty the current one",
			Args:    []Arg{{Name: "item", Help: "the # or file name of the log", Positional: true, Required: true, Complete: idsAlertLogNames}},
			Confirm: "This deletes the alerts of the log file (the current log is emptied).", Run: idsAlertLogRemove},
	)
}

func idsAlertCheckPrint(args *Args) error {
	if args.Bool("follow") && args.String("log") != "" {
		return errors.New("follow only works for the current log, remove log=")
	}
	if args.Bool("follow") && (args.Bool("detail") || args.Has("page")) {
		return errors.New("follow can not be combined with detail or page")
	}
	return nil
}

func idsAlertCheckShow(args *Args) error {
	if args.Has("item") == args.Has("position") {
		return errors.New("give either the # of the alert or position=")
	}
	return nil
}

// idsAlertId is the id remembered for the # of print: position and log
func idsAlertId(alert ids.Alert) string {
	return fmt.Sprintf("%d/%s", alert.FilePos, alert.FileId)
}

func idsAlertEndpoint(address string, port string) string {
	if port == "" {
		return address
	}
	if strings.Contains(address, ":") && net.ParseIP(address) != nil {
		return "[" + address + "]:" + port
	}
	return address + ":" + port
}

func idsAlertRow(alert ids.Alert) []string {
	return []string{alert.Timestamp, alert.Action, strconv.FormatInt(alert.Sid, 10), alert.Proto,
		idsAlertEndpoint(alert.SrcIp, alert.SrcPort), idsAlertEndpoint(alert.DestIp, alert.DestPort), alert.InIface, alert.Signature}
}

var idsAlertColumns = []string{"TIME", "ACTION", "SID", "PROTO", "SOURCE", "DESTINATION", "INTERFACE", "SIGNATURE"}

func idsAlertFields(alert ids.Alert) [][2]string {
	return [][2]string{
		{"time", alert.Timestamp},
		{"action", alert.Action},
		{"sid", strconv.FormatInt(alert.Sid, 10)},
		{"signature", alert.Signature},
		{"proto", alert.Proto},
		{"source", idsAlertEndpoint(alert.SrcIp, alert.SrcPort)},
		{"destination", idsAlertEndpoint(alert.DestIp, alert.DestPort)},
		{"interface", alert.InIface},
		{"position", strconv.FormatInt(alert.FilePos, 10)},
		{"log", alert.FileId},
	}
}

func idsAlertPrint(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var query = ids.AlertQuery{Search: args.String("search"), LogId: args.String("log"), Limit: args.Int("limit"), Page: args.Int("page")}
	if args.Bool("follow") {
		return idsAlertFollow(c, api, query, args)
	}
	var page, searchErr = api.AlertSearch(query)
	if searchErr != nil {
		return searchErr
	}
	var idList = make([]string, len(page.Alerts))
	for i, alert := range page.Alerts {
		idList[i] = idsAlertId(alert)
	}
	switch {
	case args.Bool("json"):
		for _, alert := range page.Alerts {
			c.Println(string(alert.Raw))
		}
	case args.Bool("detail"):
		var blocks = make([][][2]string, len(page.Alerts))
		for i, alert := range page.Alerts {
			blocks[i] = idsAlertFields(alert)
		}
		c.Details(blocks, idList)
	default:
		var rows = make([][]string, len(page.Alerts))
		for i, alert := range page.Alerts {
			rows[i] = idsAlertRow(alert)
		}
		c.Items(idsAlertColumns, rows, idList)
	}
	var first = (query.Page-1)*query.Limit + 1
	var last = first + len(page.Alerts) - 1
	if len(page.Alerts) > 0 && last < page.Total {
		c.Infof("alerts %d-%d of %d, page=%d shows older ones", first, last, page.Total, query.Page+1)
	}
	return nil
}

// idsAlertLine renders an alert as one line for follow
func idsAlertLine(alert ids.Alert) string {
	return fmt.Sprintf("%s %s %d %s %s -> %s %s %s", alert.Timestamp, alert.Action, alert.Sid, alert.Proto,
		idsAlertEndpoint(alert.SrcIp, alert.SrcPort), idsAlertEndpoint(alert.DestIp, alert.DestPort), alert.InIface, alert.Signature)
}

// idsAlertFollowPages is how many pages follow reads per poll at most to catch up
const idsAlertFollowPages = 10

// idsAlertFollow prints the newest alerts, then polls for alerts behind the last seen position (a smaller position
// means the log was rotated) until Ctrl-C
func idsAlertFollow(c *Context, api *ids.IdsApi, query ids.AlertQuery, args *Args) error {
	var lastPos int64 = -1 // the position of the newest alert printed, -1 for none
	var started = false
	return systemActivityPoll(c, true, args.Duration("interval"), func() error {
		var fresh []ids.Alert
		for page := 1; page <= idsAlertFollowPages; page++ {
			query.Page = page
			var result, err = systemActivityAwait(c, func() (ids.AlertPage, error) { return api.AlertSearch(query) })
			if err != nil {
				return err
			}
			if page == 1 && len(result.Alerts) > 0 && result.Alerts[0].FilePos < lastPos {
				lastPos = -1 // rotated: everything in the new log is new
			}
			// the first poll only shows the newest page
			var done = !started || len(result.Alerts) < query.Limit
			for _, alert := range result.Alerts {
				if alert.FilePos <= lastPos {
					done = true
					break
				}
				fresh = append(fresh, alert)
			}
			if done {
				break
			}
		}
		started = true
		if len(fresh) > 0 {
			lastPos = fresh[0].FilePos
		}
		for i := len(fresh) - 1; i >= 0; i-- { // oldest first
			if args.Bool("json") {
				c.Println(string(fresh[i].Raw))
			} else {
				c.Println(idsAlertLine(fresh[i]))
			}
		}
		return nil
	})
}

func idsAlertShow(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var position = int64(args.Int("position"))
	var logId = args.String("log")
	if args.Has("item") {
		var alertIds []string
		if printed, ok := c.Session.lastPrint[c.Menu.Path()]; ok {
			alertIds = printed
		} else {
			var page, searchErr = api.AlertSearch(idsAlertDefaultQuery(logId))
			if searchErr != nil {
				return searchErr
			}
			for _, alert := range page.Alerts {
				alertIds = append(alertIds, idsAlertId(alert))
			}
		}
		var id, selectErr = Select(c, args.String("item"), alertIds, func(s string) string { return s }, func(string) []string { return nil })
		if selectErr != nil {
			return selectErr
		}
		var pos, file, _ = strings.Cut(id, "/")
		position, _ = strconv.ParseInt(pos, 10, 64)
		logId = file
	}
	var alert, getErr = api.AlertGet(position, logId)
	if getErr != nil {
		return getErr
	}
	if args.Bool("json") {
		c.Println(string(alert.Raw))
		return nil
	}
	c.Fields(idsMonitRawFields(alert.Raw))
	return nil
}

func idsAlertDefaultQuery(logId string) ids.AlertQuery {
	return ids.AlertQuery{LogId: logId, Limit: 100, Page: 1}
}

// --- /ids/alert/log

func idsAlertLogIds(c *Context) []string {
	var api, err = idsApi(c)
	if err != nil {
		return nil
	}
	var logs, logsErr = api.AlertLogs()
	if logsErr != nil {
		return nil
	}
	var result []string
	for _, log := range logs {
		if id := log.Id(); id != "" {
			result = append(result, id)
		}
	}
	return result
}

func idsAlertLogNames(c *Context) []string {
	var api, err = idsApi(c)
	if err != nil {
		return nil
	}
	var logs, logsErr = api.AlertLogs()
	if logsErr != nil {
		return nil
	}
	var names []string
	for _, log := range logs {
		names = append(names, log.Filename)
	}
	return names
}

func idsAlertLogPrint(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var logs, logsErr = api.AlertLogs()
	if logsErr != nil {
		return logsErr
	}
	var rows = make([][]string, len(logs))
	var names = make([]string, len(logs))
	for i, log := range logs {
		if args.Bool("json") {
			if err := c.JSON(log); err != nil {
				return err
			}
			continue
		}
		names[i] = log.Filename
		rows[i] = []string{log.Id(), log.Filename, log.Modified, strconv.FormatInt(log.Size, 10)}
	}
	if !args.Bool("json") {
		c.Items([]string{"ID", "FILE", "NEWEST", "SIZE"}, rows, names)
	}
	return nil
}

func idsAlertLogRemove(c *Context, args *Args) error {
	var api, err = idsApi(c)
	if err != nil {
		return err
	}
	var logs, logsErr = api.AlertLogs()
	if logsErr != nil {
		return logsErr
	}
	var log, selectErr = Select(c, args.String("item"), logs, func(l ids.AlertLog) string { return l.Filename },
		func(l ids.AlertLog) []string { return []string{l.Filename} })
	if selectErr != nil {
		return selectErr
	}
	return api.AlertLogRemove(log.Filename)
}
