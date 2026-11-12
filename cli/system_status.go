package cli

import (
	"encoding/json"
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
	"time"
)

// /system/status: the notices of the system status, the bell in the header of the web GUI (full disk, firewall
// rules that failed to load, crash reports, ...). Items are selected by the # of print, the subject (diskspace,
// firewall, crashreporter, ...) or the title. Dismissing the crash reporter notice deletes the crash reports like
// the GUI does, so it asks for confirmation

const systemStatusCrashWarning = "Dismissing the crash reporter notice deletes the crash reports (/var/crash) and the " +
	"PHP error log, like the dismiss button of the web GUI."

func init() {
	var menu = Root.Menu("system/status")
	menu.Help = "system notices: full disk, firewall rules that failed to load, crash reports (the bell of the web GUI)"
	var item = Arg{Name: "item", Positional: true, Required: true, Help: "the #, subject (like diskspace) or title of the notice",
		Complete: systemStatusComplete(false)}
	var dismissItem = item
	dismissItem.Complete = systemStatusComplete(true)
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the pending notices, most severe first",
			Long: `SEVERITY is ERROR, WARNING or NOTICE, TIME when the problem was noticed (empty when unknown).
Subsystems without a problem are not listed. Notices about one page of the web GUI are only shown there.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every notice"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (plus their subject)"},
			},
			Run: systemStatusPrint,
		},
		&Command{
			Name: "show",
			Help: "show all fields of one notice",
			Args: []Arg{item},
			Run:  systemStatusShow,
		},
		&Command{
			Name: "dismiss",
			Help: "dismiss a notice, like its dismiss button in the web GUI",
			Long: `Persistent notices (like a full disk) can not be dismissed, they stay until their cause is fixed. A
dismissed notice comes back when its problem happens again.`,
			ConfirmHelp: "Asks for confirmation before dismissing the crash reporter notice: that deletes the crash reports.",
			ConfirmIf:   systemStatusConfirmDismiss,
			Args:        []Arg{dismissItem},
			Run:         systemStatusDismiss,
		},
	)
}

func systemStatusNotices(c *Context) (*system.SystemApi, []system.StatusNotice, error) {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil, nil, err
	}
	var notices, listErr = api.StatusNotices()
	return api, notices, listErr
}

// systemStatusSelect resolves the item argument to a notice
func systemStatusSelect(c *Context, args *Args) (*system.SystemApi, system.StatusNotice, error) {
	var api, notices, err = systemStatusNotices(c)
	if err != nil {
		return nil, system.StatusNotice{}, err
	}
	var notice, selectErr = Select(c, args.String("item"), notices,
		func(n system.StatusNotice) string { return n.Subject },
		func(n system.StatusNotice) []string { return []string{n.Title} })
	return api, notice, selectErr
}

// systemStatusComplete completes the subjects of the notices, only the dismissable ones for dismiss
func systemStatusComplete(dismissable bool) func(c *Context) []string {
	return func(c *Context) []string {
		var _, notices, err = systemStatusNotices(c)
		if err != nil {
			return nil
		}
		var subjects []string
		for _, notice := range notices {
			if !dismissable || notice.Dismissable() {
				subjects = append(subjects, notice.Subject)
			}
		}
		return subjects
	}
}

// systemStatusTime renders the time of a notice in local time, "" when OPNsense does not know it
func systemStatusTime(notice system.StatusNotice) string {
	if notice.Timestamp <= 0 {
		return ""
	}
	return time.Unix(notice.Timestamp, 0).Local().Format(time.DateTime)
}

// systemStatusSeverity is the status name, derived from the code should it be missing
func systemStatusSeverity(notice system.StatusNotice) string {
	if notice.Status != "" {
		return notice.Status
	}
	switch notice.StatusCode {
	case system.StatusCodeError:
		return "ERROR"
	case system.StatusCodeWarning:
		return "WARNING"
	case system.StatusCodeNotice:
		return "NOTICE"
	}
	return fmt.Sprint(notice.StatusCode)
}

// systemStatusMessage is the message on one line: it can span lines (the errors of the firewall rules), json
// has it as it is
func systemStatusMessage(notice system.StatusNotice) string {
	return strings.Join(strings.Fields(notice.Message), " ")
}

func systemStatusFields(notice system.StatusNotice) [][2]string {
	var when = systemStatusTime(notice)
	if when != "" && notice.Age != "" {
		when += " (" + notice.Age + ")"
	}
	return [][2]string{
		{"subject", notice.Subject},
		{"title", notice.Title},
		{"severity", systemStatusSeverity(notice)},
		{"message", systemStatusMessage(notice)},
		{"time", when},
		{"page", notice.Location},
		{"dismissable", YesNo(Flag(notice.Dismissable()))},
	}
}

func systemStatusPrint(c *Context, args *Args) error {
	var _, notices, err = systemStatusNotices(c)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, notice := range notices {
			var row map[string]any
			if err := json.Unmarshal(notice.Raw, &row); err != nil {
				return err
			}
			row["subject"] = notice.Subject
			if err := c.JSON(row); err != nil {
				return err
			}
		}
		return nil
	}

	var subjects = make([]string, 0, len(notices))
	for _, notice := range notices {
		subjects = append(subjects, notice.Subject)
	}
	if args.Bool("detail") {
		var items = make([][][2]string, 0, len(notices))
		for _, notice := range notices {
			items = append(items, systemStatusFields(notice))
		}
		c.Details(items, subjects)
	} else {
		var rows = make([][]string, 0, len(notices))
		for _, notice := range notices {
			rows = append(rows, []string{notice.Subject, systemStatusSeverity(notice), systemStatusTime(notice), systemStatusMessage(notice)})
		}
		c.Items([]string{"SUBJECT", "SEVERITY", "TIME", "MESSAGE"}, rows, subjects)
	}
	if len(notices) == 0 {
		c.Infof("no pending notices")
	}
	return nil
}

func systemStatusShow(c *Context, args *Args) error {
	var _, notice, err = systemStatusSelect(c, args)
	if err != nil {
		return err
	}
	c.Fields(systemStatusFields(notice))
	return nil
}

// systemStatusDismissable fails for notices OPNsense refuses to dismiss, with the reason
func systemStatusDismissable(notice system.StatusNotice) error {
	switch {
	case notice.Persistent:
		return fmt.Errorf("the notice %s is persistent and can not be dismissed, it goes away when its cause is fixed", notice.Subject)
	case notice.Location == "":
		return fmt.Errorf("the notice %s has no page in the web GUI, OPNsense does not let it be dismissed", notice.Subject)
	}
	return nil
}

func systemStatusConfirmDismiss(c *Context, args *Args) (string, error) {
	var _, notice, err = systemStatusSelect(c, args)
	if err != nil {
		return "", err
	}
	if err := systemStatusDismissable(notice); err != nil {
		return "", err
	}
	if notice.Subject == "crashreporter" {
		return systemStatusCrashWarning, nil
	}
	return "", nil
}

func systemStatusDismiss(c *Context, args *Args) error {
	var api, notice, err = systemStatusSelect(c, args)
	if err != nil {
		return err
	}
	if err := systemStatusDismissable(notice); err != nil {
		return err
	}
	return api.StatusDismiss(notice.Subject)
}
