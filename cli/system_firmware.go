package cli

import (
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
	"time"
)

// /system/firmware: System > Firmware. status shows the result of the last check, check asks the mirror, audit runs
// the security / health / connectivity audits; update and upgrade install. The background actions are followed
// until they finish (Ctrl-C stops following, not the action), their log goes to stderr (audit: stdout, it is the
// report). Sub menus: package, plugin, changelog, settings

const (
	systemFirmwareUpdateWarning = "This installs all pending updates: services restart and the firewall reboots when " +
		"the update needs it (or when the reboot setting is on)."
	systemFirmwareUpgradeWarning = "This installs the major upgrade and reboots the firewall, there is no way back but a " +
		"reinstall or a boot environment snapshot."
)

func init() {
	var menu = Root.Menu("system/firmware")
	menu.Help = "firmware status, updates, packages, plugins and settings (System > Firmware)"
	var follow = []Arg{
		{Name: "background", Type: Bool, Help: "only start it, do not follow it (see log)"},
		{Name: "timeout", Type: Duration, Default: "1h", Validate: systemPowerPositive, Help: "how long to follow it"},
	}
	menu.Add(
		&Command{Name: "status", Help: "show the result of the last check for updates",
			Long: `Shows the installed version and what the last check found (status none, update, upgrade or error).
It does not ask the mirror, run check for that. detail also lists the pending package changes.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "also list the pending updates"},
				{Name: "json", Type: Bool, Help: "the status as the API returns it"},
			},
			Run: systemFirmwareStatusCommand},
		&Command{Name: "check", Help: "check the mirror for updates and show the status",
			Long: `Downloads the package catalogue and the changelogs (it can upgrade pkg itself first, like the web
UI's check), then shows the status like "status". log shows the check's output on stderr.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "also list the pending updates"},
				{Name: "log", Type: Bool, Help: "show the output of the check"},
				{Name: "timeout", Type: Duration, Default: "10m", Validate: systemPowerPositive, Help: "how long to wait for the check"},
			},
			Run: systemFirmwareCheck},
		&Command{Name: "audit", Help: "run a security, health or connectivity audit and print its report",
			Long: `security lists installed packages with known vulnerabilities, health verifies the installed files and
packages, connection tests the mirror over IPv4 and IPv6 (minutes when one of them is not routed).`,
			Args: []Arg{
				{Name: "type", Default: "security", Values: []string{"security", "health", "connection"}, Help: "which audit"},
				{Name: "timeout", Type: Duration, Default: "15m", Validate: systemPowerPositive, Help: "how long to wait for the report"},
			},
			Run: systemFirmwareAudit},
		&Command{Name: "update", Help: "install all pending updates (run check first)",
			Args: follow, Confirm: systemFirmwareUpdateWarning, Run: systemFirmwareUpdate},
		&Command{Name: "upgrade", Help: "install the pending major upgrade (run check first)",
			Args: follow, Confirm: systemFirmwareUpgradeWarning, Run: systemFirmwareUpgrade},
		&Command{Name: "log", Help: "show the output of the last (or the running) firmware action",
			Args: []Arg{{Name: "follow", Type: Bool, Help: "follow a running action until it finishes"}},
			Run:  systemFirmwareLog},
	)
}

// --- status

func systemFirmwareStatusCommand(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		var raw, rawErr = api.FirmwareStatusRaw()
		if rawErr != nil {
			return rawErr
		}
		c.Println(string(raw))
		return nil
	}
	var status, statusErr = api.FirmwareStatus()
	if statusErr != nil {
		return statusErr
	}
	var busy, busyErr = api.FirmwareBusy()
	if busyErr != nil {
		return busyErr
	}
	systemFirmwarePrintStatus(c, status, busy, args.Bool("detail"))
	return nil
}

func systemFirmwarePrintStatus(c *Context, status system.FirmwareStatus, busy bool, detail bool) {
	var fields = [][2]string{
		{"product", strings.TrimSpace(status.Product.Name + " " + status.ProductVersion)},
		{"series", status.Product.Series},
		{"os", status.OsVersion},
		{"mirror", status.Product.Mirror},
		{"last-check", status.LastCheck},
		{"status", status.Status},
		{"message", status.StatusMsg},
	}
	if len(status.Updates) > 0 || len(status.Sets) > 0 {
		fields = append(fields,
			[2]string{"updates", fmt.Sprint(len(status.Updates))},
			[2]string{"needs-reboot", YesNo(Flag(status.Reboot))})
	}
	if len(status.Sets) > 0 {
		fields = append(fields, [2]string{"upgrade-sets", fmt.Sprint(len(status.Sets))})
	}
	if status.UpgradeMajorVersion != "" {
		fields = append(fields, [2]string{"major-upgrade", status.UpgradeMajorVersion})
	}
	if busy {
		fields = append(fields, [2]string{"busy", `yes, a firmware action is running (see "log follow")`})
	}
	c.Fields(fields)
	if !detail || len(status.Updates)+len(status.Sets) == 0 {
		return
	}
	c.Println()
	var rows [][]string
	for _, update := range append(append([]system.FirmwareUpdate(nil), status.Updates...), status.Sets...) {
		rows = append(rows, []string{update.Name, update.Old, update.New, update.Reason, update.Repository})
	}
	c.Table([]string{"NAME", "INSTALLED", "NEW", "REASON", "REPOSITORY"}, rows)
}

// --- background actions

// systemFirmwareRun starts a background action (start is called once) and follows its log, writing it to out
// (nil: discard). It refuses to start while another firmware action runs
func systemFirmwareRun(c *Context, api *system.SystemApi, what string, start func() error, out func(string), background bool, timeout time.Duration) (system.FirmwareProgress, error) {
	var busy, err = api.FirmwareBusy()
	if err != nil {
		return system.FirmwareProgress{}, err
	}
	if busy {
		return system.FirmwareProgress{}, errors.New(`another firmware action is running, see "/system/firmware log follow"`)
	}
	// the log of the previous action stays until the new one starts writing
	var previous, previousErr = api.FirmwareProgress()
	if previousErr != nil {
		return system.FirmwareProgress{}, previousErr
	}
	if err := start(); err != nil {
		return system.FirmwareProgress{}, err
	}
	if background {
		c.Infof(`%s started, follow it with "/system/firmware log follow"`, what)
		return system.FirmwareProgress{}, nil
	}
	return systemFirmwareFollow(c, api, what, system.FirmwareWaitOptions{Timeout: timeout, Previous: previous.Log, Output: out})
}

func systemFirmwareFollow(c *Context, api *system.SystemApi, what string, options system.FirmwareWaitOptions) (system.FirmwareProgress, error) {
	options.PollInterval = systemFirmwarePollInterval
	var progress, err = api.FirmwareWait(c, options)
	if c.Err() != nil {
		c.Infof("stopped following, the %s goes on in the background", what)
		return progress, errCancelledFollow
	}
	return progress, err
}

// errCancelledFollow ends a command whose following was cancelled, without an error message
var errCancelledFollow = errors.New("stopped following")

// systemFirmwarePollInterval is the time between two progress requests
var systemFirmwarePollInterval = time.Second

// systemFirmwareStderr writes log text to the message stream
func systemFirmwareStderr(c *Context) func(string) {
	return func(text string) {
		_, _ = fmt.Fprint(c.ErrOut, text)
	}
}

func systemFirmwareCheck(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var out func(string)
	if args.Bool("log") {
		out = systemFirmwareStderr(c)
	} else {
		c.Infof("checking for updates...")
	}
	if _, err := systemFirmwareRun(c, api, "check", func() error { return api.FirmwareStart(system.FirmwareActionCheck) },
		out, false, args.Duration("timeout")); err != nil {
		return systemFirmwareFollowErr(err)
	}
	var status, statusErr = api.FirmwareStatus()
	if statusErr != nil {
		return statusErr
	}
	systemFirmwarePrintStatus(c, status, false, args.Bool("detail"))
	return nil
}

// systemFirmwareFollowErr turns a cancelled follow into success (the action goes on)
func systemFirmwareFollowErr(err error) error {
	if errors.Is(err, errCancelledFollow) {
		return nil
	}
	return err
}

var systemFirmwareAuditActions = map[string]system.FirmwareAction{
	"security":   system.FirmwareActionAudit,
	"health":     system.FirmwareActionHealth,
	"connection": system.FirmwareActionConnection,
}

func systemFirmwareAudit(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var action = systemFirmwareAuditActions[strings.ToLower(args.String("type"))]
	var out = func(text string) { c.Printf("%s", text) }
	_, err = systemFirmwareRun(c, api, string(action)+" audit", func() error { return api.FirmwareStart(action) },
		out, false, args.Duration("timeout"))
	return systemFirmwareFollowErr(err)
}

func systemFirmwareUpdate(c *Context, args *Args) error {
	return systemFirmwareInstall(c, args, system.FirmwareActionUpdate)
}

func systemFirmwareUpgrade(c *Context, args *Args) error {
	return systemFirmwareInstall(c, args, system.FirmwareActionUpgrade)
}

func systemFirmwareInstall(c *Context, args *Args, action system.FirmwareAction) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var progress, runErr = systemFirmwareRun(c, api, string(action), func() error { return api.FirmwareStart(action) },
		systemFirmwareStderr(c), args.Bool("background"), args.Duration("timeout"))
	if runErr != nil {
		return systemFirmwareFollowErr(runErr)
	}
	systemFirmwareFinished(c, string(action), progress)
	return nil
}

// systemFirmwareFinished tells about a reboot at the end of an action
func systemFirmwareFinished(c *Context, what string, progress system.FirmwareProgress) {
	if progress.Status == system.FirmwareProgressReboot {
		c.Infof("the %s finished, the firewall reboots now", what)
	}
}

func systemFirmwareLog(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var progress, progressErr = api.FirmwareProgress()
	if progressErr != nil {
		return progressErr
	}
	if !args.Bool("follow") || progress.Status != system.FirmwareProgressRunning {
		if progress.Log == "" {
			c.Infof("no firmware action ran since the last boot")
			return nil
		}
		c.Println(strings.TrimRight(progress.Log, "\n"))
		if progress.Status == system.FirmwareProgressRunning {
			c.Infof(`the action is still running, follow it with "log follow"`)
		}
		return nil
	}
	// show what is there, then follow from it
	c.Printf("%s", progress.Log)
	var out = func(text string) { c.Printf("%s", text) }
	var final, followErr = systemFirmwareFollow(c, api, "firmware action",
		system.FirmwareWaitOptions{Timeout: 2 * time.Hour, Running: progress.Log, Output: out})
	if followErr != nil {
		return systemFirmwareFollowErr(followErr)
	}
	systemFirmwareFinished(c, "firmware action", final)
	return nil
}
