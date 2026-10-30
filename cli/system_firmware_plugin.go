package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/firmware/plugin sync and resync: the web UI's plugin conflict actions (System > Firmware > Plugins, "Run
// the automatic resolver" and "Reset all local conflicts"). OPNsense records the installed plugins in the
// configuration (system.firmware.plugins, the C flag): sync installs the recorded plugins that are missing, resync
// rewrites the record from the installed plugins. Both run in the background like the package actions

const (
	systemFirmwarePluginSyncWarning = "This installs the configured plugins that are not installed, with their " +
		"dependencies (services may restart), then removes unused dependencies (pkg autoremove)."
	systemFirmwarePluginResyncWarning = "This rewrites the configured plugin list from the installed plugins: installed " +
		"plugins that are not registered are registered, configured plugins that are not installed are dropped from " +
		"the configuration (a later sync no longer installs them). No package is installed or removed."
)

func init() {
	var menu = Root.Menu("system/firmware/plugin")
	var follow = []Arg{
		{Name: "background", Type: Bool, Help: "only start it, do not follow it (see /system/firmware log)"},
		{Name: "timeout", Type: Duration, Default: "30m", Validate: systemPowerPositive, Help: "how long to follow it"},
	}
	menu.Add(
		&Command{Name: "sync", Help: "install the configured plugins that are missing",
			Long: `Installs every plugin that is recorded in the configuration but not installed (print all shows them
with installed no and the C flag), like the web UI's "Run the automatic resolver". OPNsense refuses it on an
outdated base ("The update to opnsense-… is required"), then the command fails with that reason. Use it after
restoring a configuration backup on a new installation.`,
			Args: follow, Confirm: systemFirmwarePluginSyncWarning, Run: systemFirmwarePluginSync},
		&Command{Name: "resync", Help: "make the configured plugin list match the installed plugins",
			Long: `Registers the installed plugins that are not recorded in the configuration (no C flag, e.g. installed
with pkg on the console) and unregisters the configured plugins that are not installed, like the web UI's "Reset
all local conflicts". It changes only the configuration, no package. Plugins are registered by their metadata
in /usr/local/opnsense/version: one without it stays unregistered, reinstall it then.`,
			Args: follow, Confirm: systemFirmwarePluginResyncWarning, Run: systemFirmwarePluginResync},
	)
}

func systemFirmwarePluginSync(c *Context, args *Args) error {
	return systemFirmwarePluginRun(c, args, system.FirmwareActionSyncPlugins, "plugin sync", func(info system.FirmwareInfo, log string) error {
		var missing = info.MissingPlugins()
		if len(missing) == 0 {
			return nil
		}
		if reason := systemFirmwareLogReason(log); reason != "" {
			return fmt.Errorf("the plugin sync did not install %s: %s", strings.Join(missing, ", "), reason)
		}
		return fmt.Errorf(`the plugin sync did not install %s, see "/system/firmware log"`, strings.Join(missing, ", "))
	})
}

func systemFirmwarePluginResync(c *Context, args *Args) error {
	return systemFirmwarePluginRun(c, args, system.FirmwareActionResyncPlugins, "plugin resync", func(info system.FirmwareInfo, _ string) error {
		if unregistered := info.UnregisteredPlugins(); len(unregistered) > 0 {
			return fmt.Errorf("the plugin resync did not register %s: OPNsense registers plugins by their metadata in "+
				"/usr/local/opnsense/version, reinstall %s", strings.Join(unregistered, ", "), systemFirmwarePluginThem(unregistered))
		}
		if missing := info.MissingPlugins(); len(missing) > 0 {
			return fmt.Errorf(`the plugin resync did not unregister %s, see "/system/firmware log"`, strings.Join(missing, ", "))
		}
		return nil
	})
}

// systemFirmwarePluginRun starts a plugin sync or resync, follows it and checks its outcome with verify on the
// plugins afterwards: OPNsense ends a refused action with ***DONE*** like a successful one
func systemFirmwarePluginRun(c *Context, args *Args, action system.FirmwareAction, what string, verify func(info system.FirmwareInfo, log string) error) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var progress, runErr = systemFirmwareRun(c, api, what, func() error { return api.FirmwareStart(action) },
		systemFirmwareStderr(c), args.Bool("background"), args.Duration("timeout"))
	if runErr != nil {
		return systemFirmwareFollowErr(runErr)
	}
	systemFirmwareFinished(c, what, progress)
	if args.Bool("background") || progress.Status == system.FirmwareProgressReboot {
		return nil
	}
	var info, infoErr = api.FirmwareInfo()
	if infoErr != nil {
		return infoErr
	}
	return verify(info, progress.Log)
}

// systemFirmwarePluginHints warns on stderr about installed plugins that are not registered in the
// configuration and configured plugins that are not installed, with the command that fixes it
func systemFirmwarePluginHints(c *Context, info system.FirmwareInfo) {
	if unregistered := info.UnregisteredPlugins(); len(unregistered) > 0 {
		c.Infof(`warning: %s %s installed but not registered in the configuration (no C flag), register %s with `+
			`"/system/firmware/plugin resync"`, strings.Join(unregistered, ", "), systemFirmwarePluginVerb(unregistered),
			systemFirmwarePluginThem(unregistered))
	}
	if missing := info.MissingPlugins(); len(missing) > 0 {
		c.Infof(`warning: %s %s configured but not installed (missing), install %s with "/system/firmware/plugin sync" `+
			`or unregister %[3]s with "/system/firmware/plugin resync"`, strings.Join(missing, ", "),
			systemFirmwarePluginVerb(missing), systemFirmwarePluginThem(missing))
	}
}

func systemFirmwarePluginVerb(names []string) string {
	if len(names) == 1 {
		return "is"
	}
	return "are"
}

func systemFirmwarePluginThem(names []string) string {
	if len(names) == 1 {
		return "it"
	}
	return "them"
}
