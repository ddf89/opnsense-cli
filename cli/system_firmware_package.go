package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/firmware/package and /system/firmware/plugin: System > Firmware > Packages and Plugins. print lists the
// installed ones (all: also the available ones of the configured repositories), items are selected by the # of
// print or the package name. install, remove, reinstall, lock and unlock run in the background on the firewall and
// are followed until they finish

// systemFirmwarePackageKind is what one of the two menus lists
type systemFirmwarePackageKind struct {
	what    string // "package" or "plugin"
	plugins bool
}

var (
	systemFirmwarePackageKindPackage = systemFirmwarePackageKind{what: "package"}
	systemFirmwarePackageKindPlugin  = systemFirmwarePackageKind{what: "plugin", plugins: true}
)

func init() {
	systemFirmwarePackageMenu("system/firmware/package", "installed and available packages (System > Firmware > Packages)",
		systemFirmwarePackageKindPackage)
	systemFirmwarePackageMenu("system/firmware/plugin", "installed and available plugins (System > Firmware > Plugins)",
		systemFirmwarePackageKindPlugin)
}

func systemFirmwarePackageMenu(path string, help string, kind systemFirmwarePackageKind) {
	var menu = Root.Menu(path)
	menu.Help = help
	var item = Arg{Name: "item", Help: fmt.Sprintf("the # or name of the %s", kind.what), Positional: true, Required: true,
		Complete: systemFirmwarePackageComplete(kind)}
	var follow = []Arg{
		item,
		{Name: "background", Type: Bool, Help: "only start it, do not follow it (see /system/firmware log)"},
		{Name: "timeout", Type: Duration, Default: "30m", Validate: systemPowerPositive, Help: "how long to follow it"},
	}
	var action = func(action system.FirmwareAction) func(c *Context, args *Args) error {
		return func(c *Context, args *Args) error { return systemFirmwarePackageAction(c, args, kind, action) }
	}
	menu.Add(
		&Command{Name: "print", Help: fmt.Sprintf("list the installed %ss", kind.what),
			Long: `all also lists what the configured repositories provide (the catalogue of the last check). Flags: L
locked (not updated), A automatic (installed as a dependency), C configured (plugins: recorded in the
configuration, a configured plugin that is not installed is missing).`,
			Args: []Arg{
				{Name: "all", Type: Bool, Help: fmt.Sprintf("also list the available %ss", kind.what)},
				{Name: "detail", Type: Bool, Help: "show all fields of every " + kind.what},
				{Name: "json", Type: Bool, Help: "one JSON object per line"},
				{Name: "search", Help: "only those whose name or comment contains this text"},
			},
			Run: func(c *Context, args *Args) error { return systemFirmwarePackagePrint(c, args, kind) }},
		&Command{Name: "show", Help: fmt.Sprintf("show one %s with its description", kind.what), Args: []Arg{item},
			Run: func(c *Context, args *Args) error { return systemFirmwarePackageShow(c, args, kind) }},
		&Command{Name: "license", Help: fmt.Sprintf("print the license of a %s", kind.what), Args: []Arg{item},
			Run: func(c *Context, args *Args) error { return systemFirmwarePackageLicense(c, args, kind) }},
		&Command{Name: "install", Help: "install a " + kind.what, Args: follow, Run: action(system.FirmwareActionInstall),
			Confirm: fmt.Sprintf("This installs the %s with its dependencies, services may restart.", kind.what)},
		&Command{Name: "remove", Help: "remove a " + kind.what, Args: follow, Run: action(system.FirmwareActionRemove),
			Confirm: fmt.Sprintf("This removes the %s, what depends on it stops working.", kind.what)},
		&Command{Name: "reinstall", Help: "reinstall a " + kind.what, Args: follow, Run: action(system.FirmwareActionReinstall),
			Confirm: fmt.Sprintf("This reinstalls the %s, its services may restart.", kind.what)},
		&Command{Name: "lock", Help: "lock a " + kind.what + " (updates leave it alone)", Args: follow,
			Run: action(system.FirmwareActionLock), Confirm: fmt.Sprintf("This locks the %s: updates no longer change it.", kind.what)},
		&Command{Name: "unlock", Help: "unlock a " + kind.what, Args: follow,
			Run: action(system.FirmwareActionUnlock), Confirm: fmt.Sprintf("This unlocks the %s: updates change it again.", kind.what)},
	)
}

// systemFirmwarePackageList returns the packages or plugins, only the installed ones unless all
func systemFirmwarePackageList(api *system.SystemApi, kind systemFirmwarePackageKind, all bool) ([]system.FirmwarePackage, error) {
	var info, err = api.FirmwareInfo()
	if err != nil {
		return nil, err
	}
	var list = info.Packages
	if kind.plugins {
		list = info.Plugins
	}
	if all {
		return list, nil
	}
	var installed = make([]system.FirmwarePackage, 0, len(list))
	for _, pkg := range list {
		if pkg.Installed {
			installed = append(installed, pkg)
		}
	}
	return installed, nil
}

func systemFirmwarePackageName(pkg system.FirmwarePackage) string {
	return pkg.Name
}

func systemFirmwarePackageNames(pkg system.FirmwarePackage) []string {
	return []string{pkg.Name}
}

// systemFirmwarePackageSelect finds the package selector refers to: a # of the last print, else a name of all
// packages (also the available ones)
func systemFirmwarePackageSelect(c *Context, api *system.SystemApi, kind systemFirmwarePackageKind, selector string) (system.FirmwarePackage, error) {
	var all, err = systemFirmwarePackageList(api, kind, true)
	if err != nil {
		return system.FirmwarePackage{}, err
	}
	if _, printed := c.Session.lastPrint[c.Menu.Path()]; !printed && systemFirmwareIsIndex(selector) {
		// one-shot: the # is the position in the default print, the installed ones
		var installed []system.FirmwarePackage
		for _, pkg := range all {
			if pkg.Installed {
				installed = append(installed, pkg)
			}
		}
		return Select(c, selector, installed, systemFirmwarePackageName, systemFirmwarePackageNames)
	}
	return Select(c, selector, all, systemFirmwarePackageName, systemFirmwarePackageNames)
}

func systemFirmwareIsIndex(selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}
	for _, char := range selector {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func systemFirmwarePackageComplete(kind systemFirmwarePackageKind) func(c *Context) []string {
	return func(c *Context) []string {
		var api, err = systemServiceApi(c)
		if err != nil {
			return nil
		}
		var list, listErr = systemFirmwarePackageList(api, kind, kind.plugins)
		if listErr != nil {
			return nil
		}
		var names = make([]string, 0, len(list))
		for _, pkg := range list {
			names = append(names, pkg.Name)
		}
		return names
	}
}

func systemFirmwarePackageFlags(pkg system.FirmwarePackage, kind systemFirmwarePackageKind) string {
	var flags strings.Builder
	for _, flag := range []struct {
		set  bool
		char byte
	}{{pkg.Locked, 'L'}, {pkg.Automatic, 'A'}, {kind.plugins && pkg.Configured, 'C'}} {
		if flag.set {
			flags.WriteByte(flag.char)
		}
	}
	return flags.String()
}

func systemFirmwarePackageFields(pkg system.FirmwarePackage, kind systemFirmwarePackageKind) [][2]string {
	var fields = [][2]string{
		{"name", pkg.Name},
		{"version", pkg.Version},
		{"comment", pkg.Comment},
		{"installed", YesNo(Flag(pkg.Installed))},
		{"available", YesNo(Flag(pkg.Provided))},
		{"locked", YesNo(Flag(pkg.Locked))},
		{"automatic", YesNo(Flag(pkg.Automatic))},
		{"size", pkg.FlatSize},
		{"license", pkg.License},
		{"repository", pkg.Repository},
		{"origin", pkg.Origin},
	}
	if kind.plugins {
		fields = append(fields, [2]string{"configured", YesNo(Flag(pkg.Configured))}, [2]string{"tier", pkg.Tier})
	}
	return fields
}

func systemFirmwarePackageJSON(pkg system.FirmwarePackage, kind systemFirmwarePackageKind) map[string]any {
	var object = map[string]any{
		"name": pkg.Name, "version": pkg.Version, "comment": pkg.Comment, "installed": pkg.Installed,
		"provided": pkg.Provided, "locked": pkg.Locked, "automatic": pkg.Automatic, "flatsize": pkg.FlatSize,
		"license": pkg.License, "repository": pkg.Repository, "origin": pkg.Origin,
	}
	if kind.plugins {
		object["configured"] = pkg.Configured
		object["tier"] = pkg.Tier
	}
	return object
}

func systemFirmwarePackagePrint(c *Context, args *Args, kind systemFirmwarePackageKind) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var list, listErr = systemFirmwarePackageList(api, kind, args.Bool("all"))
	if listErr != nil {
		return listErr
	}
	if args.Has("search") {
		var phrase = strings.ToLower(args.String("search"))
		var matching []system.FirmwarePackage
		for _, pkg := range list {
			if strings.Contains(strings.ToLower(pkg.Name), phrase) || strings.Contains(strings.ToLower(pkg.Comment), phrase) {
				matching = append(matching, pkg)
			}
		}
		list = matching
	}

	var names = make([]string, len(list))
	for i, pkg := range list {
		names[i] = pkg.Name
	}
	switch {
	case args.Bool("json"):
		for _, pkg := range list {
			if err := c.JSON(systemFirmwarePackageJSON(pkg, kind)); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(list))
		for i, pkg := range list {
			items[i] = systemFirmwarePackageFields(pkg, kind)
		}
		c.Details(items, names)
	default:
		var headers = []string{"NAME", "VERSION", "INSTALLED", "FLAGS", "REPOSITORY", "COMMENT"}
		if kind.plugins {
			headers = []string{"NAME", "VERSION", "INSTALLED", "FLAGS", "TIER", "COMMENT"}
		}
		var rows = make([][]string, len(list))
		for i, pkg := range list {
			var column = pkg.Repository
			if kind.plugins {
				column = pkg.Tier
			}
			rows[i] = []string{pkg.Name, pkg.Version, YesNo(Flag(pkg.Installed)), systemFirmwarePackageFlags(pkg, kind), column, pkg.Comment}
		}
		c.Items(headers, rows, names)
	}
	return nil
}

func systemFirmwarePackageShow(c *Context, args *Args, kind systemFirmwarePackageKind) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var pkg, selectErr = systemFirmwarePackageSelect(c, api, kind, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemFirmwarePackageFields(pkg, kind))
	var details, detailsErr = api.FirmwarePackageDetails(pkg.Name)
	if detailsErr == nil {
		c.Println()
		c.Println(strings.TrimRight(details, "\n"))
	}
	return nil
}

func systemFirmwarePackageLicense(c *Context, args *Args, kind systemFirmwarePackageKind) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var pkg, selectErr = systemFirmwarePackageSelect(c, api, kind, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var license, licenseErr = api.FirmwarePackageLicense(pkg.Name)
	if licenseErr != nil {
		return licenseErr
	}
	c.Println(strings.TrimRight(license, "\n"))
	return nil
}

func systemFirmwarePackageAction(c *Context, args *Args, kind systemFirmwarePackageKind, action system.FirmwareAction) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var pkg, selectErr = systemFirmwarePackageSelect(c, api, kind, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	switch {
	case action == system.FirmwareActionInstall && pkg.Installed:
		return fmt.Errorf("%s %s is installed already (reinstall reinstalls it)", kind.what, pkg.Name)
	case action == system.FirmwareActionInstall && !pkg.Provided:
		return fmt.Errorf("%s %s is not available from the configured repositories", kind.what, pkg.Name)
	case action != system.FirmwareActionInstall && !pkg.Installed:
		return fmt.Errorf("%s %s is not installed", kind.what, pkg.Name)
	case action == system.FirmwareActionLock && pkg.Locked:
		return fmt.Errorf("%s %s is locked already", kind.what, pkg.Name)
	case action == system.FirmwareActionUnlock && !pkg.Locked:
		return fmt.Errorf("%s %s is not locked", kind.what, pkg.Name)
	}
	var what = fmt.Sprintf("%s of %s", action, pkg.Name)
	var progress, runErr = systemFirmwareRun(c, api, what, func() error { return api.FirmwarePackageAction(action, pkg.Name) },
		systemFirmwareStderr(c), args.Bool("background"), args.Duration("timeout"))
	if runErr != nil {
		return systemFirmwareFollowErr(runErr)
	}
	systemFirmwareFinished(c, what, progress)
	if args.Bool("background") || progress.Status == system.FirmwareProgressReboot {
		return nil
	}
	return systemFirmwarePackageVerify(api, kind, action, pkg.Name, progress.Log)
}

// systemFirmwarePackageVerify checks that a finished action changed the package. OPNsense ends a refused action
// (e.g. "Installation out of date. The update to opnsense-26.7.7 is required.") with ***DONE*** like a successful
// one. A reinstall can not be checked this way, the package is installed before and after
func systemFirmwarePackageVerify(api *system.SystemApi, kind systemFirmwarePackageKind, action system.FirmwareAction, name string, log string) error {
	var all, err = systemFirmwarePackageList(api, kind, true)
	if err != nil {
		return err
	}
	var done = action == system.FirmwareActionRemove
	for _, pkg := range all {
		if pkg.Name != name {
			continue
		}
		switch action {
		case system.FirmwareActionInstall, system.FirmwareActionReinstall:
			done = pkg.Installed
		case system.FirmwareActionRemove:
			done = !pkg.Installed
		case system.FirmwareActionLock:
			done = pkg.Locked
		case system.FirmwareActionUnlock:
			done = !pkg.Locked
		}
	}
	if done {
		return nil
	}
	if reason := systemFirmwareLogReason(log); reason != "" {
		return fmt.Errorf("the %s of %s failed: %s", action, name, reason)
	}
	return fmt.Errorf(`the %s of %s failed, see "/system/firmware log"`, action, name)
}

// systemFirmwareLogReason returns the last line of a firmware log that is not a ***MARKER*** or the
// "Currently running ..." header, the reason OPNsense gives for a refused action
func systemFirmwareLogReason(log string) string {
	var lines = strings.Split(strings.TrimSpace(log), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var line = strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "***") || strings.HasPrefix(line, "Currently running") {
			continue
		}
		return line
	}
	return ""
}
