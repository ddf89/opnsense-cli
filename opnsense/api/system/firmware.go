package system

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// System > Firmware (/ui/core/firmware) is backed by api/core/firmware (OPNsense\Core\Api\FirmwareController):
//
//   - status (GET: the result of the last check, no network access), info (installed and available packages,
//     plugins, changelogs), get / get_options / set (mirror, flavour, type settings), running (ready|busy),
//     upgradestatus (status and log of the last background action)
//   - POST only, read-only but slow: changelog/<version>, details/<pkg>, license/<pkg>
//   - background actions (POST, answer {"status":"ok","msg_uuid":…} at once, progress via upgradestatus):
//     check, audit, health, connection, update, upgrade, install/<pkg>, remove/<pkg>, reinstall/<pkg>,
//     lock/<pkg>, unlock/<pkg>. Anything but a POST answers {"status":"failure"} without doing anything.
//
// 26.7 quirks: a check can upgrade pkg itself first ("New version of pkg detected"), like the web UI's check.
// The background actions do not refuse to start while another one runs, check FirmwareBusy first.
// upgradestatus keeps the log of the previous action until the new one truncates it.

const (
	// FirmwareStatusNone no updates (or no check yet), FirmwareStatusUpdate updates within the series,
	// FirmwareStatusUpgrade a major upgrade, FirmwareStatusError the check failed (see StatusMsg)
	FirmwareStatusNone    = "none"
	FirmwareStatusUpdate  = "update"
	FirmwareStatusUpgrade = "upgrade"
	FirmwareStatusError   = "error"

	// FirmwareProgressRunning the action runs, FirmwareProgressDone it finished, FirmwareProgressReboot it
	// finished and the firewall reboots now, FirmwareProgressError there is no log (yet)
	FirmwareProgressRunning = "running"
	FirmwareProgressDone    = "done"
	FirmwareProgressReboot  = "reboot"
	FirmwareProgressError   = "error"
)

// FirmwareProduct describes the installed product (part of status and info)
type FirmwareProduct struct {
	Name           string `json:"product_name"`
	Id             string `json:"product_id"`
	Version        string `json:"product_version"`
	Series         string `json:"product_series"`
	Nickname       string `json:"product_nickname"`
	Abi            string `json:"product_abi"`
	Arch           string `json:"product_arch"`
	Hash           string `json:"product_hash"`
	Time           string `json:"product_time"`
	Latest         string `json:"product_latest"`
	Mirror         string `json:"product_mirror"`
	Repos          string `json:"product_repos"`
	Tier           string `json:"product_tier"`
	Website        string `json:"product_website"`
	Email          string `json:"product_email"`
	CopyrightOwner string `json:"product_copyright_owner"`
	CopyrightUrl   string `json:"product_copyright_url"`
	CopyrightYears string `json:"product_copyright_years"`
	// License is the business license information, [] for the community edition
	License json.RawMessage `json:"product_license"`
}

// FirmwareUpdate is one pending package or set change of a check
type FirmwareUpdate struct {
	Name       string `json:"name"`
	Reason     string `json:"reason"` // upgrade, new, reinstall, downgrade, obsolete
	Old        string `json:"old"`
	New        string `json:"new"`
	Repository string `json:"repository"`
}

// FirmwareStatus is the result of the last check for updates
type FirmwareStatus struct {
	// Status is one of FirmwareStatusNone, -Update, -Upgrade, -Error
	Status    string
	StatusMsg string
	// Reboot tells that installing the pending updates reboots the firewall
	Reboot bool
	// LastCheck is empty when there was no check since boot
	LastCheck           string
	OsVersion           string
	ProductVersion      string
	Connection          string
	Repository          string
	DownloadSize        string
	UpgradeMajorVersion string
	UpgradeMajorMessage string
	// Updates are the pending package changes, Sets the pending set changes of a major upgrade (sorted by name)
	Updates []FirmwareUpdate
	Sets    []FirmwareUpdate
	Product FirmwareProduct
}

func (s *FirmwareStatus) UnmarshalJSON(data []byte) error {
	var raw struct {
		Status              string          `json:"status"`
		StatusMsg           string          `json:"status_msg"`
		StatusReboot        string          `json:"status_reboot"`
		LastCheck           string          `json:"last_check"`
		OsVersion           string          `json:"os_version"`
		ProductVersion      string          `json:"product_version"`
		Connection          string          `json:"connection"`
		Repository          string          `json:"repository"`
		DownloadSize        string          `json:"download_size"`
		UpgradeMajorVersion string          `json:"upgrade_major_version"`
		UpgradeMajorMessage string          `json:"upgrade_major_message"`
		AllPackages         json.RawMessage `json:"all_packages"`
		AllSets             json.RawMessage `json:"all_sets"`
		Product             FirmwareProduct `json:"product"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var updates, err = firmwareNamedList[FirmwareUpdate](raw.AllPackages)
	if err != nil {
		return fmt.Errorf("all_packages: %w", err)
	}
	sets, err := firmwareNamedList[FirmwareUpdate](raw.AllSets)
	if err != nil {
		return fmt.Errorf("all_sets: %w", err)
	}
	*s = FirmwareStatus{
		Status: raw.Status, StatusMsg: raw.StatusMsg, Reboot: raw.StatusReboot == "1", LastCheck: raw.LastCheck,
		OsVersion: raw.OsVersion, ProductVersion: raw.ProductVersion, Connection: raw.Connection,
		Repository: raw.Repository, DownloadSize: raw.DownloadSize, UpgradeMajorVersion: raw.UpgradeMajorVersion,
		UpgradeMajorMessage: raw.UpgradeMajorMessage, Updates: updates, Sets: sets, Product: raw.Product,
	}
	if s.ProductVersion == "" {
		s.ProductVersion = s.Product.Version
	}
	return nil
}

// firmwareNamedList decodes an object of name → T (PHP's sorted array) or a JSON list ([] when empty) into a list
// sorted by key
func firmwareNamedList[T any](raw json.RawMessage) ([]T, error) {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []T{}, nil
	}
	if trimmed[0] == '[' {
		var list []T
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var named map[string]T
	if err := json.Unmarshal(trimmed, &named); err != nil {
		return nil, err
	}
	var keys = make([]string, 0, len(named))
	for key := range named {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToLower(keys[i]) < strings.ToLower(keys[j]) })
	var list = make([]T, 0, len(keys))
	for _, key := range keys {
		list = append(list, named[key])
	}
	return list, nil
}

// FirmwarePackage is an installed or available package (or plugin) of System > Firmware > Packages / Plugins
type FirmwarePackage struct {
	Name    string
	Version string
	Comment string
	// FlatSize is the installed size as OPNsense formats it, e.g. 5.52MiB
	FlatSize   string
	License    string
	Repository string
	Origin     string
	Locked     bool
	// Automatic packages were installed as a dependency
	Automatic bool
	Installed bool
	// Provided by a configured repository (can be installed)
	Provided bool
	// Configured plugins are recorded in the configuration (missing ones are installed by a plugin sync)
	Configured bool
	// Tier is the plugin support tier 1 (core) to 4 (community), only set for plugins
	Tier string
}

func (p *FirmwarePackage) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// OPNsense fills unknown values with the (translated) text "N/A"
	var text = func(key string) string {
		if raw[key] == "N/A" {
			return ""
		}
		return raw[key]
	}
	*p = FirmwarePackage{
		Name: raw["name"], Version: text("version"), Comment: text("comment"), FlatSize: text("flatsize"),
		License: text("license"), Repository: text("repository"), Origin: text("origin"),
		Locked: raw["locked"] == "1", Automatic: raw["automatic"] == "1", Installed: raw["installed"] == "1",
		Provided: raw["provided"] == "1", Configured: raw["configured"] == "1", Tier: raw["tier"],
	}
	return nil
}

// FirmwareChangelogItem is one release with a changelog
type FirmwareChangelogItem struct {
	Series  string `json:"series"`
	Version string `json:"version"`
	// Date is YYYY-MM-DD
	Date string `json:"date"`
}

// FirmwareInfo lists the packages, plugins and changelogs of System > Firmware
type FirmwareInfo struct {
	ProductId      string
	ProductVersion string
	// Packages are all installed and available packages sorted by name, Plugins the os-* packages (installed
	// first, then the available ones)
	Packages []FirmwarePackage
	Plugins  []FirmwarePackage
	// Changelogs newest first. The list is downloaded by a check, it is empty before the first one
	Changelogs []FirmwareChangelogItem
	Product    FirmwareProduct
}

func (i *FirmwareInfo) UnmarshalJSON(data []byte) error {
	var raw struct {
		ProductId      string                  `json:"product_id"`
		ProductVersion string                  `json:"product_version"`
		Package        []FirmwarePackage       `json:"package"`
		Plugin         []FirmwarePackage       `json:"plugin"`
		Changelog      []FirmwareChangelogItem `json:"changelog"`
		Product        json.RawMessage         `json:"product"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*i = FirmwareInfo{ProductId: raw.ProductId, ProductVersion: raw.ProductVersion, Packages: raw.Package,
		Plugins: raw.Plugin, Changelogs: raw.Changelog}
	// product is [] when OPNsense could not read it
	if trimmed := bytes.TrimSpace(raw.Product); len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &i.Product); err != nil {
			return fmt.Errorf("product: %w", err)
		}
	}
	return nil
}

// FirmwareChangelog is the changelog of one release
type FirmwareChangelog struct {
	Version string
	// Date as OPNsense writes it, e.g. "October 13, 2026"
	Date string
	Html string
}

// FirmwareProgress is the state of the last background firmware action
type FirmwareProgress struct {
	// Status is one of FirmwareProgressRunning, -Done, -Reboot, -Error (no log)
	Status string `json:"status"`
	Log    string `json:"log"`
}

// FirmwareSettings are the repository settings of System > Firmware > Settings
type FirmwareSettings struct {
	// Mirror is the package mirror URL, "" for the default
	Mirror string `json:"mirror"`
	// Flavour is the package flavour ("" default, e.g. "libressl"), Type the release type ("" community,
	// "devel", "business")
	Flavour string `json:"flavour"`
	Type    string `json:"type"`
	// Subscription is the business subscription key (a secret)
	Subscription string `json:"subscription"`
	// Plugins are the configured plugins (comma separated), they can not be changed through the settings
	Plugins string `json:"plugins"`
	// Reboot always reboots after a successful update, Aux enables the auxiliary packages repository ("1"/"0")
	Reboot string `json:"reboot"`
	Aux    string `json:"aux"`
}

// FirmwareSettingsPatch holds the settings to change, nil fields are kept
type FirmwareSettingsPatch struct {
	Mirror       *string
	Flavour      *string
	Type         *string
	Subscription *string
	Reboot       *bool
	Aux          *bool
}

// FirmwareOption is one choice of a firmware setting: Key is stored, Name displayed
type FirmwareOption struct {
	Key  string
	Name string
	// Subscription tells that the choice needs a subscription key
	Subscription bool
}

// FirmwareOptions are the known choices of the firmware settings in the order OPNsense lists them. Mirror and
// flavour also accept custom values
type FirmwareOptions struct {
	Mirrors  []FirmwareOption
	Flavours []FirmwareOption
	Types    []FirmwareOption
}

func (o *FirmwareOptions) UnmarshalJSON(data []byte) error {
	var raw struct {
		Mirrors                 json.RawMessage `json:"mirrors"`
		MirrorsSubscription     []string        `json:"mirrors_has_subscription"`
		Flavours                json.RawMessage `json:"flavours"`
		FlavoursSubscription    []string        `json:"flavours_has_subscription"`
		Families                json.RawMessage `json:"families"`
		FamiliesHasSubscription []string        `json:"families_has_subscription"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var err error
	if o.Mirrors, err = firmwareOptionList(raw.Mirrors, raw.MirrorsSubscription); err != nil {
		return fmt.Errorf("mirrors: %w", err)
	}
	if o.Flavours, err = firmwareOptionList(raw.Flavours, raw.FlavoursSubscription); err != nil {
		return fmt.Errorf("flavours: %w", err)
	}
	if o.Types, err = firmwareOptionList(raw.Families, raw.FamiliesHasSubscription); err != nil {
		return fmt.Errorf("families: %w", err)
	}
	return nil
}

// firmwareOptionList decodes {"<key>":"<name>",...} keeping its order
func firmwareOptionList(raw json.RawMessage, subscription []string) ([]FirmwareOption, error) {
	var options = make([]FirmwareOption, 0)
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] == '[' || bytes.Equal(trimmed, []byte("null")) {
		return options, nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("not an option map: %.50s", raw)
	}
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		var name string
		if err := decoder.Decode(&name); err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		var option = FirmwareOption{Key: key, Name: name}
		for _, needs := range subscription {
			option.Subscription = option.Subscription || needs == key
		}
		options = append(options, option)
	}
	return options, nil
}

func (opn *SystemApi) firmwareEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "firmware", method)
}

// FirmwareStatus returns the result of the last check for updates (it does not check, see FirmwareCheck)
func (opn *SystemApi) FirmwareStatus() (FirmwareStatus, error) {
	var status FirmwareStatus
	var raw, err = opn.FirmwareStatusRaw()
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return status, fmt.Errorf("unexpected firmware status from OPNsense: %w", err)
	}
	return status, nil
}

// FirmwareStatusRaw returns the status as the API answers it
func (opn *SystemApi) FirmwareStatusRaw() (json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("status"), nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// FirmwareInfo returns the installed and available packages, plugins and changelogs
func (opn *SystemApi) FirmwareInfo() (FirmwareInfo, error) {
	var info FirmwareInfo
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("info"), nil, &info); err != nil {
		return info, err
	}
	return info, nil
}

// FirmwareChangelog returns the changelog of a release (e.g. "26.7.7") or a *NotFoundError
func (opn *SystemApi) FirmwareChangelog(version string) (FirmwareChangelog, error) {
	if err := FirmwareValidateVersion(version); err != nil {
		return FirmwareChangelog{}, err
	}
	var container struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Date    string `json:"date"`
		Html    string `json:"html"`
	}
	if err := opn.DoJSON("POST", opn.firmwareEndpoint("changelog")+"/"+url.PathEscape(version), nil, &container); err != nil {
		return FirmwareChangelog{}, err
	}
	if container.Status != "ok" {
		return FirmwareChangelog{}, &coreapi.NotFoundError{Name: fmt.Sprintf("changelog of %q (run a check to download the changelogs)", version)}
	}
	return FirmwareChangelog{Version: container.Version, Date: container.Date, Html: container.Html}, nil
}

var (
	firmwareVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+[0-9A-Za-z._-]*$`)
	firmwarePackagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

// FirmwareValidateVersion checks a release version like 26.7 or 26.7.7
func FirmwareValidateVersion(version string) error {
	if !firmwareVersionPattern.MatchString(version) {
		return fmt.Errorf("invalid release version %q, like 26.7.7", version)
	}
	return nil
}

// FirmwareValidatePackage checks a package name like os-acme-client (letters, digits and . _ + -)
func FirmwareValidatePackage(name string) error {
	if !firmwarePackagePattern.MatchString(name) {
		return fmt.Errorf("invalid package name %q", name)
	}
	return nil
}

// FirmwarePackageDetails returns the description of a package (installed or available) or a *NotFoundError
func (opn *SystemApi) FirmwarePackageDetails(name string) (string, error) {
	return opn.firmwarePackageText("details", name)
}

// FirmwarePackageLicense returns the license text of a package or a *NotFoundError
func (opn *SystemApi) FirmwarePackageLicense(name string) (string, error) {
	return opn.firmwarePackageText("license", name)
}

func (opn *SystemApi) firmwarePackageText(method string, name string) (string, error) {
	if err := FirmwareValidatePackage(name); err != nil {
		return "", err
	}
	// {"details":"..."} / {"license":"..."}, unknown packages answer []
	var raw json.RawMessage
	if err := opn.DoJSON("POST", opn.firmwareEndpoint(method)+"/"+url.PathEscape(name), nil, &raw); err != nil {
		return "", err
	}
	var container map[string]string
	if err := json.Unmarshal(raw, &container); err != nil || container[method] == "" {
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s of package %q", method, name)}
	}
	return container[method], nil
}

// FirmwareSettings returns the repository settings
func (opn *SystemApi) FirmwareSettings() (FirmwareSettings, error) {
	var container struct {
		Firmware FirmwareSettings `json:"firmware"`
	}
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("get"), nil, &container); err != nil {
		return FirmwareSettings{}, err
	}
	return container.Firmware, nil
}

// FirmwareOptions returns the known mirrors, flavours and release types
func (opn *SystemApi) FirmwareOptions() (FirmwareOptions, error) {
	var options FirmwareOptions
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("get_options"), nil, &options); err != nil {
		return options, err
	}
	return options, nil
}

// FirmwareSettingsUpdate changes the non nil settings, the others are kept. OPNsense then regenerates the
// package repository configuration; the new settings are used by the next check or update
func (opn *SystemApi) FirmwareSettingsUpdate(patch FirmwareSettingsPatch) error {
	var fields = map[string]string{}
	for key, value := range map[string]*string{"mirror": patch.Mirror, "flavour": patch.Flavour, "type": patch.Type,
		"subscription": patch.Subscription} {
		if value != nil {
			if strings.ContainsAny(*value, "|\"\n\r") {
				return fmt.Errorf("invalid %s %q: | \" and line breaks are not allowed", key, *value)
			}
			fields[key] = *value
		}
	}
	for key, value := range map[string]*bool{"reboot": patch.Reboot, "aux": patch.Aux} {
		if value != nil {
			fields[key] = map[bool]string{true: "1", false: "0"}[*value]
		}
	}
	if len(fields) == 0 {
		return errors.New("no firmware setting to change")
	}
	var container struct {
		Status    string          `json:"status"`
		StatusMsg json.RawMessage `json:"status_msg"`
	}
	if err := opn.DoJSON("POST", opn.firmwareEndpoint("set"), map[string]any{"firmware": fields}, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		var messages []string
		if err := json.Unmarshal(container.StatusMsg, &messages); err != nil {
			var message string
			_ = json.Unmarshal(container.StatusMsg, &message)
			messages = []string{message}
		}
		return fmt.Errorf("the firmware settings were not saved: status %q %s", container.Status, strings.TrimSpace(strings.Join(messages, "; ")))
	}
	return nil
}

// FirmwareBusy tells whether a firmware action (check, update, install, ...) is running
func (opn *SystemApi) FirmwareBusy() (bool, error) {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("running"), nil, &container); err != nil {
		return false, err
	}
	switch container.Status {
	case "busy":
		return true, nil
	case "ready":
		return false, nil
	}
	return false, fmt.Errorf("unexpected firmware running state %q", container.Status)
}

// FirmwareProgress returns the state and log of the last (or the running) background firmware action
func (opn *SystemApi) FirmwareProgress() (FirmwareProgress, error) {
	var progress FirmwareProgress
	if err := opn.DoJSON("GET", opn.firmwareEndpoint("upgradestatus"), nil, &progress); err != nil {
		return progress, err
	}
	return progress, nil
}

// FirmwareAction is a background firmware action
type FirmwareAction string

const (
	// FirmwareActionCheck checks for updates (downloads the catalogue and changelogs, may upgrade pkg itself)
	FirmwareActionCheck FirmwareAction = "check"
	// FirmwareActionAudit runs a security audit of the installed packages (known vulnerabilities)
	FirmwareActionAudit FirmwareAction = "audit"
	// FirmwareActionHealth verifies the installed files and packages
	FirmwareActionHealth FirmwareAction = "health"
	// FirmwareActionConnection tests the connectivity to the mirror (IPv4 and IPv6, takes minutes when one hangs)
	FirmwareActionConnection FirmwareAction = "connection"
	// FirmwareActionUpdate installs the pending updates, may reboot
	FirmwareActionUpdate FirmwareAction = "update"
	// FirmwareActionUpgrade installs the pending major upgrade and reboots
	FirmwareActionUpgrade FirmwareAction = "upgrade"
	// package actions, see FirmwarePackageAction
	FirmwareActionInstall   FirmwareAction = "install"
	FirmwareActionRemove    FirmwareAction = "remove"
	FirmwareActionReinstall FirmwareAction = "reinstall"
	FirmwareActionLock      FirmwareAction = "lock"
	FirmwareActionUnlock    FirmwareAction = "unlock"
)

func (a FirmwareAction) needsPackage() bool {
	switch a {
	case FirmwareActionInstall, FirmwareActionRemove, FirmwareActionReinstall, FirmwareActionLock, FirmwareActionUnlock:
		return true
	}
	return false
}

// FirmwareStart starts a background action that takes no package (check, audit, health, connection, update,
// upgrade) and returns at once, follow it with FirmwareWait
func (opn *SystemApi) FirmwareStart(action FirmwareAction) error {
	if action.needsPackage() {
		return fmt.Errorf("firmware %s needs a package, use FirmwarePackageAction", action)
	}
	switch action {
	case FirmwareActionCheck, FirmwareActionAudit, FirmwareActionHealth, FirmwareActionConnection, FirmwareActionUpdate, FirmwareActionUpgrade:
	default:
		return fmt.Errorf("unknown firmware action %q", action)
	}
	return opn.firmwareStart(opn.firmwareEndpoint(string(action)), string(action))
}

// FirmwarePackageAction starts install, remove, reinstall, lock or unlock of a package and returns at once,
// follow it with FirmwareWait
func (opn *SystemApi) FirmwarePackageAction(action FirmwareAction, name string) error {
	if !action.needsPackage() {
		return fmt.Errorf("firmware %s is not a package action", action)
	}
	if err := FirmwareValidatePackage(name); err != nil {
		return err
	}
	return opn.firmwareStart(opn.firmwareEndpoint(string(action))+"/"+url.PathEscape(name), fmt.Sprintf("%s of %s", action, name))
}

func (opn *SystemApi) firmwareStart(endpoint string, what string) error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &container); err != nil {
		return err
	}
	if container.Status != "ok" {
		return fmt.Errorf("firmware %s was not accepted: status %q", what, container.Status)
	}
	return nil
}

// FirmwareWaitOptions configures FirmwareWait, zero values use the defaults
type FirmwareWaitOptions struct {
	// Timeout for the whole wait, default 30 minutes
	Timeout time.Duration
	// PollInterval between two progress requests, default 2s
	PollInterval time.Duration
	// Previous is the log of the previous action (FirmwareProgress before starting): until the log differs from
	// it, a "done" status is the previous action's
	Previous string
	// Running follows an action that is known to run already, its log up to Running was shown (Previous is
	// not used then)
	Running string
	// Output gets the new log text as it grows (optional)
	Output func(text string)
	// Now replaces the clock (tests)
	Now func() time.Time
}

// FirmwareWait follows a started background action until it is done (or reboots the firewall) and returns its
// final progress. Failed polls are retried until the timeout: the web server restarts during updates. It stops
// with ctx.Err() when ctx is cancelled (the action goes on)
func (opn *SystemApi) FirmwareWait(ctx context.Context, options FirmwareWaitOptions) (FirmwareProgress, error) {
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Minute
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 2 * time.Second
	}
	if options.Output == nil {
		options.Output = func(string) {}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	var deadline = options.Now().Add(options.Timeout)
	var started = options.Running != ""
	var shown = options.Running
	var last FirmwareProgress
	var lastErr error
	for {
		var progress, err = opn.FirmwareProgress()
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			last = progress
			if !started {
				started = progress.Log != "" && progress.Log != options.Previous
			}
			if started {
				if strings.HasPrefix(progress.Log, shown) {
					if text := progress.Log[len(shown):]; text != "" {
						options.Output(text)
					}
				} else { // a new log
					options.Output(progress.Log)
				}
				shown = progress.Log
				if progress.Status == FirmwareProgressDone || progress.Status == FirmwareProgressReboot {
					if !strings.HasSuffix(shown, "\n") && shown != "" {
						options.Output("\n")
					}
					return progress, nil
				}
			}
		}

		var remaining = deadline.Sub(options.Now())
		if remaining <= 0 {
			switch {
			case lastErr != nil:
				return last, fmt.Errorf("timed out after %s waiting for the firmware action (last error: %w)", options.Timeout, lastErr)
			case !started:
				return last, fmt.Errorf("timed out after %s: the firmware action did not start", options.Timeout)
			}
			return last, fmt.Errorf("timed out after %s waiting for the firmware action to finish, it goes on in the background", options.Timeout)
		}
		var timer = time.NewTimer(min(options.PollInterval, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return last, ctx.Err()
		case <-timer.C:
		}
	}
}
