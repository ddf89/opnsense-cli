package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"os"
	"strconv"
	"strings"
	"time"
)

// /system/backup: the configuration history (System > Configuration > History / Backups). Items are backup ids
// like config-1792886029.2372.xml, the newest one is the running configuration

const systemBackupItemHelp = "the # of print or a backup id like config-1792886029.2372.xml"

func init() {
	Root.Sub("system", "system settings, configuration and power")
	var menu = Root.Menu("system/backup")
	menu.Help = "configuration history and backups (System > Configuration > History)"

	var providerArg = Arg{Name: "provider", Default: system.BackupProviderLocal, Complete: systemBackupCompleteProviders,
		Help: `backup provider, see providers ("this" is the local firewall)`}
	var itemArg = func(help string, required bool) Arg {
		var complete = systemBackupCompleteIds
		if !required {
			complete = systemBackupCompleteIdsOrCurrent
		}
		return Arg{Name: "item", Positional: true, Required: required, Help: help, Complete: complete}
	}

	menu.Add(
		&Command{
			Name: "print",
			Help: "list the configuration history, newest first",
			Args: []Arg{
				providerArg,
				{Name: "detail", Type: Bool, Help: "show all fields of every backup"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only backups whose id, user or description contains this text (case-insensitive)"},
			},
			Run: systemBackupPrint,
		},
		&Command{
			Name: "providers",
			Help: `list the backup providers ("this" is the local firewall)`,
			Args: []Arg{{Name: "json", Type: Bool, Help: "one JSON object per line"}},
			Run:  systemBackupProviders,
		},
		&Command{
			Name: "download",
			Help: "save a config.xml (the current configuration by default)",
			Long: `The file contains secrets (password hashes, API keys, private keys), so it is written to a file
(mode 0600) named like OPNsense suggests (config-<host>-<time>.xml) unless file= is given; file=- writes
to stdout. An existing file is only overwritten with overwrite.`,
			Args: []Arg{
				itemArg(systemBackupItemHelp+", or current", false),
				providerArg,
				{Name: "file", Help: "file to write, - for stdout (default: the name suggested by OPNsense)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: systemBackupDownload,
		},
		&Command{
			Name: "diff",
			Help: "show the changes between two backups as unified diff",
			Long: `from is the old side, to the new side (default: current, the running configuration), e.g.
  diff 3           changes since backup #3 of the last print
  diff from=2 to=1`,
			Args: []Arg{
				{Name: "from", Positional: true, Required: true, Complete: systemBackupCompleteIds,
					Help: "backup to compare from (old side): " + systemBackupItemHelp},
				{Name: "to", Default: system.BackupCurrent, Complete: systemBackupCompleteIdsOrCurrent,
					Help: "backup to compare to (new side): " + systemBackupItemHelp + ", or current"},
				providerArg,
			},
			Run: systemBackupDiff,
		},
		&Command{
			Name:    "revert",
			Help:    "restore a backup of the local history as running configuration",
			Long:    `Services are not reconfigured automatically: reconfigure them or reboot to apply the reverted configuration.`,
			Args:    []Arg{itemArg(systemBackupItemHelp, true)},
			Check:   systemBackupCheckLocalItem,
			Confirm: "This replaces the WHOLE running configuration with the backup, including users and API keys (the API key in use may stop working).",
			Run:     systemBackupRevert,
		},
		&Command{
			Name: "remove",
			Help: "delete a backup from the local history",
			Long: `The newest entry is a copy of the running configuration: after removing it, "current" (download,
diff) refers to the previous revision until the configuration is saved again.`,
			Args:    []Arg{itemArg(systemBackupItemHelp, true)},
			Check:   systemBackupCheckLocalItem,
			Confirm: "This deletes the backup from the configuration history, it can not be restored.",
			Run:     systemBackupRemove,
		},
	)
}

func systemBackupApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

func systemBackupTime(backup system.Backup) string {
	var timestamp, ok = backup.Timestamp()
	if !ok {
		return backup.TimeIso
	}
	return timestamp.Local().Format(time.DateTime)
}

func systemBackupPrint(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	backups, err := api.BackupList(args.String("provider"))
	if err != nil {
		return err
	}

	if search := strings.ToLower(args.String("search")); search != "" {
		backups = coreapi.Filter(backups, func(backup system.Backup) bool {
			for _, value := range []string{backup.Id, backup.Username, backup.Description} {
				if strings.Contains(strings.ToLower(value), search) {
					return true
				}
			}
			return false
		})
	}

	var ids = make([]string, 0, len(backups))
	for _, backup := range backups {
		ids = append(ids, backup.Id)
	}

	switch {
	case args.Bool("json"):
		for _, backup := range backups {
			if err := c.JSON(backup); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(backups))
		for _, backup := range backups {
			items = append(items, [][2]string{
				{"id", backup.Id},
				{"time", systemBackupTime(backup)},
				{"user", backup.Username},
				{"size", strconv.FormatInt(backup.Filesize, 10)},
				{"description", backup.Description},
			})
		}
		c.Details(items, ids)
	default:
		var rows = make([][]string, 0, len(backups))
		for _, backup := range backups {
			rows = append(rows, []string{
				backup.Id,
				systemBackupTime(backup),
				backup.Username,
				strconv.FormatInt(backup.Filesize, 10),
				backup.Description,
			})
		}
		c.Items([]string{"ID", "TIME", "USER", "SIZE", "DESCRIPTION"}, rows, ids)
	}
	return nil
}

func systemBackupProviders(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	providers, err := api.BackupProviders()
	if err != nil {
		return err
	}

	if args.Bool("json") {
		for _, provider := range providers {
			var object = map[string]string{"name": provider.Name, "description": provider.Description, "dirname": provider.Dirname}
			if err := c.JSON(object); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(providers))
	for _, provider := range providers {
		rows = append(rows, []string{provider.Name, provider.Description, provider.Dirname})
	}
	c.Table([]string{"NAME", "DESCRIPTION", "DIRECTORY"}, rows)
	return nil
}

// systemBackupIsCurrent tells whether a selector means the running configuration
func systemBackupIsCurrent(selector string) bool {
	selector = strings.TrimSpace(selector)
	return selector == "" || strings.EqualFold(selector, system.BackupCurrent)
}

// systemBackupSelect resolves a selector (# of the last print or backup id) against the history of provider
func systemBackupSelect(c *Context, backups []system.Backup, selector string) (string, error) {
	var backup, err = Select(c, selector, backups, func(b system.Backup) string { return b.Id }, func(system.Backup) []string { return nil })
	if err != nil {
		var notFound *coreapi.NotFoundError
		if _, numberErr := strconv.Atoi(strings.TrimSpace(selector)); numberErr != nil && errors.As(err, &notFound) {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("backup %s, use the # of print or a backup id", selector)}
		}
		return "", err
	}
	return backup.Id, nil
}

// systemBackupResolver lists the history of a provider at most once and resolves selectors against it,
// "current" stays "current" (the API maps it to the newest backup)
type systemBackupResolver struct {
	c        *Context
	api      *system.SystemApi
	provider string
	backups  []system.Backup
	listed   bool
}

func (r *systemBackupResolver) resolve(selector string) (string, error) {
	if systemBackupIsCurrent(selector) {
		return system.BackupCurrent, nil
	}
	if !r.listed {
		var backups, err = r.api.BackupList(r.provider)
		if err != nil {
			return "", err
		}
		r.backups, r.listed = backups, true
	}
	return systemBackupSelect(r.c, r.backups, selector)
}

func systemBackupDownload(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	var provider = args.String("provider")
	var resolver = &systemBackupResolver{c: c, api: api, provider: provider}
	id, err := resolver.resolve(args.String("item"))
	if err != nil {
		return err
	}

	content, filename, err := api.BackupDownload(provider, id)
	if err != nil {
		return err
	}

	var output = args.String("file")
	if output == "-" {
		_, err = c.Out.Write(content)
		return err
	}
	if output != "" {
		filename = output
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(content))
	return nil
}

func systemBackupDiff(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	var provider = args.String("provider")
	var resolver = &systemBackupResolver{c: c, api: api, provider: provider}
	from, err := resolver.resolve(args.String("from"))
	if err != nil {
		return err
	}
	to, err := resolver.resolve(args.String("to"))
	if err != nil {
		return err
	}

	lines, err := api.BackupDiff(provider, from, to)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		c.Infof("no differences")
		return nil
	}
	for _, line := range lines {
		c.Println(line)
	}
	return nil
}

// systemBackupCheckLocalItem refuses current for revert / remove before the confirmation question
func systemBackupCheckLocalItem(args *Args) error {
	if systemBackupIsCurrent(args.String("item")) {
		return errors.New("item must be a backup (the # of print or a backup id), not current")
	}
	return nil
}

// systemBackupLocalItem resolves the item of revert / remove in the local history (Check already refused current)
func systemBackupLocalItem(c *Context, api *system.SystemApi, selector string) (string, error) {
	if systemBackupIsCurrent(selector) {
		return "", errors.New("item must be a backup (the # of print or a backup id), not current")
	}
	var resolver = &systemBackupResolver{c: c, api: api, provider: system.BackupProviderLocal}
	return resolver.resolve(selector)
}

func systemBackupRevert(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	id, err := systemBackupLocalItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if err := api.BackupRevert(id); err != nil {
		return err
	}
	c.Infof("configuration reverted to %s, reconfigure the services or reboot to apply it", id)
	return nil
}

func systemBackupRemove(c *Context, args *Args) error {
	var api, err = systemBackupApi(c)
	if err != nil {
		return err
	}
	id, err := systemBackupLocalItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	return api.BackupDelete(id)
}

// completion, errors are ignored

func systemBackupCompleteProviders(c *Context) []string {
	var api, err = systemBackupApi(c)
	if err != nil {
		return nil
	}
	var providers, listErr = api.BackupProviders()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(providers))
	for _, provider := range providers {
		names = append(names, provider.Name)
	}
	return names
}

func systemBackupCompleteIds(c *Context) []string {
	var api, err = systemBackupApi(c)
	if err != nil {
		return nil
	}
	var backups, listErr = api.BackupList(system.BackupProviderLocal)
	if listErr != nil {
		return nil
	}
	var ids = make([]string, 0, len(backups))
	for _, backup := range backups {
		ids = append(ids, backup.Id)
	}
	return ids
}

func systemBackupCompleteIdsOrCurrent(c *Context) []string {
	return append([]string{system.BackupCurrent}, systemBackupCompleteIds(c)...)
}
