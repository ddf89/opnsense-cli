package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/snapshot: ZFS boot environments (System > Snapshots). Items are selected by the # of print, the uuid or
// the name. Every command first checks that the firewall runs on ZFS, nothing is sent otherwise. activate makes the
// firewall boot the environment at the next reboot

const (
	systemSnapshotItemHelp        = "the #, uuid or name of the snapshot"
	systemSnapshotActivateWarning = "This makes the firewall boot this snapshot (its configuration and software) at the next reboot."
)

var errSystemSnapshotUnsupported = errors.New("snapshots are ZFS boot environments, this firewall does not run on ZFS")

func init() {
	var menu = Root.Menu("system/snapshot")
	menu.Help = "ZFS boot environments (System > Snapshots)"
	var item = Arg{Name: "item", Help: systemSnapshotItemHelp, Positional: true, Required: true, Complete: systemSnapshotItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the boot environments",
			Long: `ACTIVE is now (running), reboot (booted next time), now,reboot or -.`,
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every snapshot"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
				{Name: "search", Help: "only snapshots whose name or note contains this text"},
			},
			Run: systemSnapshotPrint},
		&Command{Name: "show", Help: "show one boot environment with its note", Args: []Arg{item}, Run: systemSnapshotShow},
		&Command{Name: "add", Help: "create a boot environment of the running system (or clone one), prints its uuid",
			Args: []Arg{
				{Name: "name", Help: "the name (letters, digits, - _ .), default the current time like 20261025153949",
					Validate: system.SnapshotValidateName},
				{Name: "note", Help: "a note (OPNsense 26.7.x after 26.7.0)"},
				{Name: "from", Help: "clone this snapshot (#, uuid or name) instead of the running system",
					Complete: systemSnapshotItemNames},
			},
			Run: systemSnapshotAdd},
		&Command{Name: "set", Help: "rename a boot environment or change its note",
			Args: []Arg{item,
				{Name: "name", Help: "the new name", Validate: system.SnapshotValidateName},
				{Name: "note", Help: `the note, "" clears it`},
			},
			Check: systemSnapshotCheckSet, Run: systemSnapshotSet},
		&Command{Name: "remove", Help: "delete a boot environment",
			Long: `The running one and the one booted next can not be removed.`,
			Args: []Arg{item}, Run: systemSnapshotRemove},
		&Command{Name: "activate", Help: "boot this environment at the next reboot",
			Args: []Arg{item}, Confirm: systemSnapshotActivateWarning, Run: systemSnapshotActivate},
	)
}

func systemSnapshotCheckSet(args *Args) error {
	if !args.Has("name") && !args.Has("note") {
		return errors.New(`set: nothing to change, give name= or note= (type "set ?" for help)`)
	}
	return nil
}

// systemSnapshotApi returns the API after checking that boot environments are supported
func systemSnapshotApi(c *Context) (*system.SystemApi, error) {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil, err
	}
	var supported, supportedErr = api.SnapshotSupported()
	if supportedErr != nil {
		return nil, supportedErr
	}
	if !supported {
		return nil, errSystemSnapshotUnsupported
	}
	return api, nil
}

func systemSnapshotUuid(snapshot system.Snapshot) string {
	return snapshot.Uuid
}

func systemSnapshotNames(snapshot system.Snapshot) []string {
	return []string{snapshot.Name}
}

func systemSnapshotSelect(c *Context, api *system.SystemApi, selector string) (system.Snapshot, error) {
	var snapshots, err = api.SnapshotList()
	if err != nil {
		return system.Snapshot{}, err
	}
	return Select(c, selector, snapshots, systemSnapshotUuid, systemSnapshotNames)
}

func systemSnapshotItemNames(c *Context) []string {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil
	}
	var snapshots, listErr = api.SnapshotList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		names = append(names, snapshot.Name)
	}
	return names
}

func systemSnapshotActive(snapshot system.Snapshot) string {
	var states []string
	if snapshot.ActiveNow() {
		states = append(states, "now")
	}
	if snapshot.ActiveOnReboot() {
		states = append(states, "reboot")
	}
	return strings.Join(states, ",")
}

func systemSnapshotFields(snapshot system.Snapshot) [][2]string {
	return [][2]string{
		{"uuid", snapshot.Uuid},
		{"name", snapshot.Name},
		{"active", systemSnapshotActive(snapshot)},
		{"mountpoint", snapshot.Mountpoint},
		{"size", snapshot.Size},
		{"created", snapshot.Created},
		{"note", snapshot.Note},
	}
}

func systemSnapshotPrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var supported, supportedErr = api.SnapshotSupported()
	if supportedErr != nil {
		return supportedErr
	}
	if !supported {
		c.Infof("%v", errSystemSnapshotUnsupported)
		return nil
	}
	var all, raw, listErr = api.SnapshotListRaw()
	if listErr != nil {
		return listErr
	}
	var snapshots []system.Snapshot
	var rows []json.RawMessage
	var phrase = strings.ToLower(args.String("search"))
	for i, snapshot := range all {
		if phrase == "" || strings.Contains(strings.ToLower(snapshot.Name), phrase) || strings.Contains(strings.ToLower(snapshot.Note), phrase) {
			snapshots = append(snapshots, snapshot)
			rows = append(rows, raw[i])
		}
	}
	var uuids = make([]string, len(snapshots))
	for i, snapshot := range snapshots {
		uuids[i] = snapshot.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range rows {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(snapshots))
		for i, snapshot := range snapshots {
			items[i] = systemSnapshotFields(snapshot)
		}
		c.Details(items, uuids)
	default:
		var table = make([][]string, len(snapshots))
		for i, snapshot := range snapshots {
			table[i] = []string{snapshot.Name, systemSnapshotActive(snapshot), snapshot.Mountpoint, snapshot.Size, snapshot.Created, snapshot.Note}
		}
		c.Items([]string{"NAME", "ACTIVE", "MOUNTPOINT", "SIZE", "CREATED", "NOTE"}, table, uuids)
	}
	return nil
}

func systemSnapshotShow(c *Context, args *Args) error {
	var api, err = systemSnapshotApi(c)
	if err != nil {
		return err
	}
	var snapshot, selectErr = systemSnapshotSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	// the note is only in get
	if full, getErr := api.SnapshotGet(snapshot.Uuid); getErr == nil {
		snapshot.Note = full.Note
	}
	c.Fields(systemSnapshotFields(snapshot))
	return nil
}

func systemSnapshotAdd(c *Context, args *Args) error {
	var api, err = systemSnapshotApi(c)
	if err != nil {
		return err
	}
	var snapshots, listErr = api.SnapshotList()
	if listErr != nil {
		return listErr
	}
	var from = ""
	if args.Has("from") {
		var source, selectErr = Select(c, args.String("from"), snapshots, systemSnapshotUuid, systemSnapshotNames)
		if selectErr != nil {
			return fmt.Errorf("from: %w", selectErr)
		}
		from = source.Uuid
	}
	var name = args.String("name")
	if name == "" {
		if name, err = api.SnapshotDefaultName(); err != nil {
			return err
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.Name == name {
			return fmt.Errorf("a snapshot named %q exists already (%s)", name, snapshot.Uuid)
		}
	}
	if err := api.SnapshotCreate(name, args.String("note"), from); err != nil {
		return err
	}
	snapshots, listErr = api.SnapshotList()
	if listErr != nil {
		return listErr
	}
	for _, snapshot := range snapshots {
		if snapshot.Name == name {
			c.Println(snapshot.Uuid)
			return nil
		}
	}
	return fmt.Errorf("snapshot %q is missing after the add", name)
}

func systemSnapshotSet(c *Context, args *Args) error {
	var api, err = systemSnapshotApi(c)
	if err != nil {
		return err
	}
	var snapshot, selectErr = systemSnapshotSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var name = snapshot.Name
	if args.Has("name") {
		name = args.String("name")
	}
	var note *string
	if args.Has("note") {
		var value = args.String("note")
		note = &value
	}
	return api.SnapshotUpdate(snapshot.Uuid, name, note)
}

func systemSnapshotRemove(c *Context, args *Args) error {
	var api, err = systemSnapshotApi(c)
	if err != nil {
		return err
	}
	var snapshot, selectErr = systemSnapshotSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if active := systemSnapshotActive(snapshot); active != "" {
		return fmt.Errorf("snapshot %s is active (%s), it can not be removed", snapshot.Name, active)
	}
	return api.SnapshotRemove(snapshot.Uuid)
}

func systemSnapshotActivate(c *Context, args *Args) error {
	var api, err = systemSnapshotApi(c)
	if err != nil {
		return err
	}
	var snapshot, selectErr = systemSnapshotSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if snapshot.ActiveOnReboot() {
		c.Infof("snapshot %s is booted next time already", snapshot.Name)
		return nil
	}
	return api.SnapshotActivate(snapshot.Uuid)
}
