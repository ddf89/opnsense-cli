package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// System > Snapshots (/ui/core/snapshots) manages ZFS boot environments (bectl) through api/core/snapshots:
// is_supported, search, get/<uuid>, add (create, or clone with uuid), set/<uuid> (rename, note), del/<uuid>,
// activate/<uuid> (boot it next time). The uuid is derived from the creation time and changes with nothing but a
// re-creation; actions answer {"status":"ok","result":…} or {"status":"failed","result":…} / validations.
//
// 26.7 quirks: on a non ZFS root file system is_supported answers {"supported":false} and search has no rows; the
// actions fail with "Unsupported root filesystem". add answers the bectl output as a JSON encoded string. Notes are
// only stored by newer 26.7.x releases (26.7.0 has no note field).

// Snapshot is a ZFS boot environment
type Snapshot struct {
	Uuid string
	Name string
	// Active is bectl's flag: "N" active now, "R" active on reboot, "NR" both, "-" neither
	Active     string
	Mountpoint string
	Size       string
	// Created is the creation time as "YYYY-MM-DD HH:MM"
	Created string
	Note    string
}

func (s *Snapshot) UnmarshalJSON(data []byte) error {
	var raw struct {
		Uuid       string `json:"uuid"`
		Name       string `json:"name"`
		Active     string `json:"active"`
		Mountpoint string `json:"mountpoint"`
		Size       string `json:"size"`
		CreatedStr string `json:"created_str"`
		Note       string `json:"note"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = Snapshot{Uuid: raw.Uuid, Name: raw.Name, Active: raw.Active, Mountpoint: raw.Mountpoint, Size: raw.Size,
		Created: raw.CreatedStr, Note: raw.Note}
	return nil
}

// ActiveNow tells whether the firewall runs from this boot environment, ActiveOnReboot whether it boots it next
func (s Snapshot) ActiveNow() bool {
	return strings.ContainsRune(s.Active, 'N')
}

func (s Snapshot) ActiveOnReboot() bool {
	return strings.ContainsRune(s.Active, 'R')
}

var snapshotNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// SnapshotValidateName checks a boot environment name like OPNsense accepts it: letters, digits, - _ and .
func SnapshotValidateName(name string) error {
	if name == "." || name == ".." || !snapshotNamePattern.MatchString(name) {
		return fmt.Errorf("invalid snapshot name %q: letters, digits, - _ and . only", name)
	}
	return nil
}

func (opn *SystemApi) snapshotEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "snapshots", method)
}

// SnapshotSupported tells whether the firewall runs on ZFS (boot environments need it)
func (opn *SystemApi) SnapshotSupported() (bool, error) {
	var container struct {
		Supported *bool `json:"supported"`
	}
	if err := opn.DoJSON("GET", opn.snapshotEndpoint("is_supported"), nil, &container); err != nil {
		return false, err
	}
	if container.Supported == nil {
		return false, errors.New("unexpected answer from OPNsense: no supported flag")
	}
	return *container.Supported, nil
}

// SnapshotListRaw returns the boot environments in API order with the raw API objects
func (opn *SystemApi) SnapshotListRaw() ([]Snapshot, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.snapshotEndpoint("search"), "")
	if err != nil {
		return nil, nil, err
	}
	var snapshots = make([]Snapshot, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &snapshots[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected snapshot from OPNsense: %w", err)
		}
	}
	return snapshots, rows, nil
}

// SnapshotList returns the boot environments in API order
func (opn *SystemApi) SnapshotList() ([]Snapshot, error) {
	var snapshots, _, err = opn.SnapshotListRaw()
	return snapshots, err
}

// SnapshotGet returns the boot environment with this uuid (including its note) or a *NotFoundError (get answers
// an unknown uuid with a new default record)
func (opn *SystemApi) SnapshotGet(uuid string) (Snapshot, error) {
	if uuid == "" {
		return Snapshot{}, errors.New("cannot look up a snapshot without uuid")
	}
	var snapshot Snapshot
	if err := opn.DoJSON("GET", opn.snapshotEndpoint("get")+"/"+url.PathEscape(uuid), nil, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Uuid != uuid {
		return Snapshot{}, &coreapi.NotFoundError{Name: "snapshot " + uuid}
	}
	return snapshot, nil
}

// SnapshotDefaultName returns the name OPNsense suggests for a new boot environment (the current time,
// YYYYMMDDhhmmss)
func (opn *SystemApi) SnapshotDefaultName() (string, error) {
	var snapshot Snapshot
	if err := opn.DoJSON("GET", opn.snapshotEndpoint("get"), nil, &snapshot); err != nil {
		return "", err
	}
	if snapshot.Name == "" {
		return "", errors.New("OPNsense suggested no snapshot name")
	}
	return snapshot.Name, nil
}

// SnapshotCreate creates a boot environment of the running system, or a clone of fromUuid when not empty
func (opn *SystemApi) SnapshotCreate(name string, note string, fromUuid string) error {
	if err := SnapshotValidateName(name); err != nil {
		return err
	}
	var body = map[string]string{"name": name, "note": note}
	if fromUuid != "" {
		body["uuid"] = fromUuid
	}
	return opn.snapshotAction(opn.snapshotEndpoint("add"), body, "snapshot add")
}

// SnapshotUpdate renames a boot environment and/or changes its note (nil keeps the note, the name is required:
// pass the current one to keep it)
func (opn *SystemApi) SnapshotUpdate(uuid string, name string, note *string) error {
	if uuid == "" {
		return errors.New("cannot update a snapshot without uuid")
	}
	if err := SnapshotValidateName(name); err != nil {
		return err
	}
	var body = map[string]string{"name": name}
	if note != nil {
		body["note"] = *note
	} else if current, err := opn.SnapshotGet(uuid); err != nil {
		return err
	} else {
		body["note"] = current.Note // set always writes the note, "" would clear it
	}
	return opn.snapshotAction(opn.snapshotEndpoint("set")+"/"+url.PathEscape(uuid), body, "snapshot set")
}

// SnapshotRemove deletes a boot environment that is not active
func (opn *SystemApi) SnapshotRemove(uuid string) error {
	if uuid == "" {
		return errors.New("cannot remove a snapshot without uuid")
	}
	return opn.snapshotAction(opn.snapshotEndpoint("del")+"/"+url.PathEscape(uuid), nil, "snapshot remove")
}

// SnapshotActivate makes the firewall boot this boot environment at the next reboot
func (opn *SystemApi) SnapshotActivate(uuid string) error {
	if uuid == "" {
		return errors.New("cannot activate a snapshot without uuid")
	}
	return opn.snapshotAction(opn.snapshotEndpoint("activate")+"/"+url.PathEscape(uuid), nil, "snapshot activate")
}

func (opn *SystemApi) snapshotAction(endpoint string, body any, what string) error {
	var raw json.RawMessage
	if err := opn.DoJSON("POST", endpoint, body, &raw); err != nil {
		var httpErr *coreapi.HttpError
		// "Snapshot not found" / "Cannot delete active snapshot" are UserExceptions (HTTP 500 with errorMessage)
		if errors.As(err, &httpErr) && httpErr.Message == "Snapshot not found" {
			return &coreapi.NotFoundError{Name: endpoint, Err: err}
		}
		return err
	}
	// add answers the bectl output as a JSON string
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		raw = json.RawMessage(encoded)
	}
	var container struct {
		Status      string                     `json:"status"`
		Result      string                     `json:"result"`
		Validations coreapi.ValidationMessages `json:"validations"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return fmt.Errorf("unexpected answer to %s: %.100s", what, raw)
	}
	switch {
	case container.Status == "ok":
		return nil
	case len(container.Validations) > 0:
		return &coreapi.ValidationError{Validations: container.Validations}
	case container.Result != "":
		return fmt.Errorf("%s failed: %s", what, container.Result)
	}
	return fmt.Errorf("%s failed: status %q", what, container.Status)
}
