package monit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TestActions are what Monit does when a test fails
var TestActions = []string{"alert", "restart", "start", "stop", "exec", "unmonitor"}

// TestTypes are the test types, OPNsense derives the type from the condition ("Custom" when it is no known pattern)
var TestTypes = []string{"Existence", "SystemResource", "ProcessResource", "ProcessDiskIO", "FileChecksum", "Timestamp",
	"FileSize", "FileContent", "FilesystemMountFlags", "SpaceUsage", "InodeUsage", "DiskIO", "Permisssion", "UID", "GID",
	"PID", "PPID", "Uptime", "ProgramStatus", "NetworkInterface", "NetworkPing", "Connection", "Custom"}

// Test is a service test of Services > Monit > Settings > Service Tests Settings: a condition and the action when
// it fails
type Test struct {
	Uuid string `json:"uuid"`
	// Name is shown in the services, letters, digits, . _ - and no spaces
	Name string `json:"name"`
	// Type is derived from Condition by OPNsense (see TestTypes)
	Type string `json:"type"`
	// Condition is the Monit condition like "cpu usage is greater than 75%"
	Condition string `json:"condition"`
	Action    string `json:"action"` // see TestActions
	// Path is the program run by the exec action
	Path string `json:"path"`
}

// TestFields are the fields to send on create / update, nil fields are not sent
type TestFields struct {
	Name      *string `json:"name,omitempty"`
	Type      *string `json:"type,omitempty"`
	Condition *string `json:"condition,omitempty"`
	Action    *string `json:"action,omitempty"`
	Path      *string `json:"path,omitempty"`
}

func testUuid(test Test) string { return test.Uuid }

// TestSearch returns the tests where any column contains searchPhrase ("" for all) sorted by name, and the rows as
// the API returned them
func (opn *MonitApi) TestSearch(searchPhrase string) ([]Test, []json.RawMessage, error) {
	return searchRecords[Test](opn, testKind, searchPhrase)
}

// TestGet returns the test with this uuid or a *NotFoundError
func (opn *MonitApi) TestGet(uuid string) (Test, error) {
	return getRecord(opn, testKind, uuid, testUuid)
}

// TestCreate adds a test and returns its uuid
func (opn *MonitApi) TestCreate(fields TestFields) (string, error) {
	return opn.createRecord(testKind, fields)
}

// TestUpdate changes the non nil fields of the test, it returns a *NotFoundError for unknown uuids. The type of a
// test used by a service can not change (also not through the condition)
func (opn *MonitApi) TestUpdate(uuid string, fields TestFields) error {
	if fields == (TestFields{}) {
		return errNoChanges
	}
	if _, err := opn.TestGet(uuid); err != nil {
		return err
	}
	return opn.updateRecord(testKind, uuid, fields)
}

// TestRemove deletes the test. A test used by a service is refused (OPNsense would delete it and leave a dangling
// reference that makes the service unchangeable)
func (opn *MonitApi) TestRemove(uuid string) error {
	if err := validateUuid(testKind.what, uuid); err != nil {
		return err
	}
	var services, _, err = opn.ServiceSearch("")
	if err != nil {
		return err
	}
	var users []string
	for _, service := range services {
		if containsUuid(service.Tests, uuid) {
			users = append(users, service.Name)
		}
	}
	if len(users) > 0 {
		return fmt.Errorf("test %s is in use by the services %s", uuid, strings.Join(users, ", "))
	}
	return opn.removeRecord(testKind, uuid)
}
