package monit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ServiceTypes are the service types (what a service checks) in GUI order
var ServiceTypes = []string{"process", "file", "fifo", "filesystem", "directory", "host", "system", "custom", "network"}

// ServiceTestTypes are the test types a service of each type accepts (Monit.php)
var ServiceTestTypes = map[string][]string{
	"process":    {"Existence", "ProcessResource", "ProcessDiskIO", "UID", "GID", "PID", "PPID", "Uptime", "Connection", "Custom"},
	"file":       {"Existence", "FileChecksum", "Timestamp", "FileSize", "FileContent", "Permisssion", "UID", "GID", "Custom"},
	"fifo":       {"Existence", "Timestamp", "Permisssion", "UID", "GID", "Custom"},
	"filesystem": {"Existence", "FilesystemMountFlags", "SpaceUsage", "InodeUsage", "DiskIO", "Permisssion", "Custom"},
	"directory":  {"Existence", "Timestamp", "Permisssion", "UID", "GID", "Custom"},
	"host":       {"NetworkPing", "Connection", "Custom"},
	"system":     {"SystemResource", "Uptime", "Custom"},
	"custom":     {"ProgramStatus", "Custom"},
	"network":    {"NetworkInterface", "Custom"},
}

// Service is a monitored service of Services > Monit > Settings > Service Settings
type Service struct {
	Uuid    string `json:"uuid"`
	Enabled string `json:"enabled"` // "1" or "0"
	// Name is unique, letters, digits and . _ - $ ($HOST is the firewall itself)
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // see ServiceTypes
	// Pidfile or Match identify a process
	Pidfile string `json:"pidfile"`
	Match   string `json:"match"`
	// Path of a file, fifo, filesystem, directory or the script of a custom service
	Path         string `json:"path"`
	Timeout      string `json:"timeout"`      // program timeout in seconds
	StartTimeout string `json:"starttimeout"` // seconds to wait after a start
	// Address of a host or network service, Interface of a network service
	Address   string `json:"address"`
	Interface string `json:"interface"`
	// Start and Stop are the commands (absolute path with arguments) Monit uses to start / stop the service
	Start string `json:"start"`
	Stop  string `json:"stop"`
	// Tests and Depends are comma separated uuids of tests and services, TestNames the names of the tests
	Tests     string `json:"tests"`
	TestNames string `json:"%tests"`
	Depends   string `json:"depends"`
	// Polltime is a cron like schedule or "every n cycles", "" for every cycle
	Polltime string `json:"polltime"`
}

// ServiceFields are the fields to send on create / update, nil fields are not sent: create uses the OPNsense
// defaults for them, update keeps them
type ServiceFields struct {
	Enabled      *string `json:"enabled,omitempty"`
	Name         *string `json:"name,omitempty"`
	Description  *string `json:"description,omitempty"`
	Type         *string `json:"type,omitempty"`
	Pidfile      *string `json:"pidfile,omitempty"`
	Match        *string `json:"match,omitempty"`
	Path         *string `json:"path,omitempty"`
	Timeout      *string `json:"timeout,omitempty"`
	StartTimeout *string `json:"starttimeout,omitempty"`
	Address      *string `json:"address,omitempty"`
	Interface    *string `json:"interface,omitempty"`
	Start        *string `json:"start,omitempty"`
	Stop         *string `json:"stop,omitempty"`
	Tests        *string `json:"tests,omitempty"`
	Depends      *string `json:"depends,omitempty"`
	Polltime     *string `json:"polltime,omitempty"`
}

func serviceUuid(service Service) string { return service.Uuid }

// ServiceSearch returns the services where any column contains searchPhrase ("" for all) sorted by name, and the
// rows as the API returned them
func (opn *MonitApi) ServiceSearch(searchPhrase string) ([]Service, []json.RawMessage, error) {
	return searchRecords[Service](opn, serviceKind, searchPhrase)
}

// ServiceGet returns the service with this uuid or a *NotFoundError
func (opn *MonitApi) ServiceGet(uuid string) (Service, error) {
	return getRecord(opn, serviceKind, uuid, serviceUuid)
}

// ServiceInterfaces returns the interfaces a network service can watch (key → description)
func (opn *MonitApi) ServiceInterfaces() ([]SettingsOption, error) {
	var answer struct {
		Service map[string]json.RawMessage `json:"service"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get_service"), nil, &answer); err != nil {
		return nil, err
	}
	var choices, _ = optionChoices(answer.Service["interface"])
	var interfaces []SettingsOption
	for _, choice := range choices {
		if choice.Key != "" {
			interfaces = append(interfaces, choice)
		}
	}
	return interfaces, nil
}

// ServiceCreate adds a service and returns its uuid
func (opn *MonitApi) ServiceCreate(fields ServiceFields) (string, error) {
	return opn.createRecord(serviceKind, fields)
}

// ServiceUpdate changes the non nil fields of the service, it returns a *NotFoundError for unknown uuids
func (opn *MonitApi) ServiceUpdate(uuid string, fields ServiceFields) error {
	if fields == (ServiceFields{}) {
		return errNoChanges
	}
	if _, err := opn.ServiceGet(uuid); err != nil {
		return err
	}
	return opn.updateRecord(serviceKind, uuid, fields)
}

// ServiceRemove deletes the service. A service other services depend on is refused (OPNsense would leave a dangling
// reference that makes the dependent services unchangeable)
func (opn *MonitApi) ServiceRemove(uuid string) error {
	if err := validateUuid(serviceKind.what, uuid); err != nil {
		return err
	}
	var services, _, err = opn.ServiceSearch("")
	if err != nil {
		return err
	}
	var users []string
	for _, service := range services {
		if service.Uuid != uuid && containsUuid(service.Depends, uuid) {
			users = append(users, service.Name)
		}
	}
	if len(users) > 0 {
		return fmt.Errorf("service %s is in use: %s depend on it", uuid, strings.Join(users, ", "))
	}
	return opn.removeRecord(serviceKind, uuid)
}
