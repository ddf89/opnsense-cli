// Package monit wraps the Monit API of OPNsense 26.7 (Services > Monit, api/monit/settings, api/monit/service and
// api/monit/status): general settings, alert recipients, monitored services, service tests, the status report and
// the daemon.
//
// Behaviour of the API this package relies on (verified on 26.7):
//   - set_* on an unknown but well-formed uuid CREATES the record, get_* on an unknown uuid answers an empty default
//     record: updates check existence first
//   - del_test and del_service do not check whether a service still uses the test / depends on the service: the
//     reference stays and every later change of that service fails ("Related item not found."), the library refuses
//     to remove items in use
//   - the test type is derived by OPNsense from the condition, a test linked to a service can not change its type,
//     and a service only accepts tests of types allowed for its service type
//   - names (service, test) and the other StrictTextFields refuse spaces
//   - get_general returns the mail server and httpd passwords in clear text
package monit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// MonitApi wraps api/monit
//
//goland:noinspection GoNameStartsWithPackageName
type MonitApi struct {
	*coreapi.OPNsense
}

func (opn *MonitApi) endpoint(controller string, method string, params ...string) string {
	var endpoint = opn.EndpointForPluginControllerMethod("monit", controller, method)
	for _, param := range params {
		endpoint += "/" + param
	}
	return endpoint
}

// errNoChanges is returned by updates without any field to change
var errNoChanges = errors.New("nothing to change")

// validateUuid refuses empty uuids and lists
func validateUuid(what string, uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/ ") {
		return fmt.Errorf("invalid %s uuid %q", what, uuid)
	}
	return nil
}

// recordKind describes a list of api/monit/settings: the endpoints search_<method>, add_<method>, set_<method>,
// del_<method> and the container key of the bodies (the same as method)
type recordKind struct {
	what   string
	method string
}

var (
	serviceKind = recordKind{what: "service", method: "service"}
	testKind    = recordKind{what: "test", method: "test"}
	alertKind   = recordKind{what: "alert", method: "alert"}
)

func searchRecords[T any](opn *MonitApi, kind recordKind, searchPhrase string) ([]T, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("settings", "search_"+kind.method), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var records = make([]T, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &records[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected %s from OPNsense: %w", kind.what, err)
		}
	}
	return records, rows, nil
}

// getRecord finds the record with this uuid in the search results (get_<method> answers unknown uuids with a default
// record)
func getRecord[T any](opn *MonitApi, kind recordKind, uuid string, uuidOf func(T) string) (T, error) {
	var zero T
	if err := validateUuid(kind.what, uuid); err != nil {
		return zero, err
	}
	var records, _, err = searchRecords[T](opn, kind, "")
	if err != nil {
		return zero, err
	}
	for _, record := range records {
		if uuidOf(record) == uuid {
			return record, nil
		}
	}
	return zero, &coreapi.NotFoundError{Name: kind.what + " " + uuid}
}

func (opn *MonitApi) createRecord(kind recordKind, fields any) (string, error) {
	return opn.Mutate(opn.endpoint("settings", "add_"+kind.method), map[string]any{kind.method: fields})
}

// updateRecord sends set_<method>/<uuid>, existence must have been checked: set on an unknown uuid creates the record
func (opn *MonitApi) updateRecord(kind recordKind, uuid string, fields any) error {
	_, err := opn.Mutate(opn.endpoint("settings", "set_"+kind.method, uuid), map[string]any{kind.method: fields})
	return err
}

func (opn *MonitApi) removeRecord(kind recordKind, uuid string) error {
	if err := validateUuid(kind.what, uuid); err != nil {
		return err
	}
	if _, err := opn.Mutate(opn.endpoint("settings", "del_"+kind.method, uuid), nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: kind.what + " " + uuid, Err: err}
		}
		return err
	}
	return nil
}

// containsUuid tells whether the comma separated list contains uuid
func containsUuid(list string, uuid string) bool {
	for _, element := range strings.Split(list, ",") {
		if strings.TrimSpace(element) == uuid {
			return true
		}
	}
	return false
}
