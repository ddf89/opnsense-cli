package monit

import (
	"encoding/json"
)

// AlertEvents are the events an alert recipient can be notified about
var AlertEvents = []string{"action", "checksum", "bytein", "byteout", "connection", "content", "data", "exec", "fsflags",
	"gid", "icmp", "instance", "invalid", "link", "nonexist", "packetin", "packetout", "permission", "pid", "ppid",
	"resource", "saturation", "size", "speed", "status", "timeout", "timestamp", "uid", "uptime"}

// Alert is an alert recipient of Services > Monit > Settings > Alert Settings
type Alert struct {
	Uuid      string `json:"uuid"`
	Enabled   string `json:"enabled"` // "1" or "0"
	Recipient string `json:"recipient"`
	// NotOn ("1") inverts Events: notify on all events except these
	NotOn string `json:"noton"`
	// Events are comma separated AlertEvents, "" for all
	Events string `json:"events"`
	// Format is the mail format like "subject: $SERVICE $EVENT", "" for the default
	Format string `json:"format"`
	// Reminder sends the alert again every n cycles while the error lasts, "" for never
	Reminder    string `json:"reminder"`
	Description string `json:"description"`
}

// AlertFields are the fields to send on create / update, nil fields are not sent
type AlertFields struct {
	Enabled     *string `json:"enabled,omitempty"`
	Recipient   *string `json:"recipient,omitempty"`
	NotOn       *string `json:"noton,omitempty"`
	Events      *string `json:"events,omitempty"`
	Format      *string `json:"format,omitempty"`
	Reminder    *string `json:"reminder,omitempty"`
	Description *string `json:"description,omitempty"`
}

func alertUuid(alert Alert) string { return alert.Uuid }

// AlertSearch returns the alerts where any column contains searchPhrase ("" for all) sorted by description, and
// the rows as the API returned them
func (opn *MonitApi) AlertSearch(searchPhrase string) ([]Alert, []json.RawMessage, error) {
	return searchRecords[Alert](opn, alertKind, searchPhrase)
}

// AlertGet returns the alert with this uuid or a *NotFoundError
func (opn *MonitApi) AlertGet(uuid string) (Alert, error) {
	return getRecord(opn, alertKind, uuid, alertUuid)
}

// AlertCreate adds an alert recipient and returns its uuid
func (opn *MonitApi) AlertCreate(fields AlertFields) (string, error) {
	return opn.createRecord(alertKind, fields)
}

// AlertUpdate changes the non nil fields of the alert, it returns a *NotFoundError for unknown uuids
func (opn *MonitApi) AlertUpdate(uuid string, fields AlertFields) error {
	if fields == (AlertFields{}) {
		return errNoChanges
	}
	if _, err := opn.AlertGet(uuid); err != nil {
		return err
	}
	return opn.updateRecord(alertKind, uuid, fields)
}

// AlertRemove deletes the alert
func (opn *MonitApi) AlertRemove(uuid string) error {
	return opn.removeRecord(alertKind, uuid)
}
