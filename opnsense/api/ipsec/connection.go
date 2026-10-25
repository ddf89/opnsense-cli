package ipsec

import (
	"fmt"
	"net/url"
	"strings"
)

// Connections of VPN > IPsec > Connections (api/ipsec/connections): a connection (IKE SA settings) with its
// local and remote authentication rounds and its children (CHILD SAs). Locals, remotes and children refer to
// their connection by its uuid in the field "connection".
//
// Field values: flags "0"/"1"; version "0" (IKEv1+IKEv2), "1" (IKEv1) or "2" (IKEv2); lists comma separated;
// proposals / esp_proposals are proposal keys like "aes256gcm16-sha256-x25519" ("default" for the strongSwan
// defaults); pools are pool uuids (or "radius"); certs / cacerts trust store refids; pubkeys key pair uuids;
// groups local group gids

var (
	// ConnectionFieldNames are the writable fields of a connection
	ConnectionFieldNames = []string{"enabled", "proposals", "unique", "aggressive", "version", "mobike", "local_addrs",
		"local_port", "remote_addrs", "remote_port", "encap", "reauth_time", "rekey_time", "over_time", "dpd_delay",
		"dpd_timeout", "pools", "send_certreq", "send_cert", "keyingtries", "description"}
	// LocalFieldNames are the writable fields of a local authentication round
	LocalFieldNames = []string{"enabled", "connection", "round", "auth", "id", "eap_id", "certs", "pubkeys", "description"}
	// RemoteFieldNames are the writable fields of a remote authentication round
	RemoteFieldNames = []string{"enabled", "connection", "round", "auth", "id", "eap_id", "groups", "certs", "cacerts",
		"pubkeys", "description"}
	// ChildFieldNames are the writable fields of a child
	ChildFieldNames = []string{"enabled", "connection", "reqid", "esp_proposals", "sha256_96", "start_action",
		"close_action", "dpd_action", "mode", "policies", "local_ts", "remote_ts", "rekey_time", "replay_window",
		"description"}
)

var (
	connectionResource = resource{controller: "connections", search: "search_connection", get: "get_connection",
		add: "add_connection", set: "set_connection", del: "del_connection", toggle: "toggle_connection",
		container: "connection", noun: "ipsec connection", fields: ConnectionFieldNames}
	localResource = resource{controller: "connections", search: "search_local", get: "get_local", add: "add_local",
		set: "set_local", del: "del_local", toggle: "toggle_local", container: "local", noun: "ipsec local authentication",
		fields: LocalFieldNames}
	remoteResource = resource{controller: "connections", search: "search_remote", get: "get_remote", add: "add_remote",
		set: "set_remote", del: "del_remote", toggle: "toggle_remote", container: "remote", noun: "ipsec remote authentication",
		fields: RemoteFieldNames}
	childResource = resource{controller: "connections", search: "search_child", get: "get_child", add: "add_child",
		set: "set_child", del: "del_child", toggle: "toggle_child", container: "child", noun: "ipsec child",
		fields: ChildFieldNames}
)

// --- connections

// ConnectionList returns the connections, searchPhrase is a substring match over all columns ("" for all)
func (opn *IPsecApi) ConnectionList(searchPhrase string) ([]Record, error) {
	return opn.list(connectionResource, searchPhrase, nil)
}

// ConnectionGet returns the connection with this uuid or a *NotFoundError
func (opn *IPsecApi) ConnectionGet(uuid string) (Record, error) {
	return opn.getRecord(connectionResource, uuid)
}

// ConnectionGetByDescription returns the only connection with this description (case-insensitive), a
// *NotFoundError or a *TooManyFoundError naming the uuids
func (opn *IPsecApi) ConnectionGetByDescription(description string) (Record, error) {
	return opn.oneByName(connectionResource, "description", "description", description)
}

// ConnectionForm returns the get answer with the defaults of a new connection: the option fields list every
// choice (proposals, pools by uuid with their names, ...). get_connection answers unknown uuids with a new
// default record too, so it is only offered for new connections
func (opn *IPsecApi) ConnectionForm() (Form, error) {
	return opn.form(connectionResource, "", nil)
}

// ConnectionCreate adds a connection and returns its uuid. The description is required, duplicates are not
// checked
func (opn *IPsecApi) ConnectionCreate(fields Fields) (string, error) {
	return opn.create(connectionResource, fields)
}

// ConnectionUpdate sends only the given fields to the connection with this uuid. Returns *NotFoundError when it
// does not exist (checked first, set_connection would create it)
func (opn *IPsecApi) ConnectionUpdate(uuid string, fields Fields) error {
	return opn.update(connectionResource, uuid, fields)
}

// ConnectionRemove deletes the connection with this uuid together with its locals, remotes and children
func (opn *IPsecApi) ConnectionRemove(uuid string) error {
	return opn.remove(connectionResource, uuid)
}

// ConnectionSetEnabled enables or disables a connection and returns whether its state changed
func (opn *IPsecApi) ConnectionSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(connectionResource, uuid, enabled)
}

// --- locals, remotes and children

func connectionQuery(connection string) url.Values {
	if connection == "" {
		return nil
	}
	return url.Values{"connection": {connection}}
}

// LocalList returns the local authentication rounds of the connection with this uuid ("" for all)
func (opn *IPsecApi) LocalList(connection string) ([]Record, error) {
	return opn.list(localResource, "", connectionQuery(connection))
}

// LocalGet returns the local authentication round with this uuid or a *NotFoundError
func (opn *IPsecApi) LocalGet(uuid string) (Record, error) {
	return opn.getRecord(localResource, uuid)
}

// LocalForm returns the get answer with the defaults of a new local round, the option fields list the
// connections, certificates and key pairs
func (opn *IPsecApi) LocalForm() (Form, error) {
	return opn.form(localResource, "", nil)
}

// LocalCreate adds a local authentication round (connection is required) and returns its uuid
func (opn *IPsecApi) LocalCreate(fields Fields) (string, error) {
	return opn.create(localResource, fields)
}

// LocalUpdate sends only the given fields to the local round with this uuid (*NotFoundError when it does not exist)
func (opn *IPsecApi) LocalUpdate(uuid string, fields Fields) error {
	return opn.update(localResource, uuid, fields)
}

// LocalRemove deletes the local authentication round with this uuid
func (opn *IPsecApi) LocalRemove(uuid string) error {
	return opn.remove(localResource, uuid)
}

// LocalSetEnabled enables or disables a local round and returns whether its state changed
func (opn *IPsecApi) LocalSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(localResource, uuid, enabled)
}

// RemoteList returns the remote authentication rounds of the connection with this uuid ("" for all)
func (opn *IPsecApi) RemoteList(connection string) ([]Record, error) {
	return opn.list(remoteResource, "", connectionQuery(connection))
}

// RemoteGet returns the remote authentication round with this uuid or a *NotFoundError
func (opn *IPsecApi) RemoteGet(uuid string) (Record, error) {
	return opn.getRecord(remoteResource, uuid)
}

// RemoteForm returns the get answer with the defaults of a new remote round, the option fields list the
// connections, groups, certificates, CAs and key pairs
func (opn *IPsecApi) RemoteForm() (Form, error) {
	return opn.form(remoteResource, "", nil)
}

// RemoteCreate adds a remote authentication round (connection is required) and returns its uuid
func (opn *IPsecApi) RemoteCreate(fields Fields) (string, error) {
	return opn.create(remoteResource, fields)
}

// RemoteUpdate sends only the given fields to the remote round with this uuid (*NotFoundError when it does not exist)
func (opn *IPsecApi) RemoteUpdate(uuid string, fields Fields) error {
	return opn.update(remoteResource, uuid, fields)
}

// RemoteRemove deletes the remote authentication round with this uuid
func (opn *IPsecApi) RemoteRemove(uuid string) error {
	return opn.remove(remoteResource, uuid)
}

// RemoteSetEnabled enables or disables a remote round and returns whether its state changed
func (opn *IPsecApi) RemoteSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(remoteResource, uuid, enabled)
}

// ChildList returns the children of the connection with this uuid ("" for all)
func (opn *IPsecApi) ChildList(connection string) ([]Record, error) {
	return opn.list(childResource, "", connectionQuery(connection))
}

// ChildGet returns the child with this uuid or a *NotFoundError
func (opn *IPsecApi) ChildGet(uuid string) (Record, error) {
	return opn.getRecord(childResource, uuid)
}

// ChildForm returns the get answer with the defaults of a new child, the option fields list the connections and
// the ESP proposals
func (opn *IPsecApi) ChildForm() (Form, error) {
	return opn.form(childResource, "", nil)
}

// ChildCreate adds a child (connection is required) and returns its uuid
func (opn *IPsecApi) ChildCreate(fields Fields) (string, error) {
	return opn.create(childResource, fields)
}

// ChildUpdate sends only the given fields to the child with this uuid (*NotFoundError when it does not exist)
func (opn *IPsecApi) ChildUpdate(uuid string, fields Fields) error {
	return opn.update(childResource, uuid, fields)
}

// ChildRemove deletes the child with this uuid. OPNsense does not check whether a manual SPD entry uses it
func (opn *IPsecApi) ChildRemove(uuid string) error {
	return opn.remove(childResource, uuid)
}

// ChildSetEnabled enables or disables a child and returns whether its state changed
func (opn *IPsecApi) ChildSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(childResource, uuid, enabled)
}

// ConnectionExists asks OPNsense whether a connection with this uuid exists (connections/connection_exists)
func (opn *IPsecApi) ConnectionExists(uuid string) (bool, error) {
	if uuid == "" || strings.ContainsAny(uuid, "/?#") {
		return false, fmt.Errorf("invalid connection uuid %q", uuid)
	}
	var answer struct {
		Exists bool `json:"exists"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("connections", "connection_exists")+"/"+uuid, nil, &answer); err != nil {
		return false, err
	}
	return answer.Exists, nil
}
