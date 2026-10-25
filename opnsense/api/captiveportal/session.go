package captiveportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Session is a logged in client of a zone (Services > Captive Portal > Sessions, api/captiveportal/session/search)
type Session struct {
	ZoneId           Value `json:"zoneid"`
	SessionId        Value `json:"sessionId"`
	AuthenticatedVia Value `json:"authenticated_via"`
	UserName         Value `json:"userName"`
	// StartTime and LastAccessed are unix times (with fractions)
	StartTime    Value   `json:"startTime"`
	LastAccessed Value   `json:"last_accessed"`
	IpAddress    Value   `json:"ipAddress"`
	IpAddresses  []Value `json:"ipAddresses"`
	MacAddress   Value   `json:"macAddress"`
	PacketsIn    Value   `json:"packets_in"`
	PacketsOut   Value   `json:"packets_out"`
	BytesIn      Value   `json:"bytes_in"`
	BytesOut     Value   `json:"bytes_out"`
	// AccSessionTimeout is the session timeout set by the authentication server (seconds), "" for none
	AccSessionTimeout Value `json:"acc_session_timeout"`
	// Raw is the row as the API returned it
	Raw json.RawMessage `json:"-"`
}

// SessionList returns the sessions of the given zones (zone ids), all sessions without zone ids; searchPhrase is
// a substring match over all columns ("" for all)
func (opn *CaptivePortalApi) SessionList(searchPhrase string, zoneIds ...string) ([]Session, error) {
	var query = url.Values{}
	for _, zoneId := range zoneIds {
		query.Add("selected_zones[]", zoneId)
	}
	if searchPhrase != "" {
		query.Set("searchPhrase", searchPhrase)
	}
	var endpoint = opn.endpoint("session", "search")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var answer struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	var sessions = make([]Session, len(answer.Rows))
	for i, row := range answer.Rows {
		if err := json.Unmarshal(row, &sessions[i]); err != nil {
			return nil, fmt.Errorf("unexpected captive portal session from OPNsense: %w", err)
		}
		sessions[i].Raw = row
	}
	return sessions, nil
}

// ZoneDescriptions returns the description of every zone by zone id (session/zones). PHP sends the map as a JSON
// list when the zone ids are 0..n
func (opn *CaptivePortalApi) ZoneDescriptions() (map[string]string, error) {
	var answer json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("session", "zones"), nil, &answer); err != nil {
		return nil, err
	}
	var descriptions = map[string]string{}
	if trimmed := bytes.TrimSpace(answer); len(trimmed) > 0 && trimmed[0] == '[' {
		var list []string
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("unexpected answer from session/zones: %w", err)
		}
		for i, description := range list {
			descriptions[strconv.Itoa(i)] = description
		}
		return descriptions, nil
	}
	if err := json.Unmarshal(answer, &descriptions); err != nil {
		return nil, fmt.Errorf("unexpected answer from session/zones: %w", err)
	}
	return descriptions, nil
}

// DisconnectedSession is what OPNsense answers for a disconnected session (the client record before removal)
type DisconnectedSession struct {
	ZoneId         Value `json:"zoneid"`
	SessionId      Value `json:"sessionid"`
	Username       Value `json:"username"`
	IpAddress      Value `json:"ip_address"`
	MacAddress     Value `json:"mac_address"`
	TerminateCause Value `json:"terminateCause"`
}

// ErrSessionNotFound is returned by SessionDisconnect for an unknown session id
var ErrSessionNotFound = errors.New("no such session")

// SessionDisconnect logs the session with this id off (session/disconnect, cause Admin-Reset): the client has to
// log in again. Returns ErrSessionNotFound for an unknown session
func (opn *CaptivePortalApi) SessionDisconnect(sessionId string) (DisconnectedSession, error) {
	if sessionId == "" {
		return DisconnectedSession{}, errors.New("session id must not be empty")
	}
	var answer struct {
		DisconnectedSession
		Status Value `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("session", "disconnect"), map[string]string{"sessionId": sessionId}, &answer); err != nil {
		return DisconnectedSession{}, err
	}
	switch {
	case answer.Status != "":
		return DisconnectedSession{}, fmt.Errorf("OPNsense could not disconnect the session: %s", answer.Status)
	case answer.TerminateCause == "UNKNOWN" || answer.TerminateCause == "":
		return DisconnectedSession{}, fmt.Errorf("session %s: %w", sessionId, ErrSessionNotFound)
	}
	return answer.DisconnectedSession, nil
}
