// Package ids wraps the Intrusion Detection (Suricata) API of OPNsense 26.7 (api/ids/settings and api/ids/service):
// general settings, rule sets, installed rules and their adjustments, policies, user defined rules, alerts and the
// service.
//
// Behaviour of the API this package relies on (verified on 26.7):
//   - set_policy / set_user_rule on an unknown but well-formed uuid CREATE the record, get_* on an unknown uuid
//     answers [] or an empty default record: updates check existence first
//   - toggle_* answer {"result":"Enabled"|"Disabled","changed":bool}; the library sets the state with set_* instead
//   - set_rule/<sid> needs an action in the body (without one it answers a bare "failed" and changes nothing), an
//     unknown sid also answers "failed"; with enabled in the body it saves the new state BEFORE validating the action
//   - toggle_rule/<sids>/<state> answers [] when no sid is known, toggle_ruleset {"status":"error"} when one file
//     name is unknown (the known ones are still changed and saved)
//   - search_installed_rules and query_alerts are POST only and answer every row for rowCount 0, the library never
//     sends 0
package ids

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// IdsApi wraps api/ids
//
//goland:noinspection GoNameStartsWithPackageName
type IdsApi struct {
	*coreapi.OPNsense
}

func (opn *IdsApi) endpoint(controller string, method string, params ...string) string {
	var endpoint = opn.EndpointForPluginControllerMethod("ids", controller, method)
	for _, param := range params {
		endpoint += "/" + param
	}
	return endpoint
}

// flag renders a bool as the "1"/"0" of the API
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// postNoTimeout POSTs a JSON body like DoJSON, but without the client timeout (cancel ctx to stop). For actions
// that can run for minutes, like the rule download
func (opn *IdsApi) postNoTimeout(ctx context.Context, endpoint string, body any, out any) error {
	var encoded, err = json.Marshal(body)
	if err != nil {
		return err
	}
	var request, reqErr = http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if reqErr != nil {
		return reqErr
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	var response, sendErr = opn.SendStream(request)
	if sendErr != nil {
		return sendErr
	}
	defer func() { _ = response.Body.Close() }()
	var answer, readErr = io.ReadAll(response.Body)
	if readErr != nil {
		return readErr
	}
	if response.StatusCode != http.StatusOK {
		var container struct {
			Message      string `json:"message"`
			ErrorMessage string `json:"errorMessage"`
		}
		var message = strings.TrimSpace(string(answer))
		if json.Unmarshal(answer, &container) == nil {
			message = firstNonEmpty(container.Message, container.ErrorMessage, message)
		}
		return &coreapi.HttpError{StatusCode: response.StatusCode, Message: message}
	}
	if len(bytes.TrimSpace(answer)) == 0 {
		return fmt.Errorf("empty response from POST %s (unsupported endpoint or OPNsense version?)", endpoint)
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("could not decode response from %s: %w", endpoint, err)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// isEmptyAnswer tells whether a get_* answer is the [] or {} OPNsense sends for unknown ids
func isEmptyAnswer(raw json.RawMessage) bool {
	var trimmed = string(bytes.TrimSpace(raw))
	return trimmed == "" || trimmed == "[]" || trimmed == "{}" || trimmed == "null"
}

// validateUuid refuses empty uuids and lists, which OPNsense would treat as several items
func validateUuid(what string, uuid string) error {
	if uuid == "" || strings.ContainsAny(uuid, ",/ ") {
		return fmt.Errorf("invalid %s uuid %q", what, uuid)
	}
	return nil
}

// notFound wraps a "not found" answer of a del_* endpoint with a readable name
func notFound(what string, uuid string, err error) error {
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: what + " " + uuid, Err: err}
	}
	return err
}

// errNoChanges is returned by updates without any field to change
var errNoChanges = errors.New("nothing to change")
