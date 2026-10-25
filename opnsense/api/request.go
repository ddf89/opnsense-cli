package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ValidationError is returned when OPNsense rejects a model change, e.g.
// {"result":"failed","validations":{"host.ip":"Please specify a valid ..."}}
type ValidationError struct {
	Validations map[string]string
}

func (e *ValidationError) Error() string {
	if len(e.Validations) == 0 {
		return "validation failed"
	}
	var fields = make([]string, 0, len(e.Validations))
	for field := range e.Validations {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	var messages = make([]string, 0, len(fields))
	for _, field := range fields {
		messages = append(messages, fmt.Sprintf("%s: %s", field, e.Validations[field]))
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(messages, "; "))
}

// HttpError is returned for any non 200 response, e.g. {"status":401,"message":"Authentication Failed"}
type HttpError struct {
	StatusCode int
	Message    string
}

func (e *HttpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// MutationResult is the answer of the add*/set*/del* endpoints of the OPNsense MVC models
type MutationResult struct {
	Result      string             `json:"result"`
	Uuid        string             `json:"uuid"`
	Validations ValidationMessages `json:"validations"`
}

// ValidationMessages maps a field like "host.ip" to its message(s). OPNsense sends a message either as a string
// or as a list of strings (e.g. {"host.ttl":["Invalid integer value."]}), multiple messages are joined by "; "
type ValidationMessages map[string]string

func (v *ValidationMessages) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*v = make(ValidationMessages, len(raw))
	for field, value := range raw {
		var message string
		if err := json.Unmarshal(value, &message); err == nil {
			(*v)[field] = message
			continue
		}
		var messages []string
		if err := json.Unmarshal(value, &messages); err != nil {
			return fmt.Errorf("unexpected validation message for %s: %s", field, value)
		}
		(*v)[field] = strings.Join(messages, "; ")
	}
	return nil
}

// DoJSON sends a request to endpoint (encoding body as JSON when not nil) and decodes the JSON answer into out (when not nil).
// Non 200 answers are returned as *HttpError
func (opn *OPNsense) DoJSON(method string, endpoint string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		var jsonBody = new(bytes.Buffer)
		if err := json.NewEncoder(jsonBody).Encode(body); err != nil {
			return err
		}
		reqBody = jsonBody
	}

	request, reqCreationErr := http.NewRequest(method, endpoint, reqBody)
	if reqCreationErr != nil {
		return reqCreationErr
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, reqErr := opn.Send(request)
	if reqErr != nil {
		return reqErr
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return readErr
	}

	if response.StatusCode != http.StatusOK {
		// e.g. {"status":401,"message":"Authentication Failed"} or {"errorMessage":"Endpoint not found"}
		var container struct {
			Message      string `json:"message"`
			ErrorMessage string `json:"errorMessage"`
		}
		var message = strings.TrimSpace(string(responseBody))
		if err := json.Unmarshal(responseBody, &container); err == nil {
			if container.Message != "" {
				message = container.Message
			} else if container.ErrorMessage != "" {
				message = container.ErrorMessage
			}
		}
		return &HttpError{StatusCode: response.StatusCode, Message: message}
	}

	if out == nil {
		return nil
	}
	// OPNsense answers unknown methods of existing controllers with an empty 200
	if len(bytes.TrimSpace(responseBody)) == 0 {
		return fmt.Errorf("empty response from %s %s (unsupported endpoint or OPNsense version?)", method, endpoint)
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return fmt.Errorf("could not decode response from %s: %w", endpoint, err)
	}
	return nil
}

// Mutate POSTs body to an add*/set*/del* endpoint and returns the uuid OPNsense answered with (only set by add*).
// A "failed" result is returned as *ValidationError, "not found" as *NotFoundError
func (opn *OPNsense) Mutate(endpoint string, body any) (string, error) {
	var result MutationResult
	if err := opn.DoJSON("POST", endpoint, body, &result); err != nil {
		return "", err
	}

	switch result.Result {
	case "saved", "deleted":
		return result.Uuid, nil
	case "not found":
		return "", &NotFoundError{Name: endpoint}
	case "failed":
		return "", &ValidationError{Validations: result.Validations}
	default:
		return "", fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// Search queries a search* endpoint and returns all rows. OPNsense returns every row when no rowCount is given.
// searchPhrase is a substring match over all columns, use "" to list everything
func Search[T any](opn *OPNsense, endpoint string, searchPhrase string) ([]T, error) {
	var reqUrl = endpoint
	if searchPhrase != "" {
		reqUrl = fmt.Sprintf("%s?%s", endpoint, url.Values{"searchPhrase": {searchPhrase}}.Encode())
	}

	var container struct {
		Rows []T `json:"rows"`
	}
	if err := opn.DoJSON("GET", reqUrl, nil, &container); err != nil {
		return nil, err
	}
	return container.Rows, nil
}

func IsNotFound(err error) bool {
	var notFound *NotFoundError
	return errors.As(err, &notFound)
}

func Filter[T any](vs []T, f func(T) bool) []T {
	filtered := make([]T, 0)
	for _, v := range vs {
		if f(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
