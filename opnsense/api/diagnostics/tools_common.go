package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	coreapi "opnsense-cli/opnsense/api"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Helpers shared by the interactive diagnostics of Interfaces > Diagnostics (ping, traceroute, port probe, DNS lookup,
// packet capture). Their models live in memory only (<mount>:memory:</mount>): "set" validates the settings and
// either runs the tool right away (traceroute, portprobe, dns_diagnostics: the output is in "response") or stores
// a job file under /tmp and answers its id (ping, packet_capture: start/stop/remove/search_jobs manage the job).
// Unlike the config models, set answers {"result":"ok"} on success, not "saved"

// ToolsText is a value OPNsense sends as string, number, bool or null (the netstat/ifconfig JSON is not typed
// consistently), kept as text. null and missing are ""
type ToolsText string

func (t *ToolsText) UnmarshalJSON(data []byte) error {
	var trimmed = bytes.TrimSpace(data)
	switch {
	case len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")):
		*t = ""
	case trimmed[0] == '"':
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return err
		}
		*t = ToolsText(text)
	case trimmed[0] == '[':
		// PHP's array_merge_recursive turns a value present twice into a list: keep the distinct values
		var values []ToolsText
		if err := json.Unmarshal(trimmed, &values); err != nil {
			return err
		}
		var distinct []string
		for _, value := range values {
			if value != "" && !slices.Contains(distinct, string(value)) {
				distinct = append(distinct, string(value))
			}
		}
		*t = ToolsText(strings.Join(distinct, ","))
	case trimmed[0] == '{':
		*t = ToolsText(trimmed)
	default:
		*t = ToolsText(trimmed) // number or bool as written
	}
	return nil
}

// ToolsCount is a counter OPNsense sends as number or numeric string ("" and null are 0)
type ToolsCount int64

func (c *ToolsCount) UnmarshalJSON(data []byte) error {
	var text = strings.Trim(string(bytes.TrimSpace(data)), `"`)
	if text == "" || text == "null" {
		*c = 0
		return nil
	}
	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		*c = ToolsCount(value)
		return nil
	}
	var value, err = strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("invalid counter %s", data)
	}
	*c = ToolsCount(value)
	return nil
}

// toolsSetResult is the answer of the set endpoint of a diagnostics tool
type toolsSetResult struct {
	Result      string                     `json:"result"`
	Uuid        string                     `json:"uuid"`
	Validations coreapi.ValidationMessages `json:"validations"`
	Response    json.RawMessage            `json:"response"`
}

// toolsSet posts {"<model>":{"settings":settings}} to api/diagnostics/<controller>/set. "failed" is returned as
// *coreapi.ValidationError
func (opn *DiagnosticsApi) toolsSet(controller string, model string, settings map[string]string) (toolsSetResult, error) {
	var result toolsSetResult
	var body = map[string]any{model: map[string]any{"settings": settings}}
	if err := opn.DoJSON("POST", opn.endpoint(controller, "set"), body, &result); err != nil {
		return result, err
	}
	switch result.Result {
	case "ok":
		return result, nil
	case "failed":
		return result, &coreapi.ValidationError{Validations: result.Validations}
	default:
		return result, fmt.Errorf("unexpected result from %s set: %q", controller, result.Result)
	}
}

// toolsJobIdPattern are the ids OPNsense generates for ping and capture jobs (uuids). Anything else is refused
// before it is put into a URL
var toolsJobIdPattern = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)

func toolsCheckJobId(what string, id string) error {
	if !toolsJobIdPattern.MatchString(id) {
		return fmt.Errorf("invalid %s job id %q", what, id)
	}
	return nil
}

// toolsJobAnswer is the answer of start/stop/remove of a ping or capture job
type toolsJobAnswer struct {
	Status           string `json:"status"`
	StatusMessage    string `json:"status_msg"`
	StartedProcesses int    `json:"started_processes"`
	StoppedProcesses int    `json:"stopped_processes"`
}

// toolsJobAction POSTs {} to api/diagnostics/<controller>/<action>/<id>. OPNsense answers a bare
// {"status":"failed"} for unknown jobs (returned as *coreapi.NotFoundError) and adds status_msg for other failures
// (e.g. "already active")
func (opn *DiagnosticsApi) toolsJobAction(what string, controller string, action string, id string) (toolsJobAnswer, error) {
	var answer toolsJobAnswer
	if err := toolsCheckJobId(what, id); err != nil {
		return answer, err
	}
	if err := opn.DoJSON("POST", opn.endpoint(controller, action+"/"+id), map[string]any{}, &answer); err != nil {
		return answer, err
	}
	switch {
	case answer.Status == "ok":
		return answer, nil
	case answer.Status == "failed" && answer.StatusMessage == "":
		return answer, &coreapi.NotFoundError{Name: fmt.Sprintf("%s job %s", what, id)}
	case answer.StatusMessage != "":
		return answer, fmt.Errorf("%s %s of job %s failed: %s", what, action, id, answer.StatusMessage)
	default:
		return answer, fmt.Errorf("unexpected answer to %s %s of job %s: status %q", what, action, id, answer.Status)
	}
}

// toolsSearchRaw reads all rows of a search endpoint as raw JSON objects
func (opn *DiagnosticsApi) toolsSearchRaw(controller string, method string) ([]json.RawMessage, error) {
	return coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint(controller, method), "")
}

// toolsDecodeRows decodes raw rows into T, keeping the raw row via setRaw
func toolsDecodeRows[T any](what string, rows []json.RawMessage, setRaw func(*T, json.RawMessage)) ([]T, error) {
	var result = make([]T, 0, len(rows))
	for _, row := range rows {
		var item T
		if err := json.Unmarshal(row, &item); err != nil {
			return nil, fmt.Errorf("unexpected %s row %s: %w", what, row, err)
		}
		setRaw(&item, row)
		result = append(result, item)
	}
	return result, nil
}

// toolsDoRaw sends a request and returns the raw answer body; non 200 answers are *coreapi.HttpError
func (opn *DiagnosticsApi) toolsDoRaw(method string, endpoint string, jsonBody string) (*http.Response, []byte, error) {
	var body io.Reader
	if jsonBody != "" {
		body = strings.NewReader(jsonBody)
	}
	var request, err = http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, nil, err
	}
	if jsonBody != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := opn.Send(request)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode != http.StatusOK {
		var container struct {
			Message      string `json:"message"`
			ErrorMessage string `json:"errorMessage"`
		}
		var message = strings.TrimSpace(string(content))
		if json.Unmarshal(content, &container) == nil {
			if container.Message != "" {
				message = container.Message
			} else if container.ErrorMessage != "" {
				message = container.ErrorMessage
			}
		}
		return nil, nil, &coreapi.HttpError{StatusCode: response.StatusCode, Message: message}
	}
	return response, content, nil
}

// toolsFlag renders a bool as the "1"/"0" of the models
func toolsFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// toolsOption is one entry of an option list of a get answer ({"key":{"value":"label","selected":0}})
type toolsOption struct {
	Value    string `json:"value"`
	Selected int    `json:"selected"`
}
