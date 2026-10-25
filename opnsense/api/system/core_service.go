package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// System > Diagnostics > Services (/ui/core/service) is backed by api/core/service (OPNsense\Core\Api\
// ServiceController): search lists every service configd knows with its state, start/stop/restart act on one.
//
// 26.7 quirks: search ignores ?searchPhrase= on GET (filter client side); start/stop/restart answer {"result":"ok"}
// for any name, also unknown ones (they run "configctl service <action> <name> <id>" and ignore its outcome), and
// {"result":"failed"} unless POSTed. Resolve the service from the list before acting on it.

// CoreService is one service of System > Diagnostics > Services
type CoreService struct {
	// Id identifies the service for start/stop/restart: the name, or "name/instance" for services running
	// several instances (e.g. "openvpn/1")
	Id          string
	Name        string
	Description string
	Running     bool
	// Locked services (configd, webgui, pf, routing ...) are always needed: the web UI only offers restart for them
	Locked bool
}

func (s *CoreService) UnmarshalJSON(data []byte) error {
	var raw struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Running     any    `json:"running"`
		Locked      any    `json:"locked"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = CoreService{Id: raw.Id, Name: raw.Name, Description: raw.Description,
		Running: coreServiceFlag(raw.Running), Locked: coreServiceFlag(raw.Locked)}
	if s.Id == "" {
		s.Id = s.Name
	}
	return nil
}

// coreServiceFlag reads a 0/1 flag OPNsense sends as number, string or bool
func coreServiceFlag(value any) bool {
	var text = fmt.Sprint(value)
	return text == "1" || text == "true"
}

func (opn *SystemApi) coreServiceEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("core", "service", method)
}

// CoreServiceListRaw returns all services in API order (sorted by name) with the raw API objects
func (opn *SystemApi) CoreServiceListRaw() ([]CoreService, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.coreServiceEndpoint("search"), "")
	if err != nil {
		return nil, nil, err
	}
	var services = make([]CoreService, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &services[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected service from OPNsense: %w", err)
		}
	}
	return services, rows, nil
}

// CoreServiceList returns all services in API order (sorted by name)
func (opn *SystemApi) CoreServiceList() ([]CoreService, error) {
	var services, _, err = opn.CoreServiceListRaw()
	return services, err
}

// CoreServiceGet returns the service with this id (name or name/instance) or a *NotFoundError
func (opn *SystemApi) CoreServiceGet(id string) (CoreService, error) {
	var services, err = opn.CoreServiceList()
	if err != nil {
		return CoreService{}, err
	}
	for _, service := range services {
		if service.Id == id {
			return service, nil
		}
	}
	return CoreService{}, &coreapi.NotFoundError{Name: fmt.Sprintf("service %q", id)}
}

// CoreServiceStart starts the service with this id (see CoreService.Id). OPNsense does not check the id, so
// callers resolve it from CoreServiceList first
func (opn *SystemApi) CoreServiceStart(id string) error {
	return opn.coreServiceAction("start", id)
}

// CoreServiceStop stops the service with this id
func (opn *SystemApi) CoreServiceStop(id string) error {
	return opn.coreServiceAction("stop", id)
}

// CoreServiceRestart restarts the service with this id
func (opn *SystemApi) CoreServiceRestart(id string) error {
	return opn.coreServiceAction("restart", id)
}

func (opn *SystemApi) coreServiceAction(action string, id string) error {
	var path, err = coreServicePath(id)
	if err != nil {
		return err
	}
	var container struct {
		Result string `json:"result"`
	}
	if err := opn.DoJSON("POST", opn.coreServiceEndpoint(action)+"/"+path, nil, &container); err != nil {
		return err
	}
	if container.Result != "ok" {
		return fmt.Errorf("service %s %s was not accepted: result %q", action, id, container.Result)
	}
	return nil
}

// coreServicePath turns "name" or "name/instance" into escaped path segments
func coreServicePath(id string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", errors.New("cannot act on a service without id")
	}
	var parts = strings.Split(id, "/")
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid service id %q: name or name/instance", id)
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid service id %q: name or name/instance", id)
		}
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/"), nil
}
