package system

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BackupProviderLocal is the provider of the local configuration history (/conf/backup). Other providers only
// exist with OPNcentral (remote hosts); revert and delete only work on the local history
const BackupProviderLocal = "this"

// BackupCurrent can be used as backup id for the current configuration: OPNsense writes a history entry on every
// save, so the newest backup is the running config.xml
const BackupCurrent = "current"

// BackupProvider is a location holding configuration backups, see BackupProviders
type BackupProvider struct {
	Name        string `json:"-"`
	Description string `json:"description"`
	Dirname     string `json:"dirname"`
}

// Backup is an entry of System > Configuration > History, as returned by core/backup/backups/<provider>
type Backup struct {
	// Id is the file name, e.g. config-1792886029.2372.xml
	Id string `json:"id"`
	// Time is the revision time as unix epoch with 2 decimals, e.g. "1792886029.24"
	Time    string `json:"time"`
	TimeIso string `json:"time_iso"`
	// Description is the change which created this revision, e.g. "/api/cron/settings/set_job/<uuid> made changes"
	Description string `json:"description"`
	// Username is the user (and source address) who made the change, e.g. root@192.168.1.2
	Username string `json:"username"`
	Filesize int64  `json:"filesize"`
}

// Timestamp returns Time as time.Time, ok is false when it cannot be parsed
func (backup Backup) Timestamp() (timestamp time.Time, ok bool) {
	var epoch, err = strconv.ParseFloat(backup.Time, 64)
	if err != nil || epoch <= 0 {
		return time.Time{}, false
	}
	var seconds = int64(epoch)
	return time.Unix(seconds, int64((epoch-float64(seconds))*1e9)).Round(10 * time.Millisecond), true
}

func (opn *SystemApi) backupEndpoint(method string, args ...string) string {
	var endpoint = opn.EndpointForPluginControllerMethod("core", "backup", method)
	for _, arg := range args {
		endpoint += "/" + url.PathEscape(arg)
	}
	return endpoint
}

// BackupProviders lists the backup locations sorted by name, "this" is the local firewall
func (opn *SystemApi) BackupProviders() ([]BackupProvider, error) {
	var container struct {
		Items map[string]BackupProvider `json:"items"`
	}
	if err := opn.DoJSON("GET", opn.backupEndpoint("providers"), nil, &container); err != nil {
		return nil, err
	}

	var providers = make([]BackupProvider, 0, len(container.Items))
	for name, provider := range container.Items {
		provider.Name = name
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers, nil
}

// BackupList lists the configuration history of provider ("" for the local one), newest first.
// An unknown provider is returned as *NotFoundError (OPNsense itself answers it with an empty list)
func (opn *SystemApi) BackupList(provider string) ([]Backup, error) {
	if provider == "" {
		provider = BackupProviderLocal
	}
	var container struct {
		Items []Backup `json:"items"`
	}
	if err := opn.DoJSON("GET", opn.backupEndpoint("backups", provider), nil, &container); err != nil {
		return nil, err
	}
	if len(container.Items) == 0 {
		if err := opn.backupCheckProvider(provider); err != nil {
			return nil, err
		}
	}
	// OPNsense sorts by the 2 decimal time, the id has more precision
	sort.SliceStable(container.Items, func(i, j int) bool {
		return backupIdEpoch(container.Items[i]) > backupIdEpoch(container.Items[j])
	})
	return container.Items, nil
}

// backupIdEpoch returns the epoch of the id config-<epoch>.xml, falling back to Time
func backupIdEpoch(backup Backup) float64 {
	var epoch = strings.TrimSuffix(strings.TrimPrefix(backup.Id, "config-"), ".xml")
	if parsed, err := strconv.ParseFloat(epoch, 64); err == nil {
		return parsed
	}
	var parsed, _ = strconv.ParseFloat(backup.Time, 64)
	return parsed
}

func (opn *SystemApi) backupCheckProvider(provider string) error {
	var providers, err = opn.BackupProviders()
	if err != nil {
		return err
	}
	for _, known := range providers {
		if known.Name == provider {
			return nil
		}
	}
	return &coreapi.NotFoundError{Name: fmt.Sprintf("backup provider %s", provider)}
}

// backupResolve maps "" / BackupCurrent to the newest backup and checks the id exists
func backupResolve(backups []Backup, id string) (string, error) {
	if id == "" || id == BackupCurrent {
		if len(backups) == 0 {
			return "", &coreapi.NotFoundError{Name: "backup (history is empty)"}
		}
		return backups[0].Id, nil
	}
	for _, backup := range backups {
		if backup.Id == id {
			return id, nil
		}
	}
	return "", &coreapi.NotFoundError{Name: fmt.Sprintf("backup %s", id)}
}

// BackupDiff returns the unified diff (diff -u) between the backups from and to of provider ("" for local).
// from is required, to may be BackupCurrent (or "") for the newest backup. Both ids are checked against the history first since
// OPNsense answers unknown ids with an empty diff. An empty result means both backups are identical
func (opn *SystemApi) BackupDiff(provider string, from string, to string) ([]string, error) {
	if from == "" {
		return nil, fmt.Errorf("a backup id to compare from is required")
	}
	if provider == "" {
		provider = BackupProviderLocal
	}
	var backups, listErr = opn.BackupList(provider)
	if listErr != nil {
		return nil, listErr
	}
	var fromId, fromErr = backupResolve(backups, from)
	if fromErr != nil {
		return nil, fromErr
	}
	var toId, toErr = backupResolve(backups, to)
	if toErr != nil {
		return nil, toErr
	}
	if fromId == toId {
		// OPNsense would answer an empty diff as well
		return []string{}, nil
	}

	var container struct {
		Items []string `json:"items"`
	}
	// diff/<host>/<b1>/<b2> runs "diff -u b2 b1", so the target goes first
	if err := opn.DoJSON("GET", opn.backupEndpoint("diff", provider, toId, fromId), nil, &container); err != nil {
		return nil, err
	}
	// lines are html escaped for the GUI
	var lines = make([]string, 0, len(container.Items))
	for _, line := range container.Items {
		lines = append(lines, html.UnescapeString(line))
	}
	return lines, nil
}

// BackupDownload returns the config.xml of backup id of provider ("" for local) and the file name OPNsense suggests,
// e.g. config-OPNsense.internal-1792886037.3483.xml. id "" or BackupCurrent downloads the newest backup, which is
// the current configuration. The content contains secrets (password hashes, API keys, certificates)
func (opn *SystemApi) BackupDownload(provider string, id string) (content []byte, filename string, err error) {
	if provider == "" {
		provider = BackupProviderLocal
	}
	var endpoint = opn.backupEndpoint("download", provider)
	if id != "" && id != BackupCurrent {
		endpoint = opn.backupEndpoint("download", provider, id)
	}

	request, reqCreationErr := http.NewRequest("GET", endpoint, nil)
	if reqCreationErr != nil {
		return nil, "", reqCreationErr
	}
	response, reqErr := opn.Send(request)
	if reqErr != nil {
		return nil, "", reqErr
	}
	defer func() { _ = response.Body.Close() }()

	content, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", backupHttpError(response.StatusCode, content)
	}
	// unknown providers and ids are answered with an empty 200
	if len(content) == 0 {
		if id == "" || id == BackupCurrent {
			return nil, "", &coreapi.NotFoundError{Name: fmt.Sprintf("backup of provider %s", provider)}
		}
		return nil, "", &coreapi.NotFoundError{Name: fmt.Sprintf("backup %s", id)}
	}

	if _, params, parseErr := mime.ParseMediaType(response.Header.Get("Content-Disposition")); parseErr == nil {
		// the name is url encoded by OPNsense
		if unescaped, unescapeErr := url.QueryUnescape(params["filename"]); unescapeErr == nil {
			filename = unescaped
		}
	}
	// never allow a path from the server
	filename = backupSafeFilename(filename)
	if filename == "" {
		filename = "config.xml"
		if id != "" && id != BackupCurrent {
			filename = backupSafeFilename(id)
		}
	}
	return content, filename, nil
}

func backupSafeFilename(name string) string {
	name = name[strings.LastIndexAny(name, `/\`)+1:]
	if name == "." || name == ".." {
		return ""
	}
	return name
}

// backupHttpError builds an *HttpError from a non JSON-decoded answer
func backupHttpError(statusCode int, body []byte) error {
	var container struct {
		Message      string `json:"message"`
		ErrorMessage string `json:"errorMessage"`
	}
	var message = strings.TrimSpace(string(body))
	if err := json.Unmarshal(body, &container); err == nil {
		if container.Message != "" {
			message = container.Message
		} else if container.ErrorMessage != "" {
			message = container.ErrorMessage
		}
	}
	return &coreapi.HttpError{StatusCode: statusCode, Message: message}
}

// BackupRevert restores the local backup id as the running configuration (it is not applied to services until
// they are reconfigured). This replaces the whole config, including users and API keys
func (opn *SystemApi) BackupRevert(id string) error {
	return opn.backupAction("revert_backup", id, "reverted")
}

// BackupDelete removes the local history entry id
func (opn *SystemApi) BackupDelete(id string) error {
	return opn.backupAction("delete_backup", id, "deleted")
}

// backupAction POSTs revert_backup / delete_backup, OPNsense answers {"status":"<success>"} or "not_found"
func (opn *SystemApi) backupAction(method string, id string, success string) error {
	if id == "" || id == BackupCurrent {
		return fmt.Errorf("a backup id like config-1792886029.2372.xml is required")
	}
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.backupEndpoint(method, id), nil, &container); err != nil {
		return err
	}
	switch container.Status {
	case success:
		return nil
	case "not_found":
		return &coreapi.NotFoundError{Name: fmt.Sprintf("backup %s", id)}
	default:
		return fmt.Errorf("unexpected answer from %s: status %q", method, container.Status)
	}
}
