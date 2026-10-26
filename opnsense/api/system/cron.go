package system

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strings"
)

// CronOriginUser is the origin of jobs created by users. Jobs registered by other services (any other origin)
// cannot be deleted and their command and parameters cannot be changed
const CronOriginUser = "cron"

// CronJob is a job of System > Settings > Cron, as returned by search_jobs
type CronJob struct {
	Uuid   string `json:"uuid"`
	Origin string `json:"origin"`
	// 0 for disabled, 1 for enabled
	Enabled  string `json:"enabled"`
	Minutes  string `json:"minutes"`  // 0-59, ranges, steps, lists and * are supported
	Hours    string `json:"hours"`    // 0-23
	Days     string `json:"days"`     // 1-31
	Months   string `json:"months"`   // 1-12 or JAN-DEC
	Weekdays string `json:"weekdays"` // 0-7, Sunday is 0 and 7
	Who      string `json:"who"`      // the user running the command
	// Command is a configd action like "firmware poll", see CronCommands
	Command            string `json:"command"`
	CommandDescription string `json:"%command"`
	Parameters         string `json:"parameters"`
	Description        string `json:"description"`
}

// Schedule returns the crontab style schedule "minutes hours days months weekdays"
func (job CronJob) Schedule() string {
	return strings.Join([]string{job.Minutes, job.Hours, job.Days, job.Months, job.Weekdays}, " ")
}

// CronJobPatch holds the fields to send on create / update, nil fields are not sent:
// OPNsense uses its defaults for them on create and keeps the current value on update
type CronJobPatch struct {
	Enabled     *string `json:"enabled,omitempty"`
	Minutes     *string `json:"minutes,omitempty"`
	Hours       *string `json:"hours,omitempty"`
	Days        *string `json:"days,omitempty"`
	Months      *string `json:"months,omitempty"`
	Weekdays    *string `json:"weekdays,omitempty"`
	Who         *string `json:"who,omitempty"`
	Command     *string `json:"command,omitempty"`
	Parameters  *string `json:"parameters,omitempty"`
	Description *string `json:"description,omitempty"`
}

// CronCommand is a configd action which can be used as CronJob.Command
type CronCommand struct {
	Key         string
	Description string
}

type cronJobContainer struct {
	Job CronJobPatch `json:"job"`
}

func (opn *SystemApi) cronSettingsEndpoint(method string) string {
	return opn.EndpointForPluginControllerMethod("cron", "settings", method)
}

// cronOptional returns nil for empty values, so they are not sent
func cronOptional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// CronJobSearch returns all jobs where any column contains searchPhrase, use "" for all jobs
func (opn *SystemApi) CronJobSearch(searchPhrase string) ([]CronJob, error) {
	return coreapi.Search[CronJob](opn.OPNsense, opn.cronSettingsEndpoint("search_jobs"), searchPhrase)
}

func (opn *SystemApi) CronJobList() ([]CronJob, error) {
	return opn.CronJobSearch("")
}

// CronJobGet returns the job with the given uuid
func (opn *SystemApi) CronJobGet(uuid string) (CronJob, error) {
	// get_job/<uuid> answers with an option list for command instead of the plain value, so we filter the search result
	var jobs, err = opn.CronJobList()
	if err != nil {
		return CronJob{}, err
	}

	var matching = coreapi.Filter(jobs, func(job CronJob) bool {
		return job.Uuid == uuid
	})
	if len(matching) == 0 {
		return CronJob{}, &coreapi.NotFoundError{Name: fmt.Sprintf("cron job %s", uuid)}
	}
	return matching[0], nil
}

// CronJobGetByDescription returns the only job with exactly the given description.
// Returns *coreapi.NotFoundError if there is none and *coreapi.TooManyFoundError if there is more than one
func (opn *SystemApi) CronJobGetByDescription(description string) (CronJob, error) {
	if description == "" {
		return CronJob{}, errors.New("cannot look up a cron job by an empty description")
	}

	var jobs, err = opn.CronJobSearch(description)
	if err != nil {
		return CronJob{}, err
	}

	var matching = coreapi.Filter(jobs, func(job CronJob) bool {
		return job.Description == description
	})
	var name = fmt.Sprintf("cron job with description %q", description)
	if len(matching) > 1 {
		var uuids = make([]string, 0, len(matching))
		for _, job := range matching {
			uuids = append(uuids, job.Uuid)
		}
		return CronJob{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s matches %s", name, strings.Join(uuids, ", "))}
	}
	if len(matching) == 0 {
		return CronJob{}, &coreapi.NotFoundError{Name: name}
	}
	return matching[0], nil
}

// CronJobCreate creates a job from all non empty fields of job (Uuid, Origin and CommandDescription are ignored)
// and returns its uuid. OPNsense requires Command and Description, the schedule defaults to daily at 00:00 as root
func (opn *SystemApi) CronJobCreate(job CronJob) (string, error) {
	var patch = CronJobPatch{
		Enabled:     cronOptional(job.Enabled),
		Minutes:     cronOptional(job.Minutes),
		Hours:       cronOptional(job.Hours),
		Days:        cronOptional(job.Days),
		Months:      cronOptional(job.Months),
		Weekdays:    cronOptional(job.Weekdays),
		Who:         cronOptional(job.Who),
		Command:     cronOptional(job.Command),
		Parameters:  cronOptional(job.Parameters),
		Description: cronOptional(job.Description),
	}
	return opn.Mutate(opn.cronSettingsEndpoint("add_job"), cronJobContainer{Job: patch})
}

// CronJobUpdate changes the non nil fields of patch on the job with the given uuid.
// Jobs registered by other services (Origin != CronOriginUser) need the unchanged Command and Parameters in the patch
func (opn *SystemApi) CronJobUpdate(uuid string, patch CronJobPatch) error {
	if uuid == "" {
		return errors.New("cannot update a cron job without uuid")
	}

	var endpoint = fmt.Sprintf("%s/%s", opn.cronSettingsEndpoint("set_job"), uuid)
	if _, err := opn.Mutate(endpoint, cronJobContainer{Job: patch}); err != nil {
		// OPNsense answers an unknown uuid with {"result":"failed"} without any validation messages
		var validationErr *coreapi.ValidationError
		if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("cron job %s", uuid), Err: err}
		}
		return err
	}
	return nil
}

// CronJobRemove deletes the job with the given uuid, returns *coreapi.NotFoundError if it does not exist.
// Jobs registered by other services cannot be deleted (OPNsense answers with HTTP 500)
func (opn *SystemApi) CronJobRemove(uuid string) error {
	if uuid == "" {
		return errors.New("cannot remove a cron job without uuid")
	}

	var endpoint = fmt.Sprintf("%s/%s", opn.cronSettingsEndpoint("del_job"), uuid)
	if _, err := opn.Mutate(endpoint, nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("cron job %s", uuid), Err: err}
		}
		// 26.7.7 answers an unknown uuid with a bare "failed" (26.7: "not found")
		var validationErr *coreapi.ValidationError
		if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
			if _, getErr := opn.CronJobGet(uuid); coreapi.IsNotFound(getErr) {
				return getErr
			}
		}
		return err
	}
	return nil
}

// CronJobSetEnabled enables or disables the job with the given uuid and returns whether its state changed
func (opn *SystemApi) CronJobSetEnabled(uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("cannot toggle a cron job without uuid")
	}

	var state = "0"
	if enabled {
		state = "1"
	}
	// toggle_job/<uuid>/<0|1> sets the given state, without the state it would flip it
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.cronSettingsEndpoint("toggle_job"), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}

	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed": // unknown uuid
		return false, &coreapi.NotFoundError{Name: fmt.Sprintf("cron job %s", uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// CronCommands returns the configd actions which can be used as CronJob.Command, sorted by key
func (opn *SystemApi) CronCommands() ([]CronCommand, error) {
	var container struct {
		Job struct {
			Command map[string]struct {
				Value string `json:"value"`
			} `json:"command"`
		} `json:"job"`
	}
	if err := opn.DoJSON("GET", opn.cronSettingsEndpoint("get_job"), nil, &container); err != nil {
		return nil, err
	}

	var commands = make([]CronCommand, 0, len(container.Job.Command))
	for key, option := range container.Job.Command {
		if key == "" { // the "none selected" option, if any
			continue
		}
		commands = append(commands, CronCommand{Key: key, Description: option.Value})
	}
	sort.Slice(commands, func(i, j int) bool {
		return commands[i].Key < commands[j].Key
	})
	return commands, nil
}

// CronReconfigure writes the crontab and reloads cron, needed to activate any job change
func (opn *SystemApi) CronReconfigure() error {
	var container struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.EndpointForPluginControllerMethod("cron", "service", "reconfigure"), nil, &container); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(container.Status), "ok") {
		return fmt.Errorf("reconfiguring cron failed: %q", container.Status)
	}
	return nil
}
