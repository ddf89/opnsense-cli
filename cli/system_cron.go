package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// /system/cron: the jobs of System > Settings > Cron. Items are selected by the # of print, the uuid or the
// description. Jobs registered by other services (origin other than "cron") can not be removed and keep their
// command and parameters

const systemCronItemHelp = "the #, uuid or description of the cron job"

const systemCronApplyHint = `Changes are only saved, run "/system/cron apply" to apply them.`

// systemCronFieldArgs are the field arguments of add (with the OPNsense defaults) and set
func systemCronFieldArgs(add bool) []Arg {
	var defaultValue = func(value string) string {
		if add {
			return value
		}
		return ""
	}
	return []Arg{
		{Name: "description", Help: "what the job is for, also its name (1-255 characters)", Required: add,
			Validate: systemCronValidateDescription},
		{Name: "command", Help: "the configd action to run, see the commands command", Required: add,
			Validate: systemCronValidateText, Complete: systemCronCommandKeys},
		{Name: "parameters", Help: "parameters for the command", Validate: systemCronValidateText},
		{Name: "minutes", Help: "0-59, lists, ranges, steps and * (ex. 1,10,20 or 1-30 or */5)", Default: defaultValue("0"),
			Validate: systemCronValidateSchedule(0, 59, nil, false)},
		{Name: "hours", Help: "0-23, lists, ranges, steps and *", Default: defaultValue("0"),
			Validate: systemCronValidateSchedule(0, 23, nil, false)},
		{Name: "days", Help: "days of the month: 1-31, lists, ranges, steps and *, or L for the last day", Default: defaultValue("*"),
			Validate: systemCronValidateSchedule(1, 31, nil, true)},
		{Name: "months", Help: "1-12 or JAN-DEC, lists, ranges, steps and *", Default: defaultValue("*"),
			Validate: systemCronValidateSchedule(1, 12, systemCronMonthNames, false)},
		{Name: "weekdays", Help: "0-7 (0 and 7 are Sunday), lists, ranges, steps and *", Default: defaultValue("*"),
			Validate: systemCronValidateSchedule(0, 7, nil, false)},
		{Name: "who", Help: "the user running the command", Default: defaultValue("root"), Validate: systemCronValidateWho},
		{Name: "disabled", Help: "keep the job, but don't run it", Type: Bool, Default: defaultValue("no")},
	}
}

func init() {
	var menu = Root.Menu("system/cron")
	menu.Help = "cron jobs (System > Settings > Cron)"
	var item = Arg{Name: "item", Help: systemCronItemHelp, Positional: true, Required: true, Complete: systemCronItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the cron jobs", Args: []Arg{
			{Name: "detail", Help: "show all fields of every cron job", Type: Bool},
			{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
			{Name: "search", Help: "only cron jobs where any field contains this text"},
		}, Run: systemCronPrint},
		&Command{Name: "show", Help: "show all fields of one cron job", Args: []Arg{item}, Run: systemCronShow},
		&Command{Name: "add", Help: "add a cron job, prints its uuid",
			Long: `The schedule defaults to daily at 00:00, run as root. The description names the job: if a job with
this description exists already, add fails unless replace is given, then that job is replaced completely
(arguments not given are reset to their defaults).
` + systemCronApplyHint,
			Args: append(systemCronFieldArgs(true), Arg{Name: "replace", Help: "replace the job with the same description", Type: Bool}),
			Run:  systemCronAdd},
		&Command{Name: "set", Help: "change fields of a cron job, the others are kept",
			Long: `description= renames the job. Jobs registered by other services keep their command and parameters.
` + systemCronApplyHint,
			Args: append([]Arg{item}, systemCronFieldArgs(false)...), Run: systemCronSet},
		&Command{Name: "remove", Help: "remove a cron job",
			Long: `Jobs registered by other services (origin other than cron) can not be removed, disable them instead.
` + systemCronApplyHint,
			Args: []Arg{item}, Run: systemCronRemove},
		&Command{Name: "enable", Help: "enable a cron job", Long: systemCronApplyHint, Args: []Arg{item}, Run: systemCronEnabler(true)},
		&Command{Name: "disable", Help: "disable a cron job", Long: systemCronApplyHint, Args: []Arg{item}, Run: systemCronEnabler(false)},
		&Command{Name: "commands", Help: "list the commands (configd actions) cron jobs can run",
			Args: []Arg{{Name: "json", Help: "print one JSON object per command", Type: Bool}}, Run: systemCronCommands},
		&Command{Name: "apply", Help: "activate the cron job changes (writes the crontab)", Run: systemCronApply},
	)
}

// --- validation

var systemCronMonthNames = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}

var systemCronElementPattern = regexp.MustCompile(`^(\*|[0-9A-Z]+(-[0-9A-Z]+)?)(/([0-9]+))?$`)

// systemCronValidateSchedule checks a crontab field like OPNsense does: comma separated elements of *, a value
// or a range a-b, each optionally with a /step. names are the alternative value names (JAN-DEC), lastDay allows
// L (last day of the month) as the whole value
func systemCronValidateSchedule(low int, high int, names []string, lastDay bool) func(string) error {
	return func(value string) error {
		var fail = func() error {
			var allowed = fmt.Sprintf("%d-%d", low, high)
			if len(names) > 0 {
				allowed += fmt.Sprintf(" or %s-%s", names[0], names[len(names)-1])
			}
			if lastDay {
				allowed += ", or L for the last day"
			}
			return fmt.Errorf("must be %s; lists, ranges, steps and * are supported (ex. 1,2,8 or 1-5 or */2), got %q", allowed, value)
		}
		if value == "" {
			return fmt.Errorf("must not be empty, use * for every value")
		}
		if lastDay && value == "L" {
			return nil
		}
		var inRange = func(text string) bool {
			for _, name := range names {
				if text == name {
					return true
				}
			}
			var number, err = strconv.Atoi(text)
			return err == nil && number >= low && number <= high
		}
		for _, element := range strings.Split(value, ",") {
			var match = systemCronElementPattern.FindStringSubmatch(element)
			if match == nil {
				return fail()
			}
			if match[1] != "*" {
				var from, to, isRange = strings.Cut(match[1], "-")
				if !inRange(from) || isRange && !inRange(to) {
					return fail()
				}
			}
			if match[4] != "" {
				if step, err := strconv.Atoi(match[4]); err != nil || step < 1 || step > high {
					return fail()
				}
			}
		}
		return nil
	}
}

// systemCronValidateText rejects control characters, OPNsense accepts newlines in fields written to the crontab
func systemCronValidateText(value string) error {
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func systemCronValidateDescription(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	if len([]rune(value)) > 255 {
		return errors.New("must be at most 255 characters")
	}
	return systemCronValidateText(value)
}

var systemCronUserPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// systemCronValidateWho accepts a user name, OPNsense accepts anything (even spaces, which shift the crontab columns)
func systemCronValidateWho(value string) error {
	if !systemCronUserPattern.MatchString(value) {
		return fmt.Errorf("must be a user name like root, got %q", value)
	}
	return nil
}

// --- lookups

func systemCronApi(c *Context) (*system.SystemApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &system.SystemApi{OPNsense: opn}, nil
}

// systemCronSearch returns the matching jobs in API order, with the raw API objects for json output
func systemCronSearch(api *system.SystemApi, searchPhrase string) ([]system.CronJob, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("cron", "settings", "search_jobs")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var jobs = make([]system.CronJob, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &jobs[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected cron job from OPNsense: %w", err)
		}
	}
	return jobs, rows, nil
}

func systemCronUuid(job system.CronJob) string {
	return job.Uuid
}

func systemCronNames(job system.CronJob) []string {
	return []string{job.Description}
}

// systemCronSelect loads all jobs and finds the one selector refers to
func systemCronSelect(c *Context, api *system.SystemApi, selector string) (system.CronJob, error) {
	var jobs, _, err = systemCronSearch(api, "")
	if err != nil {
		return system.CronJob{}, err
	}
	return Select(c, selector, jobs, systemCronUuid, systemCronNames)
}

// systemCronItemNames completes item names (descriptions) from the API
func systemCronItemNames(c *Context) []string {
	var api, err = systemCronApi(c)
	if err != nil {
		return nil
	}
	var jobs, _, searchErr = systemCronSearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names []string
	for _, job := range jobs {
		if job.Description != "" {
			names = append(names, job.Description)
		}
	}
	return names
}

// systemCronCommandKeys completes command= with the configd actions from the API
func systemCronCommandKeys(c *Context) []string {
	var api, err = systemCronApi(c)
	if err != nil {
		return nil
	}
	var commands, listErr = api.CronCommands()
	if listErr != nil {
		return nil
	}
	var keys = make([]string, 0, len(commands))
	for _, command := range commands {
		keys = append(keys, command.Key)
	}
	return keys
}

// systemCronValidateCommand checks command against the available configd actions
func systemCronValidateCommand(api *system.SystemApi, command string) error {
	var commands, err = api.CronCommands()
	if err != nil {
		return err
	}
	for _, available := range commands {
		if available.Key == command {
			return nil
		}
	}
	return fmt.Errorf("unknown command %q, see \"/system/cron commands\" for the available commands", command)
}

// --- output

// systemCronDisabled renders the enabled flag of the API as the disabled argument
func systemCronDisabled(job system.CronJob) string {
	if job.Enabled == "0" {
		return "yes"
	}
	return "no"
}

func systemCronCommandText(job system.CronJob) string {
	if job.CommandDescription == "" || job.CommandDescription == job.Command {
		return job.Command
	}
	return fmt.Sprintf("%s (%s)", job.Command, job.CommandDescription)
}

// systemCronFields are the fields of show and print detail, named like the arguments of add and set
func systemCronFields(job system.CronJob) [][2]string {
	return [][2]string{
		{"uuid", job.Uuid},
		{"disabled", systemCronDisabled(job)},
		{"description", job.Description},
		{"schedule", job.Schedule()},
		{"minutes", job.Minutes},
		{"hours", job.Hours},
		{"days", job.Days},
		{"months", job.Months},
		{"weekdays", job.Weekdays},
		{"who", job.Who},
		{"command", systemCronCommandText(job)},
		{"parameters", job.Parameters},
		{"origin", job.Origin},
	}
}

func systemCronPrint(c *Context, args *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	var jobs, raw, searchErr = systemCronSearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(jobs))
	for i, job := range jobs {
		uuids[i] = job.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(jobs))
		for i, job := range jobs {
			items[i] = systemCronFields(job)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(jobs))
		for i, job := range jobs {
			rows[i] = []string{systemCronDisabled(job), job.Schedule(), job.Who, job.Command, job.Parameters, job.Description, job.Origin}
		}
		c.Items([]string{"DISABLED", "SCHEDULE", "WHO", "COMMAND", "PARAMETERS", "DESCRIPTION", "ORIGIN"}, rows, uuids)
	}
	return nil
}

func systemCronShow(c *Context, args *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	var job, selectErr = systemCronSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemCronFields(job))
	return nil
}

// --- changes

// systemCronPatch returns the given field arguments, with all also the defaults of the arguments not given
func systemCronPatch(args *Args, all bool) system.CronJobPatch {
	var patch system.CronJobPatch
	for _, field := range []struct {
		arg   string
		field **string
	}{
		{"description", &patch.Description},
		{"command", &patch.Command},
		{"parameters", &patch.Parameters},
		{"minutes", &patch.Minutes},
		{"hours", &patch.Hours},
		{"days", &patch.Days},
		{"months", &patch.Months},
		{"weekdays", &patch.Weekdays},
		{"who", &patch.Who},
	} {
		if all || args.Has(field.arg) {
			var value = args.String(field.arg)
			*field.field = &value
		}
	}
	if all || args.Has("disabled") {
		var enabled = Flag(!args.Bool("disabled"))
		patch.Enabled = &enabled
	}
	return patch
}

// systemCronProtect keeps command and parameters of jobs registered by other services, they must be sent unchanged
func systemCronProtect(job system.CronJob, patch *system.CronJobPatch) error {
	if job.Origin == system.CronOriginUser {
		return nil
	}
	if patch.Command != nil && *patch.Command != job.Command || patch.Parameters != nil && *patch.Parameters != job.Parameters {
		return fmt.Errorf("the job %s was registered by %q, its command and parameters can not be changed", job.Uuid, job.Origin)
	}
	patch.Command = &job.Command
	patch.Parameters = &job.Parameters
	return nil
}

func systemCronAdd(c *Context, args *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	if err := systemCronValidateCommand(api, args.String("command")); err != nil {
		return err
	}

	var description = args.String("description")
	var jobs, _, searchErr = systemCronSearch(api, "")
	if searchErr != nil {
		return searchErr
	}
	var existing []system.CronJob
	for _, job := range jobs {
		if strings.EqualFold(job.Description, description) {
			existing = append(existing, job)
		}
	}

	var patch = systemCronPatch(args, true)
	switch {
	case len(existing) == 0:
		var job = system.CronJob{
			Enabled: *patch.Enabled, Minutes: *patch.Minutes, Hours: *patch.Hours, Days: *patch.Days, Months: *patch.Months,
			Weekdays: *patch.Weekdays, Who: *patch.Who, Command: *patch.Command, Parameters: *patch.Parameters,
			Description: *patch.Description,
		}
		var uuid, createErr = api.CronJobCreate(job)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, job := range existing {
			uuids[i] = job.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d cron jobs with description %q (%s), change or remove them with set or remove",
			len(existing), description, strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a cron job with description %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Description, existing[0].Uuid)
	}

	var job = existing[0]
	if err := systemCronProtect(job, &patch); err != nil {
		return err
	}
	if err := api.CronJobUpdate(job.Uuid, patch); err != nil {
		return err
	}
	c.Infof("replaced the existing cron job %q", job.Description)
	c.Println(job.Uuid)
	return nil
}

func systemCronSet(c *Context, args *Args) error {
	var patch = systemCronPatch(args, false)
	if patch == (system.CronJobPatch{}) {
		return errors.New("set: nothing to change, give at least one field like hours= or description= (type \"set ?\" for help)")
	}

	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	var job, selectErr = systemCronSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if patch.Command != nil {
		if err := systemCronValidateCommand(api, *patch.Command); err != nil {
			return err
		}
	}
	if err := systemCronProtect(job, &patch); err != nil {
		return err
	}
	return api.CronJobUpdate(job.Uuid, patch)
}

func systemCronRemove(c *Context, args *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	var job, selectErr = systemCronSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if job.Origin != system.CronOriginUser {
		return fmt.Errorf("the job %s was registered by %q and can not be removed, disable it instead", job.Uuid, job.Origin)
	}
	return api.CronJobRemove(job.Uuid)
}

func systemCronEnabler(enabled bool) func(c *Context, args *Args) error {
	return func(c *Context, args *Args) error {
		var api, err = systemCronApi(c)
		if err != nil {
			return err
		}
		var job, selectErr = systemCronSelect(c, api, args.String("item"))
		if selectErr != nil {
			return selectErr
		}
		var changed, toggleErr = api.CronJobSetEnabled(job.Uuid, enabled)
		if toggleErr != nil {
			return toggleErr
		}
		if !changed {
			c.Infof("cron job %q is already %s", job.Description, EnabledWord(enabled))
		}
		return nil
	}
}

func systemCronCommands(c *Context, args *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	var commands, listErr = api.CronCommands()
	if listErr != nil {
		return listErr
	}
	if args.Bool("json") {
		for _, command := range commands {
			if err := c.JSON(map[string]string{"command": command.Key, "description": command.Description}); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, len(commands))
	for i, command := range commands {
		rows[i] = []string{command.Key, command.Description}
	}
	c.Table([]string{"COMMAND", "DESCRIPTION"}, rows)
	return nil
}

func systemCronApply(c *Context, _ *Args) error {
	var api, err = systemCronApi(c)
	if err != nil {
		return err
	}
	return api.CronReconfigure()
}
