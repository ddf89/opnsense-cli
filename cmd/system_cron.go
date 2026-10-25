package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// systemCronUuid / systemCronDescription select a job (show, update, rm, enable, disable)
	systemCronUuid        string
	systemCronDescription string
	systemCronSearch      string
)

var systemCronCmd = &cobra.Command{
	Use:   "cron",
	Short: "Manage cron jobs (System > Settings > Cron)",
	Long: `Manage cron jobs (System > Settings > Cron).

Changes to jobs are only activated after running "opn system cron apply".`,
}

func init() {
	systemCmd.AddCommand(systemCronCmd)
}

func newSystemCronApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}

// systemCronSetupLookupFlags adds --uuid / --description to select a single job
func systemCronSetupLookupFlags(command *cobra.Command) {
	command.Flags().StringVarP(&systemCronUuid, "uuid", "", "", "select the job by uuid")
	command.Flags().StringVarP(&systemCronDescription, "description", "", "", "select the job by its exact description (must be unique)")
}

// systemCronLookup returns the job selected by --uuid or --description
func systemCronLookup(api *system.SystemApi) system.CronJob {
	var job system.CronJob
	var err error
	if systemCronUuid != "" {
		job, err = api.CronJobGet(systemCronUuid)
	} else if systemCronDescription != "" {
		job, err = api.CronJobGetByDescription(systemCronDescription)
	} else {
		log.Fatal("Please either set uuid or description")
	}
	if err != nil {
		log.Fatal(err)
	}
	return job
}

// systemCronSetupFieldFlags adds the flags for all job fields, with the OPNsense defaults if withDefaults is set
func systemCronSetupFieldFlags(command *cobra.Command, withDefaults bool) {
	var defaultValue = func(value string) string {
		if withDefaults {
			return value
		}
		return ""
	}
	command.Flags().String("command", "", "the configd action to run, see \"opn system cron commands\"")
	command.Flags().String("parameters", "", "parameters for the command")
	command.Flags().String("minutes", defaultValue("0"), "minutes: 0-59, lists, ranges, steps and * are supported (ex. 1,10,20 or 1-30 or */5)")
	command.Flags().String("hours", defaultValue("0"), "hours: 0-23, lists, ranges, steps and *")
	command.Flags().String("days", defaultValue("*"), "days of the month: 1-31, lists, ranges, steps and *")
	command.Flags().String("months", defaultValue("*"), "months: 1-12 or JAN-DEC, lists, ranges, steps and *")
	command.Flags().String("weekdays", defaultValue("*"), "weekdays: 0-7 (0 and 7 are Sunday), lists, ranges, steps and *")
	command.Flags().String("who", defaultValue("root"), "the user running the command")
	command.Flags().String("enabled", defaultValue("1"), "1 to enable the job, 0 to disable it")
}

// systemCronPatchFromFlags returns the fields given on the command line, and with all set also the flag defaults
func systemCronPatchFromFlags(command *cobra.Command, all bool) system.CronJobPatch {
	var patch system.CronJobPatch
	var fields = []struct {
		flag  string
		field **string
	}{
		{"command", &patch.Command},
		{"parameters", &patch.Parameters},
		{"minutes", &patch.Minutes},
		{"hours", &patch.Hours},
		{"days", &patch.Days},
		{"months", &patch.Months},
		{"weekdays", &patch.Weekdays},
		{"who", &patch.Who},
		{"enabled", &patch.Enabled},
	}
	for _, field := range fields {
		if all || command.Flags().Changed(field.flag) {
			var value, _ = command.Flags().GetString(field.flag)
			*field.field = &value
		}
	}
	return patch
}

// systemCronValidateCommand checks command against the available configd actions
func systemCronValidateCommand(api *system.SystemApi, command string) {
	var commands, err = api.CronCommands()
	if err != nil {
		log.Fatal(err)
	}
	for _, available := range commands {
		if available.Key == command {
			return
		}
	}
	log.Fatalf("unknown command %q, see \"opn system cron commands\" for the available commands", command)
}

func systemCronFields(job system.CronJob) [][2]string {
	return [][2]string{
		{"uuid", job.Uuid},
		{"enabled", job.Enabled},
		{"description", job.Description},
		{"schedule", job.Schedule()},
		{"minutes", job.Minutes},
		{"hours", job.Hours},
		{"days", job.Days},
		{"months", job.Months},
		{"weekdays", job.Weekdays},
		{"who", job.Who},
		{"command", strings.TrimSpace(fmt.Sprintf("%s (%s)", job.Command, job.CommandDescription))},
		{"parameters", job.Parameters},
		{"origin", job.Origin},
	}
}
