package cmd

import (
	"fmt"
	"log"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var systemCronNewDescription string

var systemCronUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update fields of an existing cron job selected by --uuid or --description",
	Long: `Update an existing cron job selected by --uuid or --description.

Only the flags given are changed, all other fields are kept. Clear the parameters with --parameters "".
To change the description use --new-description, or select the job by --uuid and pass the new --description.
Run "opn system cron apply" to activate the change.`,
	Args: cobra.NoArgs,
	Run:  systemCronUpdateRun,
}

func init() {
	systemCronSetupLookupFlags(systemCronUpdateCmd)
	systemCronUpdateCmd.Flags().StringVarP(&systemCronNewDescription, "new-description", "", "", "change the description to this value")
	systemCronSetupFieldFlags(systemCronUpdateCmd, false)

	systemCronCmd.AddCommand(systemCronUpdateCmd)
}

func systemCronUpdateRun(command *cobra.Command, _ []string) {
	var api = newSystemCronApi()
	var flags = command.Flags()

	var patch = systemCronPatchFromFlags(command, false)
	var job system.CronJob
	if systemCronUuid != "" {
		// selected by uuid, so --description is the new value
		if flags.Changed("description") && flags.Changed("new-description") {
			log.Fatal("with --uuid use either --description or --new-description")
		}
		if flags.Changed("description") {
			patch.Description = &systemCronDescription
		}
		var err error
		if job, err = api.CronJobGet(systemCronUuid); err != nil {
			log.Fatal(err)
		}
	} else {
		job = systemCronLookup(api)
	}
	if flags.Changed("new-description") {
		patch.Description = &systemCronNewDescription
	}

	if patch == (system.CronJobPatch{}) {
		log.Fatal("nothing to update, please set at least one field flag")
	}
	if patch.Description != nil && *patch.Description == "" {
		log.Fatal("the description must not be empty")
	}
	if patch.Command != nil {
		systemCronValidateCommand(api, *patch.Command)
	}

	// jobs registered by other services must send their unchanged command and parameters
	if job.Origin != system.CronOriginUser {
		if patch.Command != nil && *patch.Command != job.Command || patch.Parameters != nil && *patch.Parameters != job.Parameters {
			log.Fatalf("the job was registered by %q, its command and parameters cannot be changed", job.Origin)
		}
		patch.Command = &job.Command
		patch.Parameters = &job.Parameters
	}

	if err := api.CronJobUpdate(job.Uuid, patch); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Updated successfully, uuid: %s\n", job.Uuid)
}
