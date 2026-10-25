package cmd

import (
	"errors"
	"fmt"
	"log"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/system"

	"github.com/spf13/cobra"
)

var (
	systemTunableUuid        string
	systemTunableName        string
	systemTunableValue       string
	systemTunableDescription string
	systemTunableSearch      string
	systemTunableChanged     bool
)

var systemTunableCmd = &cobra.Command{
	Use:   "tunable",
	Short: "Manage System Tunables (sysctl / loader.conf values)",
	Long: `Manage System > Settings > Tunables.

Built-in OPNsense defaults are listed even when they are not configured, their uuid is a 32 character
md5 key and their value is the current runtime value. Setting such a tunable stores an override, removing
the override brings back the built-in default. An empty value means "use the default".
Changes are only activated by "opn system tunable apply".`,
}

func init() {
	systemCmd.AddCommand(systemTunableCmd)
}

func newSystemTunableApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}

// systemTunableSetupLookupFlags adds --name / --uuid to select an existing tunable
func systemTunableSetupLookupFlags(command *cobra.Command) {
	command.Flags().StringVar(&systemTunableName, "name", "", "select the tunable by its exact name, e.g. kern.ipc.maxsockbuf")
	command.Flags().StringVar(&systemTunableUuid, "uuid", "", "select the tunable by uuid")
	command.MarkFlagsMutuallyExclusive("name", "uuid")
	command.MarkFlagsOneRequired("name", "uuid")
}

// systemTunableLookup returns the tunable selected by --uuid or --name, exits on errors
func systemTunableLookup(api *system.SystemApi) system.Tunable {
	var tunable system.Tunable
	var err error
	if systemTunableUuid != "" {
		tunable, err = api.TunableGet(systemTunableUuid)
	} else {
		tunable, err = api.TunableGetByName(systemTunableName)
	}

	var tooMany *coreapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		log.Fatalf("%v, please select one with --uuid", err)
	}
	if err != nil {
		log.Fatal(err)
	}
	return tunable
}

// systemTunableTypeName explains the sysctl type letter
func systemTunableTypeName(sysctlType string) string {
	switch sysctlType {
	case "w":
		return "runtime"
	case "t":
		return "boot-time"
	case "r":
		return "read-only"
	case "":
		return ""
	default:
		return sysctlType
	}
}

// systemTunableSource tells whether the row is stored in the configuration
func systemTunableSource(tunable system.Tunable) string {
	switch {
	case tunable.IsBuiltin():
		return "built-in"
	case tunable.DefaultValue != "":
		return "override"
	default:
		return "custom"
	}
}

func systemTunableApplyHint() {
	log.Print("run \"opn system tunable apply\" to activate the change")
}

func systemTunableTruncate(text string, length int) string {
	var runes = []rune(text)
	if len(runes) <= length {
		return text
	}
	return fmt.Sprintf("%s...", string(runes[:length-3]))
}
