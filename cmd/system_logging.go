package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/system"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var systemLoggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "Manage System > Settings > Logging (syslog-ng): general settings, remote destinations, service",
	Long: `Manage System > Settings > Logging (syslog-ng): general settings, remote destinations, service.
Changes are saved only, run "opn system logging service reconfigure" to apply them.`,
}

func init() {
	systemCmd.AddCommand(systemLoggingCmd)
}

func systemLoggingApi() *system.SystemApi {
	return &system.SystemApi{OPNsense: GetOPNsenseApi()}
}

// systemLoggingBool converts a bool flag to the "0" / "1" OPNsense expects
func systemLoggingBool(value bool) string {
	return strconv.Itoa(BoolToInt(value))
}

// systemLoggingValidateRange exits if value is not a number between min and max (empty is allowed when allowEmpty)
func systemLoggingValidateRange(flag string, value string, min int, max int, allowEmpty bool) {
	if value == "" && allowEmpty {
		return
	}
	if number, err := strconv.Atoi(value); err != nil || number < min || number > max {
		log.Fatalf("--%s must be a number between %d and %d: %q", flag, min, max, value)
	}
}

// systemLoggingValidateList exits if value (a comma separated list, empty allowed) contains an entry not in valid
func systemLoggingValidateList(flag string, value string, valid []string) {
	if value == "" {
		return
	}
	for _, entry := range strings.Split(value, ",") {
		var found = false
		for _, option := range valid {
			found = found || entry == option
		}
		if !found {
			log.Fatalf("--%s: invalid value %q, valid are: %s", flag, entry, strings.Join(valid, ", "))
		}
	}
}
