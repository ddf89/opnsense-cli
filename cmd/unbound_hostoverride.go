package cmd

import (
	"errors"
	"fmt"
	opnsenseapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"
	"strings"

	"github.com/spf13/cobra"
)

var (
	HOSTOVERRIDEhost        string
	HOSTOVERRIDEdomain      string
	HOSTOVERRIDEuuid        string
	HOSTOVERRIDEip          string
	HOSTOVERRIDErr          string
	HOSTOVERRIDEmxprio      string
	HOSTOVERRIDEmx          string
	HOSTOVERRIDEttl         string
	HOSTOVERRIDEtxtdata     string
	HOSTOVERRIDEaddptr      string
	HOSTOVERRIDEdescription string
	// HOSTOVERRIDEnabled 0 for disabled, 1 for enabled
	HOSTOVERRIDEnabled string
	// HOSTOVERRIDEfilterRr limits show / rm to one record type. Separate from HOSTOVERRIDErr, since cobra resets
	// a variable to the flag default whenever it is bound and create / update default to A
	HOSTOVERRIDEfilterRr string
	HOSTOVERRIDEsearch   string
)

var unboundHostOverrideCmd = &cobra.Command{
	Use:   "hostoverride",
	Short: "Manage Unbound Host Override entries",
}

func init() {
	unboundCmd.AddCommand(unboundHostOverrideCmd)
}

// hostOverrideValue returns the record data depending on the record type
func hostOverrideValue(hostOverride unbound.HostOverride) string {
	switch strings.ToUpper(hostOverride.Rr) {
	case "MX":
		return strings.TrimSpace(fmt.Sprintf("%s %s", hostOverride.Mxprio, hostOverride.Mx))
	case "TXT":
		return hostOverride.Txtdata
	default:
		return hostOverride.Ip
	}
}

func hostOverrideFields(hostOverride unbound.HostOverride) [][2]string {
	return [][2]string{
		{"uuid", hostOverride.Uuid},
		{"enabled", hostOverride.Enabled},
		{"host", hostOverride.Host},
		{"domain", hostOverride.Domain},
		{"rr", hostOverride.Rr},
		{"ip", hostOverride.Ip},
		{"mxprio", hostOverride.Mxprio},
		{"mx", hostOverride.Mx},
		{"txtdata", hostOverride.Txtdata},
		{"ttl", hostOverride.Ttl},
		{"addptr", hostOverride.Addptr},
		{"description", hostOverride.Description},
	}
}

// hostOverrideLookupError adds a hint to use --uuid when a lookup by FQDN is ambiguous
func hostOverrideLookupError(err error) error {
	var tooMany *opnsenseapi.TooManyFoundError
	if errors.As(err, &tooMany) {
		return fmt.Errorf("%w, please select one with --uuid", err)
	}
	return err
}
