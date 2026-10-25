package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var systemTunableApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply the System Tunables (set runtime sysctls, regenerate loader.conf)",
	Long: `Apply the System Tunables: runtime sysctls which differ from the configuration are set and
/boot/loader.conf is regenerated, boot-time tunables take effect after a reboot.`,
	Args: cobra.NoArgs,
	Run:  systemTunableApplyRun,
}

func init() {
	systemTunableCmd.AddCommand(systemTunableApplyCmd)
}

func systemTunableApplyRun(_ *cobra.Command, _ []string) {
	if err := newSystemTunableApi().TunableReconfigure(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("tunables applied")
}
