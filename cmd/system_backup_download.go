package cmd

import (
	"log"
	"opnsense-cli/opnsense/api/system"
	"os"

	"github.com/spf13/cobra"
)

var (
	systemBackupDownloadProvider string
	systemBackupDownloadId       string
	systemBackupDownloadOutput   string
	systemBackupDownloadForce    bool
)

var systemBackupDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download a config.xml (the current configuration by default)",
	Long: `Download a config.xml (the current configuration by default).

The file contains secrets (password hashes, API keys, private keys), so it is written
to a file (mode 0600) named like OPNsense suggests (config-<host>-<time>.xml) unless
--output is given. Use --output - to write to stdout. Existing files are not
overwritten without --force.`,
	Args: cobra.NoArgs,
	Run:  systemBackupDownloadRun,
}

func init() {
	systemBackupAddProviderFlag(systemBackupDownloadCmd, &systemBackupDownloadProvider)
	systemBackupDownloadCmd.Flags().StringVar(&systemBackupDownloadId, "id", system.BackupCurrent, "backup id from 'backup list', or current")
	systemBackupDownloadCmd.Flags().StringVarP(&systemBackupDownloadOutput, "output", "o", "", "file to write, - for stdout (default: the name suggested by OPNsense)")
	systemBackupDownloadCmd.Flags().BoolVarP(&systemBackupDownloadForce, "force", "f", false, "overwrite an existing file")
	systemBackupCmd.AddCommand(systemBackupDownloadCmd)
}

func systemBackupDownloadRun(_ *cobra.Command, _ []string) {
	var content, filename, err = newSystemBackupApi().BackupDownload(systemBackupDownloadProvider, systemBackupDownloadId)
	if err != nil {
		log.Fatal(err)
	}

	if systemBackupDownloadOutput == "-" {
		if _, err := os.Stdout.Write(content); err != nil {
			log.Fatal(err)
		}
		return
	}

	if systemBackupDownloadOutput != "" {
		filename = systemBackupDownloadOutput
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if systemBackupDownloadForce {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, openErr := os.OpenFile(filename, flags, 0o600)
	if openErr != nil {
		if os.IsExist(openErr) {
			log.Fatalf("%s already exists, use --force to overwrite it", filename)
		}
		log.Fatal(openErr)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		log.Fatal(err)
	}
	if err := file.Close(); err != nil {
		log.Fatal(err)
	}
	log.Printf("Saved %s (%d bytes)", filename, len(content))
}
