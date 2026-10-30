package cli

import (
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/unbound"
)

// /unbound/host-override export and import: the CSV of the GUI's "Export as csv" / "Import csv" of Unbound >
// Overrides (api/unbound/settings/download_host_overrides, upload_host_overrides; newer than 26.7.7). The rest of
// /unbound/host-override lives in unbound_hostoverride.go

var unboundHostOverrideTransfer = CsvTransfer{
	What: "host overrides",
	Key:  "@uuid",
	Note: `The columns are those of the GUI export: @uuid, enabled, hostname, domain, rr, mxprio, mx, ttl, server
(the address of A and AAAA records), txtdata, addptr, aliases and description, in the configured order; enabled
and addptr are 0 or 1. aliases are the FQDNs of the entry's aliases (comma separated): importing the column makes
exactly them the aliases of the entry, an empty cell removes its aliases. Rows with an empty @uuid add entries,
also when an entry with the same host, domain and type exists. Needs an OPNsense newer than 26.7.7.
` + unboundApplyHint,
	Export: func(c *Context) ([]byte, error) {
		var api, err = unboundApi(c)
		if err != nil {
			return nil, err
		}
		return api.HostOverrideExportCsv()
	},
	Import: func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
		var api, err = unboundApi(c)
		if err != nil {
			return coreapi.CsvImportResult{}, err
		}
		return api.HostOverrideImportCsv(content, filename)
	},
	Columns: func(c *Context) ([]string, error) {
		var api, err = unboundApi(c)
		if err != nil {
			return nil, err
		}
		return api.HostOverrideCsvColumns()
	},
}

func init() {
	var importCommand = unboundHostOverrideTransfer.ImportCommand()
	// the file check of ImportCommand, plus the @uuid column (format, duplicates), before the confirmation
	importCommand.Check = func(args *Args) error {
		var file = args.String("file")
		var _, parsed, err = transferRead(file, unboundHostOverrideTransfer.What)
		if err != nil {
			return err
		}
		if err := unbound.HostOverrideCheckCsv(parsed); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		return nil
	}
	Root.Menu("unbound/host-override").Add(unboundHostOverrideTransfer.ExportCommand(), importCommand)
}
