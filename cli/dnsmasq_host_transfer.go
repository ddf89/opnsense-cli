package cli

import (
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/dnsmasq"
)

// /dnsmasq/host export and import: the CSV of the GUI's "Export as csv" / "Import csv" of Dnsmasq > Hosts
// (api/dnsmasq/settings/download_hosts, upload_hosts). The rest of /dnsmasq/host lives in dnsmasq_host.go

var dnsmasqHostTransfer = CsvTransfer{
	What: "hosts",
	Key:  "hostname, domain and ip_address",
	Note: `The columns are those of the GUI export: hostname, domain, local, ip_address, cnames, client_id,
hw_address, lease_time, ignore, set_tag (the uuid of the tag), description and aliases, in the configured order;
lists are comma separated, local and ignore are 0 or 1. comments are not exported: an import keeps the comments
of the hosts it updates unless the file has a comments column. The import also takes the field names host, ip,
hwaddr and descr instead of hostname, ip_address, hw_address and description. hostname, domain and ip_address
are compared as exact text, so another case or order of the addresses adds a host instead of updating one.
` + dnsmasqApplyHint,
	Export: func(c *Context) ([]byte, error) {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return nil, err
		}
		return api.HostExportCsv()
	},
	Import: func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return coreapi.CsvImportResult{}, err
		}
		return api.HostImportCsv(content, filename)
	},
	Columns: func(c *Context) ([]string, error) {
		var api, err = dnsmasqApi(c)
		if err != nil {
			return nil, err
		}
		return api.HostCsvColumns()
	},
}

func init() {
	var importCommand = dnsmasqHostTransfer.ImportCommand()
	// the file check of ImportCommand, plus a field given twice (ip and ip_address), before the confirmation
	importCommand.Check = func(args *Args) error {
		var file = args.String("file")
		var _, parsed, err = transferRead(file, dnsmasqHostTransfer.What)
		if err != nil {
			return err
		}
		if err := dnsmasq.HostCheckCsv(parsed); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		return nil
	}
	Root.Menu("dnsmasq/host").Add(dnsmasqHostTransfer.ExportCommand(), importCommand)
}
