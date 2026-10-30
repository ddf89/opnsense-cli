package cli

import (
	"fmt"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/shaper/pipe and /firewall/shaper/queue export and import: the CSV format of the GUI's "Export as csv"
// / "Import csv" (api/trafficshaper/settings/download_pipes, upload_pipes, download_queues, upload_queues). Shaper
// rules have no CSV endpoints

const firewallShaperTransferNote = `The export has all fields with @uuid first, the number and origin. A row without number (or an empty one)
gets the lowest free number from 10000 on when it adds a %[1]s and keeps the current number when it updates one; a
number used by another %[1]s is refused before anything is sent. A row with an unknown @uuid adds the %[1]s with
that uuid, so another firewall's export keeps its uuids.%[2]s
` + firewallShaperApplyHint

func firewallShaperTransfer(what string, columns []string, note string,
	export func(api *firewall.FirewallApi) ([]byte, error),
	upload func(api *firewall.FirewallApi, content []byte, filename string) (coreapi.CsvImportResult, error)) CsvTransfer {
	return CsvTransfer{What: what + "s", Key: "@uuid",
		Note: note,
		Export: func(c *Context) ([]byte, error) {
			var api, err = firewallApi(c)
			if err != nil {
				return nil, err
			}
			return export(api)
		},
		Import: func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
			var api, err = firewallApi(c)
			if err != nil {
				return coreapi.CsvImportResult{}, err
			}
			return upload(api, content, filename)
		},
		Columns: func(*Context) ([]string, error) { return columns, nil },
	}
}

func init() {
	var pipes = firewallShaperTransfer("pipe", firewall.ShaperPipeCsvColumns,
		fmt.Sprintf(firewallShaperTransferNote, "pipe", `
Queues refer to pipes by uuid: import the pipes before the queues.`),
		(*firewall.FirewallApi).ShaperPipeExport, (*firewall.FirewallApi).ShaperPipeImport)
	Root.Menu("firewall/shaper/pipe").Add(pipes.ExportCommand(), pipes.ImportCommand())

	var queues = firewallShaperTransfer("queue", firewall.ShaperQueueCsvColumns,
		fmt.Sprintf(firewallShaperTransferNote, "queue", `
The pipe column holds the pipe's uuid, the import also takes its description; a row naming a pipe that does not
exist refuses the import before anything is sent (import the pipes first).`),
		(*firewall.FirewallApi).ShaperQueueExport, (*firewall.FirewallApi).ShaperQueueImport)
	Root.Menu("firewall/shaper/queue").Add(queues.ExportCommand(), queues.ImportCommand())
}
