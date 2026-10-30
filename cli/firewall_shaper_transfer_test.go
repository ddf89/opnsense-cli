package cli

import (
	"net/http"
	"testing"
)

// export / import of /firewall/shaper/pipe, /firewall/shaper/queue and /firewall/category

const (
	firewallShaperTransferPipeDownloadPath  = "/api/trafficshaper/settings/download_pipes"
	firewallShaperTransferPipeUploadPath    = "/api/trafficshaper/settings/upload_pipes"
	firewallShaperTransferQueueUploadPath   = "/api/trafficshaper/settings/upload_queues"
	firewallShaperTransferCategoryUpload    = "/api/firewall/category/upload"
	firewallShaperTransferCategoryDownload  = "/api/firewall/category/download"
	firewallShaperTransferImported          = `{"validations":[],"inserted":1,"updated":0,"uuids":{"0f0f0f0f-1111-4222-8333-000000000001":0},"fieldnames":[]}`
	firewallShaperTransferPipeCsv           = "@uuid;number;enabled;bandwidth;bandwidthMetric;description\n0f0f0f0f-1111-4222-8333-000000000001;10000;0;64;Kbit;WAN down\n"
	firewallShaperTransferCategoryCsvExport = "name;color\nweb;ff8800\n"
)

func firewallShaperTransferFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(firewallShaperPipeSearchPath, firewallShaperPipeRows...)
	f.search(firewallShaperQueueSearchPath, firewallShaperQueueRows...)
	for path, content := range map[string]string{firewallShaperTransferPipeDownloadPath: firewallShaperTransferPipeCsv,
		firewallShaperTransferCategoryDownload: firewallShaperTransferCategoryCsvExport} {
		f.onFunc("GET", path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/csv;charset=UTF-8")
			_, _ = w.Write([]byte(content))
		})
	}
	for _, path := range []string{firewallShaperTransferPipeUploadPath, firewallShaperTransferQueueUploadPath, firewallShaperTransferCategoryUpload} {
		f.on("POST", path, 200, firewallShaperTransferImported)
	}
	return f
}

func TestFirewallShaperTransferExport(t *testing.T) {
	t.Parallel()
	var f = firewallShaperTransferFake(t)
	var r = f.run("/firewall/shaper/pipe", "export", "-")
	wantExit(t, r, 0)
	if r.stdout != firewallShaperTransferPipeCsv {
		t.Errorf("stdout: %q", r.stdout)
	}
	r = f.run("/firewall/category", "export", "-")
	wantExit(t, r, 0)
	if r.stdout != firewallShaperTransferCategoryCsvExport {
		t.Errorf("stdout: %q", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestFirewallShaperTransferImportPipes(t *testing.T) {
	t.Parallel()
	t.Run("numbers new rows", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "pipes.csv", "enabled;bandwidth;description\n0;8;guest\n")
		var r = f.run("/firewall/shaper/pipe", "import", file, "confirm=yes")
		wantExit(t, r, 0)
		wantContains(t, "stderr", r.stderr, "pipes.csv: 1 pipes added, 0 updated")
		var call = wantOneMutation(t, f, "POST", firewallShaperTransferPipeUploadPath)
		wantJSON(t, call, map[string]any{"payload": "enabled;bandwidth;description;number\n0;8;guest;10003\n", "filename": "pipes.csv"})
	})
	t.Run("without confirmation nothing is sent", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "pipes.csv", "enabled;bandwidth;description\n0;8;guest\n")
		var r = f.run("/firewall/shaper/pipe", "import", file)
		wantFailure(t, r, "confirm=yes")
		wantNoCalls(t, f)
	})
	t.Run("a used number is refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "pipes.csv", "number;bandwidth;description\n10001;8;guest\n")
		var r = f.run("/firewall/shaper/pipe", "import", file, "confirm=yes")
		wantFailure(t, r, `line 2: the number 10001 is used by the pipe "WAN up"`)
		wantNoMutations(t, f)
	})
	t.Run("unknown columns are refused", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "pipes.csv", "bandwidth;speed\n8;fast\n")
		var r = f.run("/firewall/shaper/pipe", "import", file, "confirm=yes")
		wantFailure(t, r, "unknown columns speed")
		wantNoMutations(t, f)
	})
}

func TestFirewallShaperTransferImportQueues(t *testing.T) {
	t.Parallel()
	t.Run("pipe by description", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "queues.csv", "enabled,pipe,weight,description\n0,wan up,10,ssh\n")
		var r = f.run("/firewall/shaper/queue", "import", file, "confirm=yes")
		wantExit(t, r, 0)
		var call = wantOneMutation(t, f, "POST", firewallShaperTransferQueueUploadPath)
		wantJSON(t, call, map[string]any{"payload": "enabled,pipe,weight,description,number\n0,p-up,10,ssh,10002\n", "filename": "queues.csv"})
	})
	t.Run("unknown pipe", func(t *testing.T) {
		t.Parallel()
		var f = firewallShaperTransferFake(t)
		var file = firewallRuleTransferFile(t, "queues.csv", "pipe;weight;description\nnope;10;ssh\n")
		var r = f.run("/firewall/shaper/queue", "import", file, "confirm=yes")
		wantFailure(t, r, `line 2: there is no pipe "nope"`)
		wantNoMutations(t, f)
	})
}

func TestFirewallCategoryTransferImport(t *testing.T) {
	t.Parallel()
	var f = firewallShaperTransferFake(t)
	var file = firewallRuleTransferFile(t, "categories.csv", "name;color;auto\nweb;ff8800;1\n")
	var r = f.run("/firewall/category", "import", file, "confirm=yes")
	wantFailure(t, r, "unknown columns auto, valid are: name, color")
	wantNoMutations(t, f)

	file = firewallRuleTransferFile(t, "categories.csv", "name;color\nweb;ff8800\n")
	r = f.run("/firewall/category", "import", file, "confirm=yes")
	wantExit(t, r, 0)
	var call = wantOneMutation(t, f, "POST", firewallShaperTransferCategoryUpload)
	wantJSON(t, call, map[string]any{"payload": "name;color\nweb;ff8800\n", "filename": "categories.csv"})
}
