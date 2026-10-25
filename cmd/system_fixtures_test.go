package cmd

// Fixtures and helpers for the `opn system ...` black-box tests. The canned answers are trimmed copies of what
// OPNsense 26.7 returns (collected with GETs from a live instance). Every identifier is prefixed with sys.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

const (
	sysCronSearchPath   = "/api/cron/settings/search_jobs"
	sysCronGetJobPath   = "/api/cron/settings/get_job"
	sysCronAddPath      = "/api/cron/settings/add_job"
	sysCronSetPath      = "/api/cron/settings/set_job/"
	sysCronDelPath      = "/api/cron/settings/del_job/"
	sysCronTogglePath   = "/api/cron/settings/toggle_job/"
	sysCronReconfigPath = "/api/cron/service/reconfigure"

	sysTunableSearchPath   = "/api/core/tunables/search_item"
	sysTunableAddPath      = "/api/core/tunables/add_item"
	sysTunableSetPath      = "/api/core/tunables/set_item/"
	sysTunableDelPath      = "/api/core/tunables/del_item/"
	sysTunableReconfigPath = "/api/core/tunables/reconfigure"

	sysSyslogGetPath         = "/api/syslog/settings/get"
	sysSyslogSetPath         = "/api/syslog/settings/set"
	sysSyslogSearchDestPath  = "/api/syslog/settings/search_destinations"
	sysSyslogGetDestPath     = "/api/syslog/settings/get_destination/"
	sysSyslogAddDestPath     = "/api/syslog/settings/add_destination"
	sysSyslogSetDestPath     = "/api/syslog/settings/set_destination/"
	sysSyslogDelDestPath     = "/api/syslog/settings/del_destination/"
	sysSyslogToggleDestPath  = "/api/syslog/settings/toggle_destination/"
	sysSyslogStatusPath      = "/api/syslog/service/status"
	sysSyslogRestartPath     = "/api/syslog/service/restart"
	sysSyslogReconfigurePath = "/api/syslog/service/reconfigure"
	sysSyslogStatsPath       = "/api/syslog/service/stats"

	sysBackupProvidersPath = "/api/core/backup/providers"
	sysBackupListPath      = "/api/core/backup/backups/this"
	sysBackupDownloadPath  = "/api/core/backup/download/this"
	sysBackupDiffPath      = "/api/core/backup/diff/this/"
	sysBackupRevertPath    = "/api/core/backup/revert_backup/"
	sysBackupDeletePath    = "/api/core/backup/delete_backup/"

	sysDefaultsGetPath   = "/api/core/defaults/get"
	sysDefaultsResetPath = "/api/core/defaults/factory_defaults"
	sysWizardGetPath     = "/api/core/initial_setup/get"

	sysAnswerStatusOk = `{"status":"ok"}`
)

// --- cron

func sysCronRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "origin": "cron", "enabled": "1", "minutes": "0", "hours": "5", "days": "*", "months": "*",
		"weekdays": "*", "who": "root", "command": "firmware changelog cron", "%command": "Firmware changelog update",
		"parameters": "", "description": "nightly changelog",
	}, overrides)
}

// sysCronGetJob is get_job without uuid: the defaults of a new job with the command options (trimmed)
const sysCronGetJob = `{"job":{"origin":"cron","enabled":"1","minutes":"0","hours":"0","days":"*","months":"*","weekdays":"*","who":"root",` +
	`"command":{"firmware poll":{"value":"Firmware update check","selected":0},` +
	`"firmware changelog cron":{"value":"Firmware changelog update","selected":0},` +
	`"system remote backup":{"value":"Remote backup","selected":0},` +
	`"cron restart":{"value":"Restart Cron service","selected":0}},"parameters":"","description":""}}`

// --- tunables

func sysTunableRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "tunable": "kern.ipc.maxsockbuf", "value": "8388608", "descr": "Maximum socket buffer size",
		"default_value": "4262144", "type": "w",
	}, overrides)
}

// sysTunableBuiltinUuid mimics the md5 key of a not configured built-in row
const sysTunableBuiltinUuid = "e042e8fc0a6f5e0e1b4a4b7c1f7c1a11"

// --- logging

const sysSyslogSettings = `{"syslog":{"general":{"enabled":"1","loglocal":"1","maxpreserve":"31","maxfilesize":""},` +
	`"destinations":{"destination":{}}}}`

func sysDestinationRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "enabled": "0", "transport": "udp4", "%transport": "UDP(4)", "program": "filterlog,unbound",
		"%program": "filter (filterlog), resolver (unbound)", "level": "info,err", "%level": "info, error",
		"facility": "kern,local0", "%facility": "kernel messages, locally used (0)", "hostname": "192.0.2.10",
		"certificate": "", "port": "1514", "rfc5424": "0", "description": "siem",
	}, overrides)
}

// sysDestinationGet is get_destination/<uuid> with option maps (trimmed)
func sysDestinationGet(description string) string {
	return `{"destination":{"enabled":"0",` +
		`"transport":{"udp4":{"value":"UDP(4)","selected":1},"tcp4":{"value":"TCP(4)","selected":0},"udp6":{"value":"UDP(6)","selected":0}},` +
		`"program":{"audit":{"value":"audit (audit)","selected":0},"filterlog":{"value":"filter (filterlog)","selected":1},"unbound":{"value":"resolver (unbound)","selected":1}},` +
		`"level":{"debug":{"value":"debug","selected":0},"info":{"value":"info","selected":1},"err":{"value":"error","selected":1}},` +
		`"facility":{"kern":{"value":"kernel messages","selected":1},"user":{"value":"user-level messages","selected":0},"local0":{"value":"locally used (0)","selected":1}},` +
		`"hostname":"192.0.2.10","certificate":{"":{"value":"None","selected":1},"6add3e24dc0a9":{"value":"Web GUI TLS certificate","selected":0}},` +
		`"port":"1514","rfc5424":"0","description":` + sysQuote(description) + `}}`
}

const sysSyslogStats = `{"total":3,"rowCount":9999,"current":1,"rows":[` +
	`{"#":"1350a2e3","Description":"","SourceName":"dst.program","SourceId":"d_config_changed_event#0","SourceInstance":"/usr/local/sbin/configctl","State":"a","Type":"processed","Number":"228"},` +
	`{"#":"92b5447b","Description":"","SourceName":"global","SourceId":"scratch_buffers_count","SourceInstance":"","State":"a","Type":"queued","Number":"3"},` +
	`{"#":"6e7c40f9","Description":"","SourceName":"destination","SourceId":"d_local_portalauth","SourceInstance":"","State":"a","Type":"dropped","Number":"0"}]}`

// --- backups

const sysBackupProviders = `{"items":{"this":{"description":"This Firewall","dirname":"/conf/backup"}}}`

const (
	sysBackupNewest = "config-1792886044.3812.xml"
	sysBackupMiddle = "config-1792886029.2372.xml"
	sysBackupOldest = "config-1792885909.1543.xml"
)

// sysBackupList is the history in the (2 decimal time) order OPNsense sends it
const sysBackupList = `{"items":[` +
	`{"time":"1792886044.38","time_iso":"2026-10-24T23:54:04+00:00","description":"/api/cron/settings/set_job/807ac3e3 made changes","username":"root@192.168.1.2","filesize":39130,"id":"` + sysBackupNewest + `"},` +
	`{"time":"1792886029.24","time_iso":"2026-10-24T23:53:49+00:00","description":"/api/cron/settings/add_job made changes","username":"root@192.168.1.2","filesize":39101,"id":"` + sysBackupMiddle + `"},` +
	`{"time":"1792885909.15","time_iso":"2026-10-24T23:51:49+00:00","description":"/api/dnsmasq/settings/set_host/5f2e09fc made changes","username":"root@192.168.1.2","filesize":39010,"id":"` + sysBackupOldest + `"}]}`

// sysConfigXml stands in for a downloaded config.xml
const sysConfigXml = "<?xml version=\"1.0\"?>\n<opnsense>\n  <trigger_initial_wizard/>\n  <system><hostname>OPNsense</hostname></system>\n</opnsense>\n"

// sysOnDownload answers a download like OPNsense: octet-stream with a suggested file name
func sysOnDownload(f *fakeOPN, path string, filename string, content string) {
	f.onFunc("GET", path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		_, _ = io.WriteString(w, content)
	})
}

// --- defaults / wizard

const sysDefaults = `{"default_ip":"192.168.1.1"}`

// sysWizard is core/initial_setup/get (option lists trimmed), the password fields are always sent empty
const sysWizard = `{"wizard":{"hostname":"OPNsense","domain":"internal",` +
	`"language":{"cs_CZ":{"value":"Czech","selected":0},"en_US":{"value":"English","selected":1},"de_DE":{"value":"German","selected":0}},` +
	`"dns_servers":{"9.9.9.9":{"value":"9.9.9.9","selected":1},"1.1.1.1":{"value":"1.1.1.1","selected":1}},"dnsallowoverride":"1",` +
	`"unbound":{"enabled":"1","dnssec":"0","dnssecstripped":"0"},` +
	`"timezone":{"Africa/Abidjan":{"value":"Africa/Abidjan","selected":0},"Etc/UTC":{"value":"Etc/UTC","selected":1}},` +
	`"interfaces":{"wan":{"disable":"0","ipv4_type":{"dhcp":{"value":"DHCP","selected":1},"static":{"value":"Static","selected":0},"pppoe":{"value":"PPPoE","selected":0}},` +
	`"spoofmac":"","mtu":"","mss":"","ipaddr":"","gateway":"","dhcphostname":"","pppoe_username":"","pppoe_password":"s3cr3t-pppoe","pppoe_provider":"","blockpriv":"1","blockbogons":"1"},` +
	`"lan":{"ipaddr":"192.168.1.1/24","disable":"0","configure_dhcp":"1"}},` +
	`"deployment_type":{"multiwan":"1","dhcp_dns_registration":"1","maxthreads":"0"},"password":"s3cr3t-root","password_confirm":"s3cr3t-root"}}`

// --- helpers

func sysQuote(s string) string {
	var b, _ = json.Marshal(s)
	return string(b)
}

var sysColumnSeparator = regexp.MustCompile(`\s{2,}`)

// sysTable splits printTable output into cells (columns are separated by at least two spaces)
func sysTable(output string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows = append(rows, sysColumnSeparator.Split(strings.TrimSpace(line), -1))
	}
	return rows
}

// sysWantTable asserts the header and that the first cells of the data rows are wantFirst, in this order
func sysWantTable(t *testing.T, output string, header []string, wantFirst ...string) [][]string {
	t.Helper()
	var rows = sysTable(output)
	if len(rows) == 0 {
		t.Fatalf("no table in output:\n%s", output)
	}
	if strings.Join(rows[0], "|") != strings.Join(header, "|") {
		t.Errorf("table header %q, want %q", rows[0], header)
	}
	var first []string
	for _, row := range rows[1:] {
		if len(row) != len(header) {
			t.Errorf("row has %d cells, header %d: %q", len(row), len(header), row)
		}
		first = append(first, row[0])
	}
	if strings.Join(first, "|") != strings.Join(wantFirst, "|") {
		t.Errorf("table rows %q, want %q\n%s", first, wantFirst, output)
	}
	return rows
}

// sysWantCalled asserts that method path was called at least once
func sysWantCalled(t *testing.T, f *fakeOPN, method string, path string) {
	t.Helper()
	for _, call := range f.calls() {
		if call.Method == method && call.Path == path {
			return
		}
	}
	t.Errorf("%s %s was not called, calls: %v", method, path, f.calls())
}

// sysWantNoCallTo asserts that path was never requested with any method
func sysWantNoCallTo(t *testing.T, f *fakeOPN, pathPrefix string) {
	t.Helper()
	for _, call := range f.calls() {
		if strings.HasPrefix(call.Path, pathPrefix) {
			t.Errorf("unexpected call %s", call)
		}
	}
}

func sysName(args []string) string {
	return strings.ReplaceAll(fmt.Sprint(args), " ", "_")
}
