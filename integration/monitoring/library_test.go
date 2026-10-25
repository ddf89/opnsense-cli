//go:build integration

package integrationmonitoring

import (
	"errors"
	"strings"
	"testing"
	"time"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
)

func diagApi(t *testing.T) *diagnostics.DiagnosticsApi {
	t.Helper()
	return &diagnostics.DiagnosticsApi{OPNsense: coreApi(t)}
}

func TestHealthReportsLive(t *testing.T) {
	var diag = diagApi(t)
	var reports, raw, err = diag.HealthReports()
	if err != nil {
		t.Fatalf("HealthReports: %v", err)
	}
	if len(raw) == 0 {
		t.Error("no raw answer")
	}
	t.Logf("%d health reports", len(reports))

	// an unknown report is not found (26.7 answers {"set":[],"title":"error"})
	var _, fetchErr = diag.HealthFetch(runPrefix+"-nope-system", 0)
	var notFound *api.NotFoundError
	if !errors.As(fetchErr, &notFound) {
		t.Errorf("want not found for an unknown report, got %v", fetchErr)
	}
	// its CSV export is empty
	if content, err := diag.HealthExportCsv(runPrefix+"-nope-system", 0); err != nil || content != nil {
		t.Errorf("want no export for an unknown report, got %q, %v", content, err)
	}

	if len(reports) == 0 {
		t.Log("no RRD data on this box (collection disabled), the data checks are skipped")
		return
	}
	var series, seriesErr = diag.HealthFetch(reports[0].Metric, 0)
	if seriesErr != nil {
		t.Fatalf("HealthFetch %s: %v", reports[0].Metric, seriesErr)
	}
	if len(series.Rows) > 0 && len(series.Rows[0].Values) != len(series.Columns) {
		t.Errorf("rows and columns differ: %+v", series)
	}
	if content, err := diag.HealthExportCsv(reports[0].Metric, 0); err != nil || (len(series.Rows) > 0 && !strings.HasPrefix(string(content), "iso_time;")) {
		t.Errorf("export: %q, %v", content, err)
	}
}

func TestHealthSettingsLive(t *testing.T) {
	var before = restoreAfter(t)
	var diag = diagApi(t)
	var enabled, _, err = diag.HealthSettings()
	if err != nil {
		t.Fatalf("HealthSettings: %v", err)
	}
	if enabled != (before.HealthEnabled == "1") {
		t.Errorf("enabled %v, raw %q", enabled, before.HealthEnabled)
	}
	// toggle and restore, never applied (no reconfigure)
	if err := diag.HealthSetEnabled(!enabled); err != nil {
		t.Fatalf("HealthSetEnabled: %v", err)
	}
	if now := snapshot(t); now.HealthEnabled == before.HealthEnabled {
		t.Errorf("the setting did not change: %+v", now)
	}
	if err := diag.HealthSetEnabled(enabled); err != nil {
		t.Fatalf("HealthSetEnabled (restore): %v", err)
	}
	if now := snapshot(t); now.HealthEnabled != before.HealthEnabled {
		t.Errorf("the setting was not restored: %+v", now)
	}
}

func TestMemoryStatsLive(t *testing.T) {
	var stats, err = diagApi(t).MemoryStats()
	if err != nil {
		t.Fatalf("MemoryStats: %v", err)
	}
	if len(stats.Malloc) < 10 || len(stats.Zones) < 10 {
		t.Fatalf("want malloc types and zones, got %d / %d", len(stats.Malloc), len(stats.Zones))
	}
	var bytes int64
	for _, item := range stats.Malloc {
		if item.Name == "" {
			t.Errorf("malloc type without name: %s", item.Raw)
		}
		bytes += item.Bytes
	}
	if bytes <= 0 {
		t.Errorf("no malloc memory in use")
	}
	for _, zone := range stats.Zones {
		if zone.Name == "" || zone.Size <= 0 {
			t.Errorf("odd zone: %s", zone.Raw)
		}
	}
}

func TestNetflowLive(t *testing.T) {
	var before = restoreAfter(t)
	var diag = diagApi(t)
	var settings, err = diag.NetflowSettings()
	if err != nil {
		t.Fatalf("NetflowSettings: %v", err)
	}
	if strings.Join(settings.Interfaces, ",") != before.Interfaces || settings.Version != before.Version ||
		settings.ActiveTimeout != before.ActiveTimeout || strings.Join(settings.Targets, ",") != before.Targets {
		t.Errorf("settings %+v, raw %+v", settings, before)
	}
	if _, found := settings.InterfaceOptions["lan"]; !found {
		t.Errorf("lan is not offered: %v", settings.InterfaceOptions)
	}
	if _, err := diag.NetflowStatus(); err != nil {
		t.Errorf("NetflowStatus: %v", err)
	}
	if _, _, err := diag.NetflowEnabled(); err != nil {
		t.Errorf("NetflowEnabled: %v", err)
	}
	if _, err := diag.NetflowCache(); err != nil {
		t.Errorf("NetflowCache: %v", err)
	}

	// harmless changes, never applied: timeouts, version and the capture interface lan without targets
	var version = map[string]string{"v9": "v5", "v5": "v9"}[settings.Version]
	var active, inactive = "1234", "42"
	var lan = []string{"lan"}
	if err := diag.NetflowSetSettings(diagnostics.NetflowSettingsFields{Version: &version, ActiveTimeout: &active,
		InactiveTimeout: &inactive, Interfaces: &lan}); err != nil {
		t.Fatalf("NetflowSetSettings: %v", err)
	}
	var now = snapshot(t)
	if now.Version != version || now.ActiveTimeout != active || now.InactiveTimeout != inactive || now.Interfaces != "lan" ||
		now.Targets != before.Targets || now.Collect != before.Collect {
		t.Errorf("after set: %+v", now)
	}
	var restoredInterfaces = settings.Interfaces
	if err := diag.NetflowSetSettings(diagnostics.NetflowSettingsFields{Version: &settings.Version, ActiveTimeout: &settings.ActiveTimeout,
		InactiveTimeout: &settings.InactiveTimeout, Interfaces: &restoredInterfaces}); err != nil {
		t.Fatalf("NetflowSetSettings (restore): %v", err)
	}
	if now := snapshot(t); now != before {
		t.Errorf("not restored: %+v, want %+v", now, before)
	}

	// an invalid collector is a validation error and changes nothing
	var targets = []string{"999.0.2.1:2055"}
	var validation *api.ValidationError
	if err := diag.NetflowSetSettings(diagnostics.NetflowSettingsFields{Targets: &targets}); !errors.As(err, &validation) {
		t.Errorf("want a validation error, got %v", err)
	} else {
		t.Logf("validation: %v", validation)
	}
	if now := snapshot(t); now != before {
		t.Errorf("a failed set changed the settings: %+v", now)
	}
}

func TestNetflowReconfigureLive(t *testing.T) {
	var before = snapshot(t)
	if !netflowIdle(t, before) {
		t.Skip("NetFlow is configured on this box, reconfigure is not run live")
	}
	if err := diagApi(t).NetflowReconfigure(); err != nil {
		t.Errorf("NetflowReconfigure: %v", err)
	}
	if status, err := diagApi(t).NetflowStatus(); err != nil || status.Active {
		t.Errorf("want NetFlow still inactive, got %+v, %v", status, err)
	}
}

func TestInsightLive(t *testing.T) {
	var diag = diagApi(t)
	var metadata, err = diag.InsightMetadata()
	if err != nil {
		t.Fatalf("InsightMetadata: %v", err)
	}
	for _, provider := range []string{diagnostics.InsightInterfaceTotals, diagnostics.InsightDstPortTotals,
		diagnostics.InsightSourceAddrTotals, diagnostics.InsightSourceAddrDetails} {
		if len(metadata.Resolutions[provider]) == 0 {
			t.Errorf("no resolutions for %s: %+v", provider, metadata.Resolutions)
		}
	}
	var interfaces, interfacesErr = diag.InsightInterfaces()
	if interfacesErr != nil || len(interfaces) == 0 {
		t.Errorf("InsightInterfaces: %v, %v", interfaces, interfacesErr)
	}
	if protocols, err := diag.InsightProtocols(); err != nil || protocols["6"] != "tcp" || protocols["17"] != "udp" {
		t.Errorf("InsightProtocols: %v", err)
	}
	if services, err := diag.InsightServices(); err != nil || services["443"] != "https" {
		t.Errorf("InsightServices: %v", err)
	}

	var to = time.Now()
	var from = to.Add(-24 * time.Hour)
	for _, query := range []diagnostics.InsightTopQuery{
		{Provider: diagnostics.InsightInterfaceTotals, Fields: []string{"if", "direction"}, Measure: "octets"},
		{Provider: diagnostics.InsightDstPortTotals, Fields: []string{"dst_port", "protocol"}, Measure: "packets",
			Filters: []diagnostics.InsightFilter{{Field: "dst_port", Value: "443"}}},
		{Provider: diagnostics.InsightSourceAddrTotals, Fields: []string{"src_addr"}},
		{Provider: diagnostics.InsightSourceAddrDetails, Fields: []string{"service_port", "protocol", "if", "src_addr", "dst_addr"},
			Filters: []diagnostics.InsightFilter{{Field: "src_addr", Value: "192.0.2.1"}}},
	} {
		query.From, query.To, query.MaxHits = from, to, 10
		var rows, err = diag.InsightTop(query)
		if err != nil {
			t.Errorf("InsightTop %s: %v", query.Provider, err)
		}
		t.Logf("%s: %d rows", query.Provider, len(rows))
	}
	if _, err := diag.InsightTimeseries(diagnostics.InsightInterfaceTotals, "bps", from, to, 300, []string{"if", "direction"}); err != nil {
		t.Errorf("InsightTimeseries: %v", err)
	}
	if _, err := diag.InsightExportCsv(diagnostics.InsightInterfaceTotals, from, to, 300); err != nil {
		t.Errorf("InsightExportCsv: %v", err)
	}
}
