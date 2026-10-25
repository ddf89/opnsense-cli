package firewall

import (
	"strings"
	"testing"
)

func TestMigrationCount(t *testing.T) {
	var api, requests = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/migration/count_rules":    {ContentType: "application/json", Body: `{"status":"ok","count":12}`},
		"GET /api/firewall/migration/count_outbound": {ContentType: "application/json", Body: `{"status":"ok","count":0}`},
	})
	if count, err := api.MigrationCount(MigrationFilter); err != nil || count != 12 {
		t.Errorf("filter: %d %v", count, err)
	}
	if count, err := api.MigrationCount(MigrationOutbound); err != nil || count != 0 {
		t.Errorf("outbound: %d %v", count, err)
	}
	if _, err := api.MigrationCount("nat"); err == nil {
		t.Errorf("unknown kind must fail")
	}
	if got := requests(); len(got) != 2 {
		t.Errorf("unknown kinds must not send: %+v", got)
	}

	var broken, _ = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/migration/count_rules": {ContentType: "application/json", Body: `{"status":"failed"}`},
	})
	if _, err := broken.MigrationCount(MigrationFilter); err == nil {
		t.Errorf("status failed must be an error")
	}
}

func TestMigrationExport(t *testing.T) {
	var api, requests = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"GET /api/firewall/migration/download_rules":    filterTransferTestCsvAnswer(filterTransferTestCsv),
		"GET /api/firewall/migration/download_outbound": filterTransferTestCsvAnswer(""),
	})
	if content, err := api.MigrationExport(MigrationFilter); err != nil || string(content) != filterTransferTestCsv {
		t.Errorf("filter: %q %v", content, err)
	}
	if content, err := api.MigrationExport(MigrationOutbound); err != nil || len(content) != 0 {
		t.Errorf("outbound: %q %v", content, err)
	}
	for _, request := range requests() {
		if request.Method != "GET" {
			t.Errorf("downloads are GETs: %+v", request)
		}
	}
}

func TestMigrationFlush(t *testing.T) {
	var api, requests = filterTransferTestApi(t, map[string]filterTransferTestAnswer{
		"POST /api/firewall/migration/flush":          {ContentType: "application/json", Body: `{"status":"ok"}`},
		"POST /api/firewall/migration/flush_outbound": {ContentType: "application/json", Body: `{"status":"failed"}`},
	})
	if err := api.MigrationFlush(MigrationFilter); err != nil {
		t.Errorf("filter: %v", err)
	}
	if err := api.MigrationFlush(MigrationOutbound); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("outbound: %v", err)
	}
	if err := api.MigrationFlush(""); err == nil {
		t.Errorf("unknown kind must fail")
	}
	var got = requests()
	if len(got) != 2 || got[0].Method != "POST" || got[0].Path != "/api/firewall/migration/flush" || got[0].Body != "" ||
		got[1].Path != "/api/firewall/migration/flush_outbound" {
		t.Errorf("requests: %+v", got)
	}
}
