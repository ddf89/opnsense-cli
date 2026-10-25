package diagnostics

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const insightTestMetadata = `{"last_sync":1761400000,"aggregators":{"FlowInterfaceTotals":{"resolutions":[300,30,3600,86400]},` +
	`"FlowDstPortTotals":{"resolutions":[300,3600,86400]},"FlowSourceAddrDetails":{"resolutions":[86400]},` +
	`"FlowSourceAddrTotals":{"resolutions":[300,3600,86400]}}}`

func TestInsightMetadataAndMaps(t *testing.T) {
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/networkinsight/getMetadata":   healthTestJSON(insightTestMetadata),
		"GET /api/diagnostics/networkinsight/getInterfaces": healthTestJSON(`{"vtnet1":"wan","vtnet0":"lan","lo0":"Loopback"}`),
		"GET /api/diagnostics/networkinsight/getProtocols":  healthTestJSON(`{"0":"ip","6":"tcp","17":"udp"}`),
		"GET /api/diagnostics/networkinsight/getServices":   healthTestJSON(`[]`),
	})
	var metadata, err = api.InsightMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.LastSync.Equal(time.Unix(1761400000, 0)) || !reflect.DeepEqual(metadata.Resolutions[InsightInterfaceTotals], []int{30, 300, 3600, 86400}) ||
		len(metadata.Resolutions) != 4 {
		t.Errorf("metadata: %+v", metadata)
	}
	if interfaces, err := api.InsightInterfaces(); err != nil || interfaces["vtnet0"] != "lan" || len(interfaces) != 3 {
		t.Errorf("interfaces: %v, %v", interfaces, err)
	}
	if protocols, err := api.InsightProtocols(); err != nil || protocols["6"] != "tcp" {
		t.Errorf("protocols: %v, %v", protocols, err)
	}
	if services, err := api.InsightServices(); err != nil || len(services) != 0 {
		t.Errorf("services: %v, %v", services, err)
	}

	var fresh, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/networkinsight/getMetadata": healthTestJSON(`{"last_sync":0,"aggregators":{}}`),
	})
	if metadata, err := fresh.InsightMetadata(); err != nil || !metadata.LastSync.IsZero() {
		t.Errorf("fresh: %+v, %v", metadata, err)
	}
}

func TestInsightTop(t *testing.T) {
	var from, to = time.Unix(1761390000, 0), time.Unix(1761400000, 0)
	var api, calls = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/networkinsight/top/FlowDstPortTotals/1761390000/1761400000/dst_port,protocol/octets/2": healthTestJSON(
			`[{"dst_port":443,"protocol":6,"total":123456,"last_seen":1761399999,"label":"https (tcp)","last_seen_str":"2026-10-25 13:46:39"},` +
				`{"dst_port":53,"protocol":17,"total":2048.5,"last_seen":1761399000,"label":"domain (udp)"},` +
				`{"total":99,"dst_port":"","protocol":"","last_seen":"","label":"","last_seen_str":""}]`),
		"GET /api/diagnostics/networkinsight/top/FlowSourceAddrTotals/1761390000/1761400000/src_addr/packets/25": healthTestJSON(`[]`),
	})
	var rows, err = api.InsightTop(InsightTopQuery{Provider: InsightDstPortTotals, From: from, To: to, Fields: []string{"dst_port", "protocol"},
		MaxHits: 2, Filters: []InsightFilter{{"if", "vtnet0"}, {"dst_port", "443"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[0].Fields["dst_port"] != "443" || rows[0].Fields["protocol"] != "6" || rows[0].Total != 123456 || rows[0].Label != "https (tcp)" ||
		!rows[0].LastSeen.Equal(time.Unix(1761399999, 0)) || rows[0].Rest {
		t.Errorf("first row: %+v", rows[0])
	}
	if rows[1].Total != 2048.5 || rows[1].Rest {
		t.Errorf("second row: %+v", rows[1])
	}
	if !rows[2].Rest || rows[2].Total != 99 || !rows[2].LastSeen.IsZero() {
		t.Errorf("rest row: %+v", rows[2])
	}
	var query = calls()[0].Query
	if query.Get("filter_field") != "if,dst_port" || query.Get("filter_value") != "vtnet0,443" {
		t.Errorf("filters: %v", query)
	}

	rows, err = api.InsightTop(InsightTopQuery{Provider: InsightSourceAddrTotals, From: from, To: to, Fields: []string{"src_addr"},
		Measure: "packets", MaxHits: 25})
	if err != nil || len(rows) != 0 || len(calls()[1].Query) != 0 {
		t.Errorf("empty: %+v, %v, %v", rows, err, calls()[1])
	}

	if _, err := api.InsightTop(InsightTopQuery{Provider: InsightSourceAddrTotals, Fields: []string{"src_addr"},
		Filters: []InsightFilter{{"src_addr", "a,b"}}}); err == nil || !strings.Contains(err.Error(), "comma") {
		t.Errorf("want an error for a comma, got %v", err)
	}
	if _, err := api.InsightTop(InsightTopQuery{Provider: InsightSourceAddrTotals}); err == nil {
		t.Error("want an error without fields")
	}
	if len(calls()) != 2 {
		t.Errorf("invalid queries must not be sent: %v", calls())
	}
}

func TestInsightTimeseries(t *testing.T) {
	var from, to = time.Unix(1761390000, 0), time.Unix(1761400000, 0)
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/networkinsight/timeserie/FlowInterfaceTotals/bps/1761390000/1761400000/300/if,direction": healthTestJSON(
			`[{"key":"vtnet0,in","values":[[1761390000000,1200.5],[1761390300000,0]],"interface":"lan","direction":"in"},` +
				`{"key":"vtnet0,out","values":[[1761390000000,800],[1761390300000,null]],"interface":"lan","direction":"out"}]`),
	})
	var series, err = api.InsightTimeseries(InsightInterfaceTotals, "bps", from, to, 300, []string{"if", "direction"})
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 2 || series[0].Key != "vtnet0,in" || series[0].Interface != "lan" || series[0].Direction != "in" ||
		len(series[0].Points) != 2 || series[0].Points[0].Value != 1200.5 || !series[0].Points[1].Time.Equal(time.Unix(1761390300, 0)) ||
		series[1].Points[1].Value != 0 {
		t.Errorf("got %+v", series)
	}
}

func TestInsightExportCsv(t *testing.T) {
	var from, to = time.Unix(1761390000, 0), time.Unix(1761400000, 0)
	var csv = "if,direction,octets,packets,mtime\nvtnet0,in,1200,10,2026/10/25 13:40:00\n"
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/networkinsight/export/FlowInterfaceTotals/1761390000/1761400000/300": healthTestRaw(200, "application/octet-stream", csv),
		"GET /api/diagnostics/networkinsight/export/FlowInterfaceTotals/1761390000/1761400000/30":  healthTestRaw(200, "application/octet-stream", "\n\n"),
	})
	if content, err := api.InsightExportCsv(InsightInterfaceTotals, from, to, 300); err != nil || string(content) != csv {
		t.Errorf("got %q, %v", content, err)
	}
	if content, err := api.InsightExportCsv(InsightInterfaceTotals, from, to, 30); err != nil || content != nil {
		t.Errorf("want no content, got %q, %v", content, err)
	}
}
