package unbound

import (
	"reflect"
	"strings"
	"testing"
)

func TestStatisticsTotals(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{"GET /api/unbound/overview/totals/5": `{"total":10,"blocklist_size":2,"passed":8,
		"resolved":{"total":6,"pcnt":"60.00"},"blocked":{"total":2,"pcnt":"20.00"},"local":{"total":0,"pcnt":0},"start_time":1761400000,
		"top":{"a.example":{"total":3,"pcnt":"37.50"},"b.example":{"total":5,"pcnt":"62.50"},"c.example":{"total":3,"pcnt":"37.50"}},
		"top_blocked":{"ads.example":{"total":2,"pcnt":"100.00","blocklist":"AdGuard List","category":"General Blocklists","latest_policy_uuid":"p1"}}}`})
	var totals, err = api.StatisticsTotals(5)
	if err != nil {
		t.Fatal(err)
	}
	if !totals.Available || totals.Total != "10" || totals.Local.Percent != "0" || totals.Resolved.Percent != "60.00" || totals.StartTime.Int() != 1761400000 {
		t.Errorf("unexpected totals %+v", totals)
	}
	var top []string
	for _, domain := range totals.Top {
		top = append(top, domain.Domain)
	}
	if !reflect.DeepEqual(top, []string{"b.example", "a.example", "c.example"}) {
		t.Errorf("top is not sorted by count then name: %v", top)
	}
	if len(totals.TopBlocked) != 1 || totals.TopBlocked[0].Blocklist != "AdGuard List" || totals.TopBlocked[0].LatestPolicyUuid != "p1" {
		t.Errorf("unexpected top blocked %+v", totals.TopBlocked)
	}
	if (*requests)[0] != "GET /api/unbound/overview/totals/5" {
		t.Errorf("unexpected request %v", *requests)
	}
	if _, err := api.StatisticsTotals(0); err == nil {
		t.Error("top 0: want an error")
	}
}

func TestStatisticsTotalsWithoutStatistics(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/overview/totals/10": `[]`})
	var totals, err = api.StatisticsTotals(10)
	if err != nil || totals.Available {
		t.Errorf("want unavailable totals, got %+v, %v", totals, err)
	}
}

func TestStatisticsTotalsWithoutBlockedDomains(t *testing.T) {
	// PHP re-encodes the empty top_blocked map of the qstats script as []
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/overview/totals/10": `{"total":3,"blocklist_size":0,"passed":3,
		"resolved":{"total":3,"pcnt":"100.00"},"blocked":{"total":0,"pcnt":0},"local":{"total":0,"pcnt":0},"start_time":1761400000,
		"top":{"a.example":{"total":3,"pcnt":"100.00"}},"top_blocked":[]}`})
	var totals, err = api.StatisticsTotals(10)
	if err != nil || !totals.Available || len(totals.Top) != 1 || len(totals.TopBlocked) != 0 {
		t.Errorf("want totals with one top domain and no blocked ones, got %+v, %v", totals, err)
	}
}

func TestStatisticsHistory(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/overview/rolling/1/0":  `{"1761400060":{"total":2,"passed":2,"blocked":0,"dropped":0,"resolved":1,"local":0,"cached":1},"1761400000":{"total":1,"passed":1,"blocked":0,"dropped":0,"resolved":1,"local":0,"cached":0}}`,
		"GET /api/unbound/overview/rolling/24/0": `[]`,
	})
	var intervals, err = api.StatisticsHistory(1)
	if err != nil || len(intervals) != 2 || intervals[0].Start != 1761400000 || intervals[1].Cached != "1" {
		t.Errorf("StatisticsHistory: %+v, %v", intervals, err)
	}
	if intervals, err := api.StatisticsHistory(24); err != nil || len(intervals) != 0 {
		t.Errorf("without statistics: %+v, %v", intervals, err)
	}
	if _, err := api.StatisticsHistory(2); err == nil {
		t.Error("hours 2: want an error")
	}
}

func TestStatisticsQueries(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/overview/search_queries": `{"total":1,"rowCount":1,"current":1,"rows":[
		{"uuid":null,"time":1761400000,"client":"192.168.1.10","family":"ip4","type":"A","domain":"example.com","action":"Pass","source":"Recursion",
		 "blocklist":null,"rcode":"NOERROR","resolve_time_ms":12,"dnssec_status":"Unchecked","ttl":300,"policy":"","status":0}]}`})
	var queries, raws, err = api.StatisticsQueries("")
	if err != nil || len(queries) != 1 || len(raws) != 1 {
		t.Fatalf("StatisticsQueries: %+v, %v", queries, err)
	}
	if queries[0].Domain != "example.com" || queries[0].ResolveTimeMs != "12" || queries[0].Time.Int() != 1761400000 {
		t.Errorf("unexpected query %+v", queries[0])
	}
}

func TestStatisticsReset(t *testing.T) {
	var api, requests = newRecordTestApi(t, map[string]string{"POST /api/unbound/overview/reset": `{"status":"OK\n\n"}`})
	if err := api.StatisticsReset(); err != nil {
		t.Fatal(err)
	}
	if (*requests)[0] != "POST /api/unbound/overview/reset {}" {
		t.Errorf("unexpected request %v", *requests)
	}
}

func TestCounters(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/diagnostics/stats": `{"status":"ok","data":{
		"total":{"num":{"queries":"18","dnscrypt":{"crypted":"0"}}},"time":{"up":"100.5"},
		"num":{"query":{"type":{"A":"7"},"tcp":{"__value__":"2","out":"1"}}},
		"histogram":[{"from":[0,0],"to":[0,1],"value":"3"}]}}`})
	var counters, err = api.Counters()
	if err != nil {
		t.Fatal(err)
	}
	var want = map[string]string{"total.num.queries": "18", "total.num.dnscrypt.crypted": "0", "time.up": "100.5",
		"num.query.type.A": "7", "num.query.tcp": "2", "num.query.tcp.out": "1"}
	if !reflect.DeepEqual(counters, want) {
		t.Errorf("counters:\n got  %v\n want %v", counters, want)
	}
}

func TestDiagnosticsDumps(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{
		"GET /api/unbound/diagnostics/dumpcache":      `{"status":"ok","data":[{"host":"example.com.","ttl":"300","type":"IN","rrtype":"A","value":"192.0.2.1"}]}`,
		"GET /api/unbound/diagnostics/listlocaldata":  `{"status":"ok","data":[{"name":"web.lan.","ttl":"3600","type":"IN","rrtype":"A","value":"10.0.0.1"}]}`,
		"GET /api/unbound/diagnostics/listlocalzones": `{"status":"ok","data":[{"zone":"lan.","type":"transparent"}]}`,
		"GET /api/unbound/diagnostics/listinsecure":   `{"status":"ok","data":[""]}`,
		"GET /api/unbound/diagnostics/dumpinfra":      `{"status":"failed"}`,
	})
	if entries, err := api.CacheDump(); err != nil || len(entries) != 1 || entries[0].Name != "example.com." || entries[0].Value != "192.0.2.1" {
		t.Errorf("CacheDump: %+v, %v", entries, err)
	}
	if entries, err := api.LocalData(); err != nil || len(entries) != 1 || entries[0].Name != "web.lan." {
		t.Errorf("LocalData: %+v, %v", entries, err)
	}
	if zones, err := api.LocalZones(); err != nil || !reflect.DeepEqual(zones, []LocalZone{{"lan.", "transparent"}}) {
		t.Errorf("LocalZones: %+v, %v", zones, err)
	}
	if zones, err := api.InsecureZones(); err != nil || len(zones) != 0 {
		t.Errorf("InsecureZones: %+v, %v", zones, err)
	}
	if _, err := api.InfraDump(); err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("InfraDump: want the failure, got %v", err)
	}
}

func TestInfraDump(t *testing.T) {
	var api, _ = newRecordTestApi(t, map[string]string{"GET /api/unbound/diagnostics/dumpinfra": `{"status":"ok","data":[{"ip":"192.0.2.53","host":"org.","ttl":"250","rtt":"594","lame":true}]}`})
	var entries, err = api.InfraDump()
	if err != nil || len(entries) != 1 || !entries[0].Lame || entries[0].Stats["rtt"] != "594" || entries[0].Host != "org." {
		t.Errorf("InfraDump: %+v, %v", entries, err)
	}
}
