package diagnostics

import (
	"net/http"
	"testing"
)

// memoryTestAnswer is a trimmed system/memory answer of 26.7 (statistics below "vmstat")
const memoryTestAnswer = `{"__version":"2","vmstat":{"malloc-statistics":{"memory":[` +
	`{"type":"CAM periph","in-use":2,"memory-use":384,"requests":20,"size":[16,128]},` +
	`{"type":"bounce","in-use":8197,"memory-use":33574912,"requests":8197,"size":[]}]},` +
	`"memory-zone-statistics":{"zone":[` +
	`{"name":"vm pgcache","size":4096,"limit":0,"used":81665,"free":120,"requests":1941475,"fail":210,"sleep":0,"xdomain":0},` +
	`{"name":"mbuf_jumbo_page","size":4096,"limit":62757,"used":2112,"free":174,"requests":48536,"fail":0,"sleep":1,"xdomain":2}]}}}`

func TestMemoryStats(t *testing.T) {
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/system/memory": healthTestJSON(memoryTestAnswer),
	})
	var stats, err = api.MemoryStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Malloc) != 2 || len(stats.Zones) != 2 {
		t.Fatalf("got %+v", stats)
	}
	var cam = stats.Malloc[0]
	if cam.Name != "CAM periph" || cam.InUse != 2 || cam.Bytes != 384 || cam.Requests != 20 || len(cam.Sizes) != 2 ||
		string(cam.Raw) != `{"type":"CAM periph","in-use":2,"memory-use":384,"requests":20,"size":[16,128]}` {
		t.Errorf("malloc: %+v", cam)
	}
	var jumbo = stats.Zones[1]
	if jumbo.Name != "mbuf_jumbo_page" || jumbo.Size != 4096 || jumbo.Limit != 62757 || jumbo.Used != 2112 || jumbo.Free != 174 ||
		jumbo.Requests != 48536 || jumbo.Sleep != 1 || jumbo.XDomain != 2 || jumbo.Bytes() != 4096*(2112+174) {
		t.Errorf("zone: %+v", jumbo)
	}
	if stats.Zones[0].Fail != 210 {
		t.Errorf("zone: %+v", stats.Zones[0])
	}
}

func TestMemoryStatsShapes(t *testing.T) {
	// the shape the controller expects (and post-processes): no "vmstat" level, type renamed to name, totals added
	var api, _ = healthTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/system/memory": healthTestJSON(`{"malloc-statistics":{"memory":[{"name":"devbuf","in-use":1,` +
			`"memory-use":1024,"requests":3,"size":[64]}],"totals":{"used":1024,"used_fmt":"1,024 k"}}}`),
	})
	var stats, err = api.MemoryStats()
	if err != nil || len(stats.Malloc) != 1 || stats.Malloc[0].Name != "devbuf" || len(stats.Zones) != 0 {
		t.Errorf("got %+v, %v", stats, err)
	}

	for _, answer := range []string{`[]`, `{"__version":"2"}`, `{"vmstat":"x"}`} {
		var failing, _ = healthTestApi(t, map[string]http.HandlerFunc{"GET /api/diagnostics/system/memory": healthTestJSON(answer)})
		if _, err := failing.MemoryStats(); err == nil {
			t.Errorf("want an error for %s", answer)
		}
	}
}
