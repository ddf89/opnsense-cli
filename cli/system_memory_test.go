package cli

import (
	"strings"
	"testing"
)

const systemMemoryPath = "/api/diagnostics/system/memory"

// systemMemoryTestAnswer is a trimmed system/memory answer of 26.7
const systemMemoryTestAnswer = `{"__version":"2","vmstat":{"malloc-statistics":{"memory":[` +
	`{"type":"CAM periph","in-use":2,"memory-use":384,"requests":20,"size":[16,128]},` +
	`{"type":"bounce","in-use":8197,"memory-use":33574912,"requests":8197,"size":[]},` +
	`{"type":"devbuf","in-use":4405,"memory-use":7355312,"requests":94445,"size":[16,32,64]}]},` +
	`"memory-zone-statistics":{"zone":[` +
	`{"name":"vm pgcache","size":4096,"limit":0,"used":81665,"free":120,"requests":1941475,"fail":210,"sleep":0,"xdomain":0},` +
	`{"name":"mbuf_jumbo_page","size":4096,"limit":62757,"used":2112,"free":174,"requests":48536,"fail":0,"sleep":1,"xdomain":0},` +
	`{"name":"mbuf","size":256,"limit":0,"used":3000,"free":1000,"requests":900000,"fail":0,"sleep":0,"xdomain":0}]}}}`

func TestSystemMemoryPrint(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", systemMemoryPath, 200, systemMemoryTestAnswer)

	var r = f.run("/system/memory", "print")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "TYPE") || !strings.HasPrefix(lines[1], "bounce") ||
		!strings.HasPrefix(lines[2], "devbuf") || !strings.HasPrefix(lines[3], "CAM periph") {
		t.Errorf("want the biggest first:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "bounce      8197    32.0 MiB  8197      -", "CAM periph  2       384 B     20        16,128")
	wantContains(t, "stderr", r.stderr, "39.0 MiB in use by 3 malloc types")

	r = f.run("/system/memory", "print", "sort=requests", "limit=1")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "devbuf")
	wantNotContains(t, "stdout", r.stdout, "bounce", "CAM")
	wantContains(t, "stderr", r.stderr, "in use by 3 malloc types") // the total of all matching rows

	r = f.run("/system/memory", "print", "search=CAM", "json")
	wantExit(t, r, 0)
	if strings.TrimSpace(r.stdout) != `{"type":"CAM periph","in-use":2,"memory-use":384,"requests":20,"size":[16,128]}` {
		t.Errorf("json: %s", r.stdout)
	}

	r = f.run("/system/memory", "print", "sort=name")
	wantExit(t, r, 0)
	lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if !strings.HasPrefix(lines[1], "bounce") || !strings.HasPrefix(lines[2], "CAM periph") || !strings.HasPrefix(lines[3], "devbuf") {
		t.Errorf("want sorted by name:\n%s", r.stdout)
	}
	wantNoMutations(t, f)
}

func TestSystemMemoryPrintZones(t *testing.T) {
	var f = newFakeOPN(t)
	f.on("GET", systemMemoryPath, 200, systemMemoryTestAnswer)

	var r = f.run("/system/memory", "print", "zone")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ZONE") || !strings.HasPrefix(lines[1], "vm pgcache") ||
		!strings.HasPrefix(lines[2], "mbuf_jumbo_page") || !strings.HasPrefix(lines[3], "mbuf ") {
		t.Errorf("want the biggest first:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "SIZE  LIMIT  USED", "mbuf_jumbo_page  4096  62757  2112   174   8.9 MiB")
	wantContains(t, "stderr", r.stderr, "held by 3 zones")

	r = f.run("/system/memory", "print", "zone", "search=MBUF", "sort=free")
	wantExit(t, r, 0)
	lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "mbuf ") || !strings.HasPrefix(lines[2], "mbuf_jumbo_page") {
		t.Errorf("want the mbuf zones by free:\n%s", r.stdout)
	}

	r = f.run("/system/memory", "print", "zone", "sort=fail", "limit=1", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `{"name":"vm pgcache"`)
	if strings.Count(r.stdout, "\n") != 1 {
		t.Errorf("json: %s", r.stdout)
	}
}

func TestSystemMemoryErrors(t *testing.T) {
	var f = newFakeOPN(t)
	wantFailure(t, f.run("/system/memory", "print", "sort=fail"), "sort=fail only with zone")
	wantFailure(t, f.run("/system/memory", "print", "sort=bogus"), "sort")
	wantFailure(t, f.run("/system/memory", "print", "limit=-1"), "limit")
	wantNoCalls(t, f)

	f.on("GET", systemMemoryPath, 200, `[]`)
	wantFailure(t, f.run("/system/memory", "print"), "no memory statistics")
}
