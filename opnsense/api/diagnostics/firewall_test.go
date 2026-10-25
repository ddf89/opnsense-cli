package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// firewallTestServer records requests and answers them with handler
type firewallTestServer struct {
	mu       sync.Mutex
	requests []*url.URL
}

func (s *firewallTestServer) record(r *http.Request) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.URL)
	return len(s.requests)
}

func (s *firewallTestServer) urls() []*url.URL {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*url.URL(nil), s.requests...)
}

func firewallTestApi(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) (*DiagnosticsApi, *firewallTestServer) {
	t.Helper()
	var recorder = &firewallTestServer{}
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, recorder.record(r))
	}))
	t.Cleanup(server.Close)

	var baseUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl, ApiKey: "k", ApiSecret: "s"}}, recorder
}

// firewallTestRecord builds a log record like read_log.py does, port distinguishes records
func firewallTestRecord(port int, digest string) string {
	return fmt.Sprintf(`{"rulenr":"86","subrulenr":"","anchorname":"","rid":"3345e049","interface":"vtnet0","reason":"match","action":"pass","dir":"in","ipversion":"4","protonum":"6","protoname":"tcp","length":"60","src":"192.168.1.2","dst":"192.168.1.1","srcport":"%d","dstport":"443","tcpflags":"S","__timestamp__":"2026-10-25T00:03:19","__host__":"OPNsense.internal","__digest__":"%s","__spec__":["rulenr","subrulenr","anchorname","rid","interface","reason","action","dir","ipversion","protonum","protoname","length","src","dst","srcport","dstport","tcpflags"],"label":"anti-lockout rule"}`, port, digest)
}

func firewallTestRecords(records ...string) string {
	return "[" + strings.Join(records, ",") + "]"
}

func firewallTestPorts(entries []FirewallLogEntry) string {
	var ports []string
	for _, entry := range entries {
		ports = append(ports, entry.SrcPort)
	}
	return strings.Join(ports, ",")
}

func TestFirewallLog(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		_, _ = w.Write([]byte(firewallTestRecords(firewallTestRecord(3, "d3"), firewallTestRecord(2, "d2"), firewallTestRecord(1, "d1"))))
	})

	var entries, found, err = api.FirewallLog(3, "")
	if err != nil {
		t.Fatal(err)
	}
	if found || firewallTestPorts(entries) != "3,2,1" {
		t.Errorf("entries = %s, found = %v", firewallTestPorts(entries), found)
	}
	var first = entries[0]
	if first.Timestamp != "2026-10-25T00:03:19" || first.Host != "OPNsense.internal" || first.Digest != "d3" ||
		first.Action != "pass" || first.Dir != "in" || first.Interface != "vtnet0" || first.ProtoName != "tcp" ||
		first.Src != "192.168.1.2" || first.DstPort != "443" || first.Label != "anti-lockout rule" || first.RuleNr != "86" ||
		first.TcpFlags != "S" || len(first.Spec) != 17 {
		t.Errorf("first = %+v", first)
	}
	if !strings.Contains(string(first.Raw), `"subrulenr":""`) {
		t.Errorf("Raw = %s", first.Raw)
	}

	// the digest record is included by OPNsense and removed
	entries, found, err = api.FirewallLog(0, "d1")
	if err != nil || !found || firewallTestPorts(entries) != "3,2" {
		t.Errorf("since d1: %s %v %v", firewallTestPorts(entries), found, err)
	}
	entries, found, err = api.FirewallLog(0, "d3")
	if err != nil || !found || len(entries) != 0 {
		t.Errorf("since d3: %s %v %v", firewallTestPorts(entries), found, err)
	}
	entries, found, err = api.FirewallLog(0, "gone")
	if err != nil || found || len(entries) != 3 {
		t.Errorf("since unknown: %s %v %v", firewallTestPorts(entries), found, err)
	}

	var urls = server.urls()
	if urls[0].Path != "/api/diagnostics/firewall/log" || urls[0].RawQuery != "limit=3" {
		t.Errorf("first request %s", urls[0])
	}
	if urls[1].Query().Get("limit") != "1000" || urls[1].Query().Get("digest") != "d1" {
		t.Errorf("since request %s", urls[1])
	}
}

func TestFirewallLogErrors(t *testing.T) {
	var api, _ = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1:
			_, _ = w.Write([]byte(`null`))
		case 2:
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"status":401,"message":"Authentication Failed"}`))
		default:
			_, _ = w.Write([]byte(`{"not":"a list"}`))
		}
	})
	if _, _, err := api.FirewallLog(5, ""); err == nil {
		t.Errorf("null answer accepted")
	}
	var _, _, err = api.FirewallLog(5, "")
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 {
		t.Errorf("err = %v", err)
	}
	if _, _, err := api.FirewallLog(5, ""); err == nil {
		t.Errorf("object answer accepted")
	}
}

func TestFirewallLogEntryKey(t *testing.T) {
	var logEntry, streamEntry FirewallLogEntry
	if err := json.Unmarshal([]byte(firewallTestRecord(1, "fromlog")), &logEntry); err != nil {
		t.Fatal(err)
	}
	// the stream sends another digest (md5 including the newline) and a counter
	var streamRecord = strings.Replace(firewallTestRecord(1, "fromstream"), `"label"`, `"counter":7,"label"`, 1)
	if err := json.Unmarshal([]byte(streamRecord), &streamEntry); err != nil {
		t.Fatal(err)
	}
	if logEntry.Key() != streamEntry.Key() {
		t.Errorf("keys differ:\n%s\n%s", logEntry.Key(), streamEntry.Key())
	}
	if streamEntry.Fields()["counter"] != "7" {
		t.Errorf("Fields() = %v", streamEntry.Fields())
	}

	var other FirewallLogEntry
	_ = json.Unmarshal([]byte(firewallTestRecord(2, "fromlog")), &other)
	if other.Key() == logEntry.Key() {
		t.Errorf("different records share a key")
	}

	// records without spec still get a stable key ignoring digest, counter and label
	var a, b FirewallLogEntry
	_ = json.Unmarshal([]byte(`{"__timestamp__":"t","src":"1","__digest__":"x","label":"l"}`), &a)
	_ = json.Unmarshal([]byte(`{"__timestamp__":"t","src":"1","__digest__":"y","counter":3}`), &b)
	if a.Key() != b.Key() {
		t.Errorf("keys without spec differ: %s / %s", a.Key(), b.Key())
	}
}

func TestFirewallLogFiltersAndNames(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		switch r.URL.Path {
		case "/api/diagnostics/firewall/log_filters":
			_, _ = w.Write([]byte(`{"action":["pass","block","rdr","nat","binat"],"interface_name":["lan","Loopback","wan"],"dir":["in","out"]}`))
		case "/api/diagnostics/interface/getInterfaceNames":
			_, _ = w.Write([]byte(`{"vtnet0":"LAN","lo0":"Loopback","vtnet1":"WAN"}`))
		}
	})

	var filters, err = api.FirewallLogFilters()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(filters.Action, ",") != "pass,block,rdr,nat,binat" || strings.Join(filters.InterfaceName, ",") != "lan,Loopback,wan" ||
		strings.Join(filters.Dir, ",") != "in,out" {
		t.Errorf("filters = %+v", filters)
	}

	var names, namesErr = api.FirewallInterfaceNames()
	if namesErr != nil || names["vtnet0"] != "LAN" || len(names) != 3 {
		t.Errorf("names = %v, %v", names, namesErr)
	}
	if len(server.urls()) != 2 {
		t.Errorf("requests = %v", server.urls())
	}
}

func TestFirewallStats(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if n == 1 {
			_, _ = w.Write([]byte(`[{"label":"lan","value":1262},{"label":"wan","value":769}]`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})

	var stats, err = api.FirewallStats("", 0)
	if err != nil || len(stats) != 2 || stats[0] != (FirewallStat{"lan", 1262}) {
		t.Errorf("stats = %v, %v", stats, err)
	}
	stats, err = api.FirewallStats("protoname", 200)
	if err != nil || stats == nil || len(stats) != 0 {
		t.Errorf("stats = %#v, %v", stats, err)
	}

	var urls = server.urls()
	if urls[0].Path != "/api/diagnostics/firewall/stats" || urls[0].RawQuery != "" {
		t.Errorf("default request %s", urls[0])
	}
	if urls[1].Query().Get("group_by") != "protoname" || urls[1].Query().Get("limit") != "200" {
		t.Errorf("request %s", urls[1])
	}
}

// firewallTestSSE writes server-sent events like OPNsense: records as message events and keepalives
func firewallTestSSE(w http.ResponseWriter, records ...string) {
	w.Header().Set("Content-Type", "text/event-stream;charset=UTF-8")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, "event: keepalive\ndata:\n\n")
	for _, record := range records {
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", record)
	}
	_, _ = io.WriteString(w, "event: other\ndata: {\"ignored\":true}\n\n")
	_, _ = io.WriteString(w, "event: keepalive\ndata:\n\n")
}

func TestFirewallLogStream(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		firewallTestSSE(w, firewallTestRecord(1, "s1"), firewallTestRecord(2, "s2"))
	})

	var entries []FirewallLogEntry
	var err = api.FirewallLogStream(context.Background(), func(entry FirewallLogEntry) error {
		entries = append(entries, entry)
		return nil
	})
	if !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF at end of stream", err)
	}
	if firewallTestPorts(entries) != "1,2" || entries[1].Digest != "s2" {
		t.Errorf("entries = %s", firewallTestPorts(entries))
	}
	if server.urls()[0].Path != "/api/diagnostics/firewall/stream_log" {
		t.Errorf("request %s", server.urls()[0])
	}
}

func TestFirewallLogStreamInvalidRecord(t *testing.T) {
	var api, _ = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		firewallTestSSE(w, `{"broken"`)
	})
	var err = api.FirewallLogStream(context.Background(), func(FirewallLogEntry) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "could not decode firewall log event") {
		t.Errorf("err = %v", err)
	}
}

func TestFirewallLogFollowPoll(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, n int) {
		var answer string
		switch n {
		case 1: // since d0: two new records, newest first, including d0
			answer = firewallTestRecords(firewallTestRecord(2, "d2"), firewallTestRecord(1, "d1"), firewallTestRecord(0, "d0"))
		case 2: // nothing new
			answer = firewallTestRecords(firewallTestRecord(2, "d2"))
		case 3: // transient error, retried
			w.WriteHeader(502)
			answer = "Bad Gateway"
		default:
			answer = firewallTestRecords(firewallTestRecord(3, "d3"), firewallTestRecord(2, "d2"))
		}
		_, _ = w.Write([]byte(answer))
	})

	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var entries []FirewallLogEntry
	var warnings []error
	var options = FirewallFollowOptions{
		SinceDigest: "d0",
		Interval:    time.Millisecond,
		MaxBackoff:  time.Millisecond,
		OnWarning:   func(err error) { warnings = append(warnings, err) },
	}
	var err = api.FirewallLogFollow(ctx, options, func(entry FirewallLogEntry) error {
		entries = append(entries, entry)
		if len(entries) == 3 {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Errorf("err = %v, want nil after cancel", err)
	}
	if firewallTestPorts(entries) != "1,2,3" {
		t.Errorf("entries = %s, want oldest first without duplicates", firewallTestPorts(entries))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "HTTP 502") {
		t.Errorf("warnings = %v", warnings)
	}

	var digests []string
	for _, u := range server.urls() {
		digests = append(digests, u.Query().Get("digest"))
	}
	if strings.Join(digests, ",") != "d0,d2,d2,d2" {
		t.Errorf("digests polled = %v", digests)
	}
}

func TestFirewallLogFollowPollGap(t *testing.T) {
	var records = make([]string, FirewallLogDefaultLimit)
	for i := range records {
		records[i] = firewallTestRecord(FirewallLogDefaultLimit-i, fmt.Sprintf("n%d", FirewallLogDefaultLimit-i))
	}
	var api, _ = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		_, _ = w.Write([]byte(firewallTestRecords(records...)))
	})

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var count int
	var warnings []error
	var err = api.FirewallLogFollow(ctx, FirewallFollowOptions{
		SinceDigest: "rotated-away",
		Interval:    time.Millisecond,
		OnWarning:   func(err error) { warnings = append(warnings, err) },
	}, func(entry FirewallLogEntry) error {
		count++
		if count == FirewallLogDefaultLimit {
			cancel()
		}
		return nil
	})
	if err != nil || count != FirewallLogDefaultLimit {
		t.Errorf("err = %v, count = %d", err, count)
	}
	var gapErr *FirewallLogGapError
	if len(warnings) != 1 || !errors.As(warnings[0], &gapErr) || gapErr.SinceDigest != "rotated-away" ||
		!strings.Contains(gapErr.Error(), "may have been skipped") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestFirewallLogFollowPollFatal(t *testing.T) {
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"status":401,"message":"Authentication Failed"}`))
	})
	var err = api.FirewallLogFollow(context.Background(), FirewallFollowOptions{Interval: time.Millisecond}, func(FirewallLogEntry) error {
		return nil
	})
	var httpErr *coreapi.HttpError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 401 || len(server.urls()) != 1 {
		t.Errorf("err = %v after %d requests, want 401 without retry", err, len(server.urls()))
	}
}

func TestFirewallLogFollowHandleError(t *testing.T) {
	var api, _ = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		_, _ = w.Write([]byte(firewallTestRecords(firewallTestRecord(1, "d1"))))
	})
	var stop = errors.New("stop")
	var err = api.FirewallLogFollow(context.Background(), FirewallFollowOptions{Interval: time.Millisecond}, func(FirewallLogEntry) error {
		return stop
	})
	if !errors.Is(err, stop) {
		t.Errorf("err = %v", err)
	}
}

func TestFirewallLogFollowStream(t *testing.T) {
	// each connection replays the newest records (like tail -n 5) and is then closed by the server
	var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1:
			firewallTestSSE(w, firewallTestRecord(1, "s1"), firewallTestRecord(2, "s2"))
		case 2:
			w.WriteHeader(503)
		default:
			firewallTestSSE(w, firewallTestRecord(1, "s1"), firewallTestRecord(2, "s2"), firewallTestRecord(3, "s3"))
		}
	})

	// record 1 was already shown from the log (with the log's digest)
	var seen FirewallLogEntry
	_ = json.Unmarshal([]byte(firewallTestRecord(1, "logdigest")), &seen)

	var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var entries []FirewallLogEntry
	var warnings []string
	var err = api.FirewallLogFollow(ctx, FirewallFollowOptions{
		Stream:     true,
		Seen:       []FirewallLogEntry{seen},
		MaxBackoff: time.Millisecond,
		OnWarning:  func(err error) { warnings = append(warnings, err.Error()) },
	}, func(entry FirewallLogEntry) error {
		entries = append(entries, entry)
		if len(entries) == 2 {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if firewallTestPorts(entries) != "2,3" {
		t.Errorf("entries = %s, want replayed records only once", firewallTestPorts(entries))
	}
	if len(server.urls()) != 3 {
		t.Errorf("connections = %d, want 3", len(server.urls()))
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "stream closed by OPNsense") || !strings.Contains(warnings[1], "HTTP 503") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestFirewallLogFollowStreamFatal(t *testing.T) {
	var cases = map[string]func(w http.ResponseWriter){
		"not found": func(w http.ResponseWriter) {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
		},
		// an OPNsense version without the stream answers something else before any record
		"no event stream": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			var api, server = firewallTestApi(t, func(w http.ResponseWriter, r *http.Request, _ int) { answer(w) })
			var err = api.FirewallLogFollow(context.Background(), FirewallFollowOptions{Stream: true, MaxBackoff: time.Millisecond},
				func(FirewallLogEntry) error { return nil })
			if err == nil || len(server.urls()) != 1 {
				t.Errorf("err = %v after %d requests, want an error without retry", err, len(server.urls()))
			}
		})
	}
}

func TestFirewallBackoff(t *testing.T) {
	var max = 30 * time.Second
	var got []string
	var backoff time.Duration
	for i := 0; i < 7; i++ {
		backoff = firewallBackoff(backoff, max)
		got = append(got, backoff.String())
	}
	if strings.Join(got, ",") != "1s,2s,4s,8s,16s,30s,30s" {
		t.Errorf("backoff = %v", got)
	}
	if firewallBackoff(0, time.Millisecond) != time.Millisecond {
		t.Errorf("first backoff exceeds max")
	}
}

func TestFirewallSeenKeysBounded(t *testing.T) {
	var seen = &firewallSeenKeys{keys: map[string]bool{}}
	for i := 0; i < firewallSeenKeysMax+10; i++ {
		if !seen.add(fmt.Sprint(i)) {
			t.Fatalf("key %d reported as seen", i)
		}
	}
	if len(seen.keys) != firewallSeenKeysMax || len(seen.order) != firewallSeenKeysMax {
		t.Errorf("old keys not evicted: %d keys", len(seen.keys))
	}
	if !seen.add("5") {
		t.Errorf("evicted key still reported as seen")
	}
	if seen.add(fmt.Sprint(firewallSeenKeysMax + 5)) {
		t.Errorf("recent key not remembered")
	}
}
