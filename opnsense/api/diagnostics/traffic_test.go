package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers shared by the traffic, cpu, activity and system tests

type trafficTestCall struct {
	Method string
	Path   string
	Accept string
}

// trafficTestApi returns a DiagnosticsApi talking to a test server answering "METHOD /path" with routes,
// unknown routes get a 404 like OPNsense. The second return value reports the requests seen so far
func trafficTestApi(t *testing.T, routes map[string]http.HandlerFunc) (*DiagnosticsApi, func() []trafficTestCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []trafficTestCall
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, trafficTestCall{Method: r.Method, Path: r.URL.Path, Accept: r.Header.Get("Accept")})
		mu.Unlock()
		if handler, found := routes[r.Method+" "+r.URL.EscapedPath()]; found {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
	}))
	t.Cleanup(server.Close)

	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &DiagnosticsApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}},
		func() []trafficTestCall {
			mu.Lock()
			defer mu.Unlock()
			return append([]trafficTestCall(nil), calls...)
		}
}

func trafficTestJSON(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// trafficTestSSE answers with a text/event-stream sending each data as "event: message" (with keepalives in
// between), then closes the stream, or keeps it open until the client goes away when hold is set
func trafficTestSSE(hold bool, data ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		var flusher = w.(http.Flusher)
		for _, d := range data {
			_, _ = fmt.Fprintf(w, "event: keepalive\ndata: \n\nevent: message\ndata: %s\n\n", d)
			flusher.Flush()
		}
		if hold {
			<-r.Context().Done()
		}
	}
}

// trafficTestSample builds a traffic stream event
func trafficTestSample(time float64, lanIn int, lanOut int) string {
	return fmt.Sprintf(`{"interfaces":{"lan":{"inbytes":%d,"outbytes":%d,"inpkts":%d,"outpkts":%d,"inerrs":1,"outerrs":0,"collisions":0,"name":"LAN"},`+
		`"wan":{"inbytes":0,"outbytes":0,"inpkts":0,"outpkts":0,"inerrs":0,"outerrs":0,"collisions":0,"name":"WAN"}},"time":%f}`,
		lanIn, lanOut, lanIn/100, lanOut/100, time)
}

func trafficTestNear(a float64, b float64) bool {
	return math.Abs(a-b) < 1e-6
}

// --- tests

func TestTrafficStream(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/stream/2": trafficTestSSE(false,
			trafficTestSample(1000, 0, 0), trafficTestSample(1002, 2000, 4000)),
	})
	var samples []TrafficSample
	var err = api.TrafficStream(context.Background(), 2, func(sample TrafficSample) error {
		samples = append(samples, sample)
		return nil
	})
	if err != io.EOF {
		t.Fatalf("want io.EOF after the server closed the stream, got %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("want 2 samples (keepalives skipped), got %d", len(samples))
	}
	var lan = samples[1].Interfaces["lan"]
	if lan.Name != "LAN" || lan.InBytes != 2000 || lan.OutBytes != 4000 || lan.InPkts != 20 || lan.InErrs != 1 || samples[1].Time != 1002 {
		t.Errorf("unexpected sample %+v", samples[1])
	}
	if string(samples[1].Raw) != trafficTestSample(1002, 2000, 4000) {
		t.Errorf("raw not kept: %s", samples[1].Raw)
	}
	if samples[1].Timestamp().Unix() != 1002 {
		t.Errorf("unexpected timestamp %v", samples[1].Timestamp())
	}
	if got := calls(); len(got) != 1 || got[0].Method != "GET" || got[0].Accept != "text/event-stream" {
		t.Errorf("unexpected requests %+v", got)
	}
}

func TestTrafficStreamInvalidInterval(t *testing.T) {
	var api, calls = trafficTestApi(t, nil)
	if err := api.TrafficStream(context.Background(), 0, func(TrafficSample) error { return nil }); err == nil {
		t.Fatal("want an error for interval 0")
	}
	if len(calls()) != 0 {
		t.Errorf("want no request, got %v", calls())
	}
}

func TestTrafficStreamDecoding(t *testing.T) {
	for _, tc := range []struct {
		data    string
		wantErr string
		check   func(TrafficSample) bool
	}{
		{`{"interfaces":[],"time":1.5}`, "", func(s TrafficSample) bool { return len(s.Interfaces) == 0 && s.Time == 1.5 }},
		// counters of interfaces that appeared during the stream are passed through as ifconfig strings
		{`{"interfaces":{"opt1":{"inbytes":"12","outbytes":"7","name":"DMZ"}},"time":2}`, "",
			func(s TrafficSample) bool {
				return s.Interfaces["opt1"].InBytes == 12 && s.Interfaces["opt1"].OutBytes == 7
			}},
		{`{"interfaces":{}}`, "without time", nil},
		{`not json`, "unexpected traffic event", nil},
		{`{"interfaces":{"lan":{"inbytes":"many"}},"time":2}`, "invalid counter", nil},
	} {
		t.Run(tc.data, func(t *testing.T) {
			var sample, err = trafficParseSample(tc.data)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || !tc.check(sample) {
				t.Fatalf("unexpected result %+v, %v", sample, err)
			}
		})
	}
}

func TestTrafficStreamErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"401", trafficTestJSON(401, `{"status":401,"message":"Authentication Failed"}`), "HTTP 401"},
		{"not a stream", trafficTestJSON(200, `{"status":"ok"}`), "did not answer with an event stream"},
		{"bad event", trafficTestSSE(false, `{"bogus"`), "unexpected traffic event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{"GET /api/diagnostics/traffic/stream/1": tc.handler})
			var err = api.TrafficStream(context.Background(), 1, func(TrafficSample) error { return nil })
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	var api, _ = trafficTestApi(t, nil)
	var httpErr *coreapi.HttpError
	if err := api.TrafficStream(context.Background(), 1, func(TrafficSample) error { return nil }); !errors.As(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Errorf("want *HttpError 404, got %v", err)
	}
}

func TestTrafficRates(t *testing.T) {
	var previous, _ = trafficParseSample(trafficTestSample(1000, 0, 0))
	var current, _ = trafficParseSample(trafficTestSample(1002, 2000, 5000))
	var rates = TrafficRates(previous, current)
	if len(rates) != 2 || rates[0].Interface != "lan" || rates[1].Interface != "wan" {
		t.Fatalf("want lan and wan sorted, got %+v", rates)
	}
	var lan = rates[0]
	if lan.Name != "LAN" || !trafficTestNear(lan.Seconds, 2) || !trafficTestNear(lan.InBitsPerSecond, 8000) ||
		!trafficTestNear(lan.OutBitsPerSecond, 20000) || !trafficTestNear(lan.InPacketsPerSecond, 10) ||
		!trafficTestNear(lan.OutPacketsPerSecond, 25) || lan.Errors != 1 {
		t.Errorf("unexpected rate %+v", lan)
	}
	if TrafficRates(current, previous) != nil || TrafficRates(current, current) != nil {
		t.Error("want nil rates when no time passed")
	}
}

// trafficTestSleeper records the reconnect delays instead of waiting, cancelling ctx after maxSleeps
type trafficTestSleeper struct {
	mu        sync.Mutex
	delays    []time.Duration
	maxSleeps int
	cancel    context.CancelFunc
}

func (s *trafficTestSleeper) sleep(ctx context.Context, d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delays = append(s.delays, d)
	if len(s.delays) >= s.maxSleeps {
		s.cancel()
		return false
	}
	return ctx.Err() == nil
}

func (s *trafficTestSleeper) options(reconnects *[]error) TrafficFollowOptions {
	return TrafficFollowOptions{
		Sleep:       s.sleep,
		OnReconnect: func(err error, _ time.Duration) { *reconnects = append(*reconnects, err) },
	}
}

func TestTrafficWatchSkipsBaselineAndStops(t *testing.T) {
	var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/stream/1": trafficTestSSE(true,
			trafficTestSample(1000, 0, 0), trafficTestSample(1001, 1000, 0), trafficTestSample(1002, 3000, 0)),
	})
	var stop = errors.New("stop")
	var got []float64
	var err = api.TrafficWatch(context.Background(), 1, TrafficFollowOptions{}, func(sample TrafficSample, rates []TrafficRate) error {
		got = append(got, rates[0].InBitsPerSecond)
		if len(got) == 2 {
			return stop
		}
		return nil
	})
	if err != stop {
		t.Fatalf("want the handle error unwrapped, got %v", err)
	}
	if len(got) != 2 || got[0] != 8000 || got[1] != 24000 {
		t.Errorf("want rates of the 2nd and 3rd event, got %v", got)
	}
}

func TestTrafficWatchCancel(t *testing.T) {
	var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/stream/1": trafficTestSSE(true, trafficTestSample(1000, 0, 0), trafficTestSample(1001, 1, 1)),
	})
	var ctx, cancel = context.WithCancel(context.Background())
	var done = make(chan error)
	go func() {
		done <- api.TrafficWatch(ctx, 1, TrafficFollowOptions{}, func(TrafficSample, []TrafficRate) error {
			cancel()
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("want nil on cancel, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TrafficWatch did not return after cancel")
	}
}

func TestTrafficWatchReconnectsWithBackoff(t *testing.T) {
	var mu sync.Mutex
	var connection = 0
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/stream/1": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connection++
			var n = connection
			mu.Unlock()
			switch n {
			case 1: // healthy, then dropped
				trafficTestSSE(false, trafficTestSample(100, 0, 0), trafficTestSample(101, 1000, 0))(w, r)
			case 2, 3: // only a baseline, then dropped
				trafficTestSSE(false, trafficTestSample(200, 0, 0))(w, r)
			case 4: // server error
				trafficTestJSON(502, `<html>Bad Gateway</html>`)(w, r)
			default: // healthy again, every connection starts with its own baseline
				trafficTestSSE(false, trafficTestSample(float64(n*100), 0, 0), trafficTestSample(float64(n*100+1), n*1000, 0))(w, r)
			}
		},
	})
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &trafficTestSleeper{maxSleeps: 7, cancel: cancel}
	var reconnects []error
	var got []float64
	var err = api.TrafficWatch(ctx, 1, sleeper.options(&reconnects), func(sample TrafficSample, rates []TrafficRate) error {
		got = append(got, rates[0].InBitsPerSecond)
		return nil
	})
	if err != nil {
		t.Fatalf("want nil after cancel, got %v", err)
	}
	if len(calls()) != 7 || len(got) != 4 || got[0] != 8000 || got[1] != 40000 || got[3] != 56000 {
		t.Errorf("want rates of connections 1, 5, 6, 7, got %v after %d requests", got, len(calls()))
	}
	// 1s after the healthy connection, doubling while nothing arrives, back to 1s once samples flow again
	var want = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, time.Second, time.Second, time.Second}
	if fmt.Sprint(sleeper.delays) != fmt.Sprint(want) {
		t.Errorf("want delays %v, got %v", want, sleeper.delays)
	}
	if len(reconnects) != 7 || reconnects[0] != io.EOF || !strings.Contains(reconnects[3].Error(), "HTTP 502") {
		t.Errorf("unexpected reconnect reasons %v", reconnects)
	}
}

func TestTrafficWatchMaxDelay(t *testing.T) {
	var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/stream/1": trafficTestSSE(false, trafficTestSample(1000, 0, 0)),
	})
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &trafficTestSleeper{maxSleeps: 5, cancel: cancel}
	var options = TrafficFollowOptions{Sleep: sleeper.sleep, MinDelay: 10 * time.Second, MaxDelay: 25 * time.Second}
	if err := api.TrafficWatch(ctx, 1, options, func(TrafficSample, []TrafficRate) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sleeper.delays) != "[10s 20s 25s 25s 25s]" {
		t.Errorf("unexpected delays %v", sleeper.delays)
	}
}

func TestTrafficWatchPermanentErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{"401", trafficTestJSON(401, `{"status":401,"message":"Authentication Failed"}`), "HTTP 401"},
		{"403", trafficTestJSON(403, `{"status":403,"message":"Forbidden"}`), "HTTP 403"},
		{"not a stream", trafficTestJSON(200, `{"status":"ok"}`), "event stream"},
		{"first connection 500", trafficTestJSON(500, `oops`), "HTTP 500"},
		{"invalid event", trafficTestSSE(true, trafficTestSample(1, 0, 0), `<b>Fatal error</b>`), "unexpected traffic event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{"GET /api/diagnostics/traffic/stream/1": tc.handler})
			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()
			var sleeper = &trafficTestSleeper{maxSleeps: 3, cancel: cancel}
			var err = api.TrafficWatch(ctx, 1, TrafficFollowOptions{Sleep: sleeper.sleep}, func(TrafficSample, []TrafficRate) error { return nil })
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if len(calls()) != 1 || len(sleeper.delays) != 0 {
				t.Errorf("want no retry, got %d requests", len(calls()))
			}
		})
	}
	var api, calls = trafficTestApi(t, nil)
	if err := api.TrafficWatch(context.Background(), 0, TrafficFollowOptions{}, func(TrafficSample, []TrafficRate) error { return nil }); err == nil || len(calls()) != 0 {
		t.Errorf("want an error without request for interval 0, got %v", err)
	}
}

const trafficTestInterfaceAnswer = `{"interfaces":{"lan":{"device":"vtnet0","mtu":"1500","bytes received":"4908196",` +
	`"bytes transmitted":"15538584","packets received":"24506","packets transmitted":"30761","input errors":"0",` +
	`"output errors":"0","collisions":"0","line rate":"10000000000 bit\/s","name":"LAN"},` +
	`"wan":{"device":"vtnet1","mtu":"1500","bytes received":"507660","name":"WAN","index":2,"vhid":null}},"time":1792886793.949564}`

func TestTrafficInterfaces(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/interface": trafficTestJSON(200, trafficTestInterfaceAnswer),
	})
	var interfaces, err = api.TrafficInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 || interfaces["lan"]["bytes received"] != "4908196" || interfaces["lan"]["line rate"] != "10000000000 bit/s" ||
		interfaces["wan"]["name"] != "WAN" || interfaces["wan"]["index"] != "2" || interfaces["wan"]["vhid"] != "" {
		t.Errorf("unexpected interfaces %+v", interfaces)
	}
	if got := calls(); len(got) != 1 || got[0].Method != "GET" {
		t.Errorf("unexpected requests %+v", got)
	}
}

func TestTrafficInterfacesErrors(t *testing.T) {
	for _, tc := range []struct {
		status  int
		answer  string
		wantErr string
	}{
		{200, `{}`, "no interfaces"},
		{200, ``, "empty response"},
		{200, `{"interfaces":"x"}`, "unexpected answer"},
		{401, `{"status":401,"message":"Authentication Failed"}`, "HTTP 401"},
	} {
		var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
			"GET /api/diagnostics/traffic/interface": trafficTestJSON(tc.status, tc.answer),
		})
		if _, err := api.TrafficInterfaces(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: want error containing %q, got %v", tc.answer, tc.wantErr, err)
		}
	}
	var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/interface": trafficTestJSON(200, `{"interfaces":[]}`),
	})
	if interfaces, err := api.TrafficInterfaces(); err != nil || len(interfaces) != 0 {
		t.Errorf("want no interfaces for [], got %v, %v", interfaces, err)
	}
}

const trafficTestTopAnswer = `{"lan":{"records":[{"address":"192.168.1.2","rate_bits_in":91400,"rate_bits_out":22600,` +
	`"rate_bits":114000,"cumulative_bytes_in":20000,"cumulative_bytes_out":8400,"cumulative_bytes":28400,"tags":["private"],` +
	`"details":[{"address":"192.168.1.1","rate":"91.4Kb","rate_bits":91400,"cumulative":"20KB","cumulative_bytes":20000,"tags":["local","private"]}],` +
	`"rname":"client.lan","rate_in":"91.4 kb","rate_out":"22.6 kb","rate":"114.0 kb","cumulative_in":"20.0 kb",` +
	`"cumulative_out":"8.4 kb","cumulative":"28.4 kb"}],"status":"ok"},"wan":{"records":[],"status":"timeout"}}`

func TestTrafficTop(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/top/lan,wan": trafficTestJSON(200, trafficTestTopAnswer),
	})
	var top, raw, err = api.TrafficTop([]string{"lan", "wan"})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != trafficTestTopAnswer {
		t.Errorf("raw answer not returned: %s", raw)
	}
	var lan = top["lan"]
	if lan.Status != "ok" || len(lan.Records) != 1 || top["wan"].Status != "timeout" {
		t.Fatalf("unexpected top %+v", top)
	}
	var host = lan.Records[0]
	if host.Address != "192.168.1.2" || host.ReverseName != "client.lan" || host.RateBitsIn != 91400 || host.RateBitsOut != 22600 ||
		host.RateBits != 114000 || host.CumulativeBytes != 28400 || len(host.Tags) != 1 || len(host.Details) != 1 ||
		host.Details[0].RateBits != 91400 {
		t.Errorf("unexpected host %+v", host)
	}
	if got := calls(); len(got) != 1 || got[0].Method != "GET" {
		t.Errorf("unexpected requests %+v", got)
	}
}

func TestTrafficTopEmptyAndErrors(t *testing.T) {
	var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/traffic/top/bogus": trafficTestJSON(200, `[]`),
	})
	if top, _, err := api.TrafficTop([]string{"bogus"}); err != nil || len(top) != 0 {
		t.Errorf("want an empty result for [], got %v, %v", top, err)
	}

	var api2, calls = trafficTestApi(t, nil)
	for _, interfaces := range [][]string{nil, {""}, {"lan/x"}, {"lan,wan"}} {
		if _, _, err := api2.TrafficTop(interfaces); err == nil {
			t.Errorf("%q: want an error", interfaces)
		}
	}
	if len(calls()) != 0 {
		t.Errorf("want no requests for invalid names, got %v", calls())
	}
	if _, _, err := api2.TrafficTop([]string{"lan"}); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("want HTTP 404, got %v", err)
	}
}
