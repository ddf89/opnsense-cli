package diagnostics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const cpuTestStreamPath = "GET /api/diagnostics/cpu_usage/stream"

func TestCpuStream(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		cpuTestStreamPath: trafficTestSSE(false, `{"total":5,"user":4,"nice":0,"sys":1,"intr":0,"idle":95}`,
			`{"total":100,"user":81,"nice":0,"sys":17,"intr":2,"idle":0}`),
	})
	var got []CpuUsage
	var err = api.CpuStream(context.Background(), func(usage CpuUsage) error {
		got = append(got, usage)
		return nil
	})
	if err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if len(got) != 2 || got[1].Total != 100 || got[1].User != 81 || got[1].Sys != 17 || got[1].Intr != 2 || got[1].Idle != 0 ||
		string(got[1].Raw) != `{"total":100,"user":81,"nice":0,"sys":17,"intr":2,"idle":0}` {
		t.Errorf("unexpected usage %+v", got)
	}
	if c := calls(); len(c) != 1 || c[0].Method != "GET" || c[0].Accept != "text/event-stream" {
		t.Errorf("unexpected requests %+v", c)
	}
}

func TestCpuParseUsage(t *testing.T) {
	for _, data := range []string{`{"user":1}`, `[]`, `<b>Fatal error</b>`, `{"total":"x","idle":1}`} {
		if _, err := cpuParseUsage(data); err == nil || !strings.Contains(err.Error(), "unexpected cpu usage event") {
			t.Errorf("%s: want an error, got %v", data, err)
		}
	}
}

func TestCpuWatchSkipsFirstEventPerConnection(t *testing.T) {
	var mu sync.Mutex
	var connection = 0
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		cpuTestStreamPath: func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connection++
			var n = connection
			mu.Unlock()
			if n == 1 {
				trafficTestSSE(false, `{"total":3,"user":2,"nice":0,"sys":1,"intr":0,"idle":97}`, `{"total":42,"user":30,"nice":0,"sys":10,"intr":2,"idle":58}`)(w, r)
				return
			}
			trafficTestSSE(true, `{"total":4,"user":2,"nice":0,"sys":2,"intr":0,"idle":96}`, `{"total":50,"user":40,"nice":0,"sys":10,"intr":0,"idle":50}`)(w, r)
		},
	})
	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	var sleeper = &trafficTestSleeper{maxSleeps: 5, cancel: cancel}
	var reconnects []error
	var stop = errors.New("stop")
	var got []int
	var err = api.CpuWatch(ctx, sleeper.options(&reconnects), func(usage CpuUsage) error {
		got = append(got, usage.Total)
		if len(got) == 2 {
			return stop
		}
		return nil
	})
	if err != stop {
		t.Fatalf("want the handle error, got %v", err)
	}
	if len(got) != 2 || got[0] != 42 || got[1] != 50 || len(calls()) != 2 || len(reconnects) != 1 || reconnects[0] != io.EOF {
		t.Errorf("want 42 then 50 over 2 connections, got %v after %d requests, reconnects %v", got, len(calls()), reconnects)
	}
}

func TestCpuWatchPermanentErrors(t *testing.T) {
	for _, tc := range []struct {
		handler http.HandlerFunc
		wantErr string
	}{
		{trafficTestJSON(404, `{"errorMessage":"Endpoint not found"}`), "HTTP 404"},
		{trafficTestJSON(200, `{"status":"ok"}`), "event stream"},
		{trafficTestSSE(true, `garbage`), "unexpected cpu usage event"},
	} {
		var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{cpuTestStreamPath: tc.handler})
		var ctx, cancel = context.WithCancel(context.Background())
		var sleeper = &trafficTestSleeper{maxSleeps: 3, cancel: cancel}
		var err = api.CpuWatch(ctx, TrafficFollowOptions{Sleep: sleeper.sleep}, func(CpuUsage) error { return nil })
		cancel()
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) || len(calls()) != 1 {
			t.Errorf("want error containing %q without retry, got %v after %d requests", tc.wantErr, err, len(calls()))
		}
	}
}

func TestCpuType(t *testing.T) {
	var api, calls = trafficTestApi(t, map[string]http.HandlerFunc{
		"GET /api/diagnostics/cpu_usage/getCPUType": trafficTestJSON(200, `["Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)"]`),
	})
	if model, err := api.CpuType(); err != nil || model != "Intel(R) Core(TM) Ultra 7 165U (1 cores, 1 threads)" {
		t.Errorf("unexpected %q, %v", model, err)
	}
	if c := calls(); len(c) != 1 || c[0].Method != "GET" {
		t.Errorf("unexpected requests %+v", c)
	}
	for _, answer := range []string{`[]`, `[""]`, `{}`, ``} {
		var api, _ = trafficTestApi(t, map[string]http.HandlerFunc{"GET /api/diagnostics/cpu_usage/getCPUType": trafficTestJSON(200, answer)})
		if _, err := api.CpuType(); err == nil {
			t.Errorf("%q: want an error", answer)
		}
	}
}
