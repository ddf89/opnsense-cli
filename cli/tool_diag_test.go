package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// /tool traceroute, port-probe and dns-lookup

const toolDiagTestTraceroute = `{"result":"ok","response":{"rows":[{"address":"10.0.2.2","ttl":"1","AS":"AS0","host":"10.0.2.2","probes":"0.153 ms"},` +
	`{"address":"192.0.2.1","ttl":"2","AS":"AS64500","host":"router.example","probes":"1.2 ms"}],` +
	`"notice":"traceroute to 192.0.2.1 (192.0.2.1), 64 hops max, 48 byte packets"}}`

func TestToolTraceroute(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/traceroute/set", 200, toolDiagTestTraceroute)
	var r = f.run("/tool", "traceroute", "192.0.2.1", "protocol=icmp", "source=10.0.2.15")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "HOP", "ADDRESS", "HOST", "AS", "TIME", "10.0.2.2", "192.0.2.1", "router.example", "AS64500", "1.2 ms")
	wantContains(t, "stderr", r.stderr, "traceroute to 192.0.2.1")
	if lines := strings.Split(strings.TrimSpace(r.stdout), "\n"); len(lines) != 3 || !strings.Contains(lines[1], " - ") {
		t.Errorf("want 2 hops, the host of hop 1 equals its address and is not repeated:\n%s", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/diagnostics/traceroute/set"), map[string]any{"traceroute": map[string]any{"settings": map[string]any{
		"hostname": "192.0.2.1", "ipproto": "inet", "protocol": "icmp", "source_address": "10.0.2.15"}}})

	r = f.run("/tool", "traceroute", "192.0.2.1", "json")
	wantExit(t, r, 0)
	if !strings.HasPrefix(r.stdout, `{"rows":[{"address":"10.0.2.2"`) {
		t.Errorf("want the raw response:\n%s", r.stdout)
	}

	var v6 = newFakeOPN(t)
	v6.on("POST", "/api/diagnostics/traceroute/set", 200, `{"result":"ok","response":{"rows":[],"error":"timeout reached"}}`)
	r = v6.run("/tool", "traceroute", "fd00::1")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "warning: timeout reached")
	if settings := v6.mutations()[0].json(t)["traceroute"].(map[string]any)["settings"].(map[string]any); settings["ipproto"] != "inet6" || settings["protocol"] != "udp" {
		t.Errorf("settings %v", settings)
	}

	var invalid = newFakeOPN(t)
	invalid.on("POST", "/api/diagnostics/traceroute/set", 200, `{"result":"failed","validations":{"traceroute.settings.hostname":"Provide a valid hostname or address."}}`)
	wantFailure(t, invalid.run("/tool", "traceroute", "bad_host"), "Provide a valid hostname or address.")

	for _, args := range [][]string{
		{"/tool", "traceroute"},
		{"/tool", "traceroute", "10.0.0.1", "protocol=tcp"},
		{"/tool", "traceroute", "10.0.0.1", "family=ipv6"},
		{"/tool", "traceroute", "a;b"},
	} {
		var none = newFakeOPN(t)
		wantFailure(t, none.run(args...))
		wantNoCalls(t, none)
	}
}

func TestToolTracerouteInterrupt(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.onFunc("POST", "/api/diagnostics/traceroute/set", func(w http.ResponseWriter, r *http.Request) {
		select { // traceroute takes up to 20s
		case <-r.Context().Done():
		case <-f.done():
		case <-time.After(5 * time.Second):
		}
	})
	var p = f.start("/tool", "traceroute", "10.0.2.2")
	var deadline = time.Now().Add(5 * time.Second)
	for len(f.mutations()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var r = p.interrupt()
	wantExit(t, r, 0)
	if r.stdout != "" {
		t.Errorf("want no output after Ctrl-C: %q", r.stdout)
	}
}

func TestToolPortProbe(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/portprobe/set", 200, `{"result":"ok","response":{"message":"Connection to 127.0.0.1 22 port [tcp\/ssh] succeeded!","payload":"SSH-2.0-OpenSSH_9.9\r\n"}}`)
	var r = f.run("/tool", "port-probe", "127.0.0.1", "port=22", "show-text", "source-port=40000")
	wantExit(t, r, 0)
	if r.stdout != "Connection to 127.0.0.1 22 port [tcp/ssh] succeeded!\nSSH-2.0-OpenSSH_9.9\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/diagnostics/portprobe/set"), map[string]any{"portprobe": map[string]any{"settings": map[string]any{
		"hostname": "127.0.0.1", "port": "22", "ipproto": "inet", "source_address": "", "source_port": "40000", "showtext": "1"}}})

	var closed = newFakeOPN(t)
	closed.on("POST", "/api/diagnostics/portprobe/set", 200, `{"result":"ok","response":{"message":"nc: connect to 127.0.0.1 port 9 (tcp) failed: Connection refused","payload":""}}`)
	r = closed.run("/tool", "port-probe", "127.0.0.1", "port=9")
	wantFailure(t, r, "port-probe 127.0.0.1 port 9: connect to 127.0.0.1 port 9 (tcp) failed: Connection refused")
	if r.stdout != "" {
		t.Errorf("want no output on stdout: %q", r.stdout)
	}
	r = closed.run("/tool", "port-probe", "127.0.0.1", "port=9", "json")
	wantExit(t, r, 1)
	wantContains(t, "stdout", r.stdout, `"message":"nc: connect to 127.0.0.1 port 9`)

	for _, args := range [][]string{
		{"/tool", "port-probe", "127.0.0.1"},
		{"/tool", "port-probe", "127.0.0.1", "port=0"},
		{"/tool", "port-probe", "127.0.0.1", "port=22", "source-port=70000"},
		{"/tool", "port-probe", "127.0.0.1", "port=22", "family=ipv6"},
	} {
		var none = newFakeOPN(t)
		wantFailure(t, none.run(args...))
		wantNoCalls(t, none)
	}
}

func TestToolDnsLookup(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("POST", "/api/diagnostics/dns_diagnostics/set", 200, `{"result":"ok","response":{"AAAA":{"answers":["localhost.\t10800\tIN\tAAAA\t::1"],"query_time":"0 msec","server":"127.0.0.1"},`+
		`"A":{"answers":["localhost.\t10800\tIN\tA\t127.0.0.1"],"query_time":"1 msec","server":"127.0.0.1"},`+
		`"TXT":{"answers":["localhost.\t300\tIN\tTXT\t\"v=spf1 -all\""],"query_time":"0 msec","server":"127.0.0.1"}}}`)
	var r = f.run("/tool", "dns-lookup", "localhost", "server=127.0.0.1")
	wantExit(t, r, 0)
	var lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], "A ") || !strings.HasPrefix(lines[2], "AAAA") || !strings.HasSuffix(lines[3], `"v=spf1 -all"`) {
		t.Errorf("want A, AAAA, TXT in this order:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "TYPE", "NAME", "TTL", "DATA", "localhost.", "10800", "127.0.0.1", "::1")
	wantContains(t, "stderr", r.stderr, "A: answered by 127.0.0.1 in 1 msec")
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/diagnostics/dns_diagnostics/set"), map[string]any{"dns": map[string]any{"settings": map[string]any{
		"hostname": "localhost", "server": "127.0.0.1"}}})

	r = f.run("/tool", "dns-lookup", "localhost", "json")
	wantExit(t, r, 0)
	if !strings.HasPrefix(r.stdout, `{"AAAA":`) || strings.Count(r.stdout, "\n") != 1 {
		t.Errorf("want the raw response:\n%s", r.stdout)
	}

	var failing = newFakeOPN(t)
	failing.on("POST", "/api/diagnostics/dns_diagnostics/set", 200, `{"result":"ok","response":{"error_message":"Error: error sending query: Error creating socket"}}`)
	wantFailure(t, failing.run("/tool", "dns-lookup", "localhost", "server=127.0.0.2"), "dns-lookup localhost: error sending query: Error creating socket")

	var none = newFakeOPN(t)
	none.on("POST", "/api/diagnostics/dns_diagnostics/set", 200, `{"result":"ok","response":{}}`)
	wantFailure(t, none.run("/tool", "dns-lookup", "nonexistent.invalid"), "no records found")

	for _, args := range [][]string{
		{"/tool", "dns-lookup"},
		{"/tool", "dns-lookup", "localhost", "server=dns.example"},
		{"/tool", "dns-lookup", "a b"},
	} {
		var none = newFakeOPN(t)
		wantFailure(t, none.run(args...))
		wantNoCalls(t, none)
	}
}
