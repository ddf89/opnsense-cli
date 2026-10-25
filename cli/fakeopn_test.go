package cli

// Black-box test harness for the opn CLI: TestMain builds the binary once, every test starts a fake OPNsense
// (httptest TLS server) that records all requests and answers with canned OPNsense 26.7 shaped responses,
// then runs the binary against it with a clean environment. f.run("/dnsmasq", "host", "print") runs one command
// (each argument is one word, like in the shell), f.runScript("line\nline", ...) feeds a script on stdin.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testApiKey    = "test-key"
	testApiSecret = "test-secret"
)

// opnBinary is the CLI built by TestMain
var opnBinary string

func TestMain(m *testing.M) {
	var dir, err = os.MkdirTemp("", "opn-cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	opnBinary = filepath.Join(dir, "opn")
	var build = exec.Command("go", "build", "-o", opnBinary, ".")
	build.Dir = ".." // module root
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "building opn failed: %v\n%s", buildErr, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	var code = m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// apiCall is one request received by the fake OPNsense
type apiCall struct {
	Method  string
	Path    string
	Query   url.Values
	Body    string
	User    string
	Pass    string
	HasAuth bool
}

func (c apiCall) String() string {
	var s = c.Method + " " + c.Path
	if len(c.Query) > 0 {
		s += "?" + c.Query.Encode()
	}
	if c.Body != "" {
		s += " " + strings.TrimSpace(c.Body)
	}
	return s
}

// json decodes the request body, failing the test if it is not JSON
func (c apiCall) json(t *testing.T) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(c.Body), &decoded); err != nil {
		t.Fatalf("body of %s %s is not a JSON object: %v: %q", c.Method, c.Path, err, c.Body)
	}
	return decoded
}

type fakeOPN struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	recorded []apiCall
	handlers map[string]http.HandlerFunc // "METHOD /path"
	doneCh   chan struct{}               // see done()
}

// newFakeOPN starts a fake OPNsense. Requests without the test credentials get a 401 like OPNsense,
// unregistered endpoints are answered with an empty 200 like OPNsense does for unknown endpoints
func newFakeOPN(t *testing.T) *fakeOPN {
	t.Helper()
	var f = &fakeOPN{t: t, handlers: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected TLS handshake errors of the verification tests
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.doneCh = make(chan struct{})
	t.Cleanup(func() { close(f.doneCh) }) // cleanups run last in first out: before srv.Close
	return f
}

func (f *fakeOPN) serve(w http.ResponseWriter, r *http.Request) {
	var body, _ = io.ReadAll(r.Body)
	var user, pass, hasAuth = r.BasicAuth()
	f.mu.Lock()
	f.recorded = append(f.recorded, apiCall{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Body: string(body),
		User: user, Pass: pass, HasAuth: hasAuth,
	})
	var handler = f.handlers[r.Method+" "+r.URL.Path]
	f.mu.Unlock()

	if !hasAuth || user != testApiKey || pass != testApiSecret {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":401,"message":"Authentication Failed"}`)
		return
	}
	if handler == nil {
		return // empty 200
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	handler(w, r)
}

// on registers a static JSON answer
func (f *fakeOPN) on(method string, path string, status int, body string) {
	f.onFunc(method, path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func (f *fakeOPN) onFunc(method string, path string, handler http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[method+" "+path] = handler
}

// search registers a GET search endpoint answering rows, filtered like OPNsense by ?searchPhrase=
// (case-insensitive substring match over all column values)
func (f *fakeOPN) search(path string, rows ...map[string]any) {
	f.onFunc("GET", path, func(w http.ResponseWriter, r *http.Request) {
		var phrase = strings.ToLower(r.URL.Query().Get("searchPhrase"))
		var matching = make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			if phrase == "" || rowContains(row, phrase) {
				matching = append(matching, row)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rows": matching, "rowCount": len(matching), "total": len(matching), "current": 1,
		})
	})
}

func rowContains(row map[string]any, phrase string) bool {
	for _, value := range row {
		if s, ok := value.(string); ok && strings.Contains(strings.ToLower(s), phrase) {
			return true
		}
	}
	return false
}

func (f *fakeOPN) calls() []apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apiCall(nil), f.recorded...)
}

// mutations returns all non GET calls
func (f *fakeOPN) mutations() []apiCall {
	var result []apiCall
	for _, call := range f.calls() {
		if call.Method != "GET" {
			result = append(result, call)
		}
	}
	return result
}

// env is a complete, clean environment pointing the CLI at the fake server
func (f *fakeOPN) env() []string {
	return []string{
		"OPN_URL=" + f.srv.URL,
		"OPN_APIKEY=" + testApiKey,
		"OPN_APISECRET=" + testApiSecret,
		"OPN_NOSSLVERIFY=1",
	}
}

// run runs the CLI against the fake server
func (f *fakeOPN) run(args ...string) runResult {
	f.t.Helper()
	return runOpn(f.t, f.env(), args...)
}

type runResult struct {
	code   int
	stdout string
	stderr string
}

func (r runResult) String() string {
	return fmt.Sprintf("exit %d\n--- stdout:\n%s--- stderr:\n%s", r.code, r.stdout, r.stderr)
}

// runOpn runs the binary with exactly env (plus TZ=UTC) in an empty temp dir, so no stray .env is loaded
func runOpn(t *testing.T, env []string, args ...string) runResult {
	t.Helper()
	return runOpnIn(t, t.TempDir(), env, args...)
}

func runOpnIn(t *testing.T, dir string, env []string, args ...string) runResult {
	t.Helper()
	return runOpnWithStdin(t, dir, env, "", args...)
}

// runScript runs the CLI in script mode: no command arguments, the lines come from stdin
func (f *fakeOPN) runScript(script string, args ...string) runResult {
	f.t.Helper()
	return runOpnWithStdin(f.t, f.t.TempDir(), f.env(), script, args...)
}

func runOpnWithStdin(t *testing.T, dir string, env []string, stdin string, args ...string) runResult {
	t.Helper()
	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var command = exec.CommandContext(ctx, opnBinary, args...)
	command.Stdin = strings.NewReader(stdin)
	command.Dir = dir
	command.Env = append([]string{"TZ=UTC"}, env...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	var err = command.Run()
	var result = runResult{stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running opn %v: %v", args, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("opn %v timed out", args)
	}
	return result
}

// --- assertions

func wantExit(t *testing.T, r runResult, code int) {
	t.Helper()
	if code == 0 && r.code != 0 || code != 0 && r.code == 0 {
		t.Fatalf("want exit code %d, got:\n%s", code, r)
	}
}

func wantContains(t *testing.T, what string, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("%s does not contain %q:\n%s", what, want, got)
		}
	}
}

func wantNotContains(t *testing.T, what string, got string, unwanted ...string) {
	t.Helper()
	for _, s := range unwanted {
		if strings.Contains(strings.ToLower(got), strings.ToLower(s)) {
			t.Errorf("%s contains %q:\n%s", what, s, got)
		}
	}
}

// wantFailure asserts a non-zero exit with all wants somewhere in stdout or stderr and nothing claiming success
func wantFailure(t *testing.T, r runResult, wants ...string) {
	t.Helper()
	wantExit(t, r, 1)
	wantContains(t, "output", r.stdout+r.stderr, wants...)
	wantNotContains(t, "output", r.stdout+r.stderr, "success", "created", "updated", "deleted")
}

func wantNoCalls(t *testing.T, f *fakeOPN) {
	t.Helper()
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("want no API calls, got %v", calls)
	}
}

func wantNoMutations(t *testing.T, f *fakeOPN) {
	t.Helper()
	if calls := f.mutations(); len(calls) != 0 {
		t.Errorf("want no mutating API calls, got %v", calls)
	}
}

// wantOneMutation asserts exactly one non GET call to method path and returns it
func wantOneMutation(t *testing.T, f *fakeOPN, method string, path string) apiCall {
	t.Helper()
	var calls = f.mutations()
	if len(calls) != 1 || calls[0].Method != method || calls[0].Path != path {
		t.Fatalf("want exactly one %s %s, got %v", method, path, calls)
	}
	return calls[0]
}

// wantJSON asserts the decoded body equals want
func wantJSON(t *testing.T, call apiCall, want map[string]any) {
	t.Helper()
	var got = call.json(t)
	if !reflect.DeepEqual(got, want) {
		var gotJSON, _ = json.Marshal(got)
		var wantJSON, _ = json.Marshal(want)
		t.Errorf("body of %s %s:\n got  %s\n want %s", call.Method, call.Path, gotJSON, wantJSON)
	}
}

// wantSearchPhrases asserts the GET calls to path used exactly these searchPhrases ("" for none)
func wantSearchPhrases(t *testing.T, f *fakeOPN, path string, phrases ...string) {
	t.Helper()
	var got []string
	for _, call := range f.calls() {
		if call.Method == "GET" && call.Path == path {
			got = append(got, call.Query.Get("searchPhrase"))
		}
	}
	if !reflect.DeepEqual(got, phrases) {
		t.Errorf("searchPhrases for %s: got %q, want %q", path, got, phrases)
	}
}

// --- 26.7 shaped rows

func withFields(base map[string]any, overrides map[string]any) map[string]any {
	var row = maps.Clone(base)
	maps.Copy(row, overrides)
	return row
}

func unboundRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "enabled": "1", "hostname": "clitest", "domain": "example.lan", "rr": "A", "%rr": "A (IPv4 address)",
		"mxprio": "", "mx": "", "ttl": "", "server": "10.9.9.8", "txtdata": "", "addptr": "1", "aliases": "",
		"description": "", "isAlias": false,
	}, overrides)
}

func dnsmasqHostRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "host": "probe", "domain": "example.lan", "local": "0", "ip": "10.1.1.1,fd00::1",
		"cnames": "alias1.example.lan,alias2.example.lan", "client_id": "", "hwaddr": "aa:bb:cc:dd:ee:ff",
		"lease_time": "", "ignore": "0", "set_tag": "", "descr": "probe host", "comments": "", "aliases": "www.example.lan",
	}, overrides)
}

func dnsmasqDomainRow(overrides map[string]any) map[string]any {
	return withFields(map[string]any{
		"uuid": "", "sequence": "1", "domain": "corp.example", "ipset": "", "srcip": "", "port": "5353",
		"ip": "10.0.0.53", "descr": "corp dns",
	}, overrides)
}

const (
	answerSaved      = `{"result":"saved"}`
	answerDeleted    = `{"result":"deleted"}`
	answerNotFound   = `{"result":"not found"}`
	answerFailedBare = `{"result":"failed"}`
)

func answerAdded(uuid string) string {
	return fmt.Sprintf(`{"result":"saved","uuid":%q}`, uuid)
}

func answerValidation(field string, message string) string {
	return fmt.Sprintf(`{"result":"failed","validations":{%q:%q}}`, field, message)
}

// --- server-sent event streams (diag --follow)

// sseConn describes what one connection to a stream endpoint gets
type sseConn struct {
	// Events are raw event blocks without the dispatching blank line, e.g. sseData(`{"a":1}`)
	Events []string
	// Keepalive sends a keepalive event before every event and every 50ms while the stream is held open
	Keepalive bool
	// Drop closes the stream after the events, instead of holding it open until the client disconnects
	Drop bool
	// Status != 0 answers with Status, ContentType and Body instead of a stream
	Status      int
	ContentType string
	Body        string
}

const sseKeepaliveEvent = "event: keepalive\ndata:"

func sseData(data string) string {
	return "data: " + data
}

// stream registers a GET text/event-stream endpoint. Connection n gets conns[n] (the last one repeats);
// held open streams end when the client disconnects or the test ends
func (f *fakeOPN) stream(path string, conns ...sseConn) {
	var mu sync.Mutex
	var connections int
	f.onFunc("GET", path, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		var conn = conns[min(connections, len(conns)-1)]
		connections++
		mu.Unlock()

		if conn.Status != 0 {
			w.Header().Set("Content-Type", conn.ContentType)
			w.WriteHeader(conn.Status)
			_, _ = io.WriteString(w, conn.Body)
			return
		}

		var flusher, _ = w.(http.Flusher)
		var send = func(block string) bool {
			if _, err := io.WriteString(w, block+"\n\n"); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for _, event := range conn.Events {
			if conn.Keepalive && !send(sseKeepaliveEvent) {
				return
			}
			if !send(event) {
				return
			}
		}
		if conn.Drop {
			return
		}
		var ticker = time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-f.done():
				return
			case <-ticker.C:
				if conn.Keepalive && !send(sseKeepaliveEvent) {
					return
				}
			}
		}
	})
}

// streamConnections counts the GET requests to path
func (f *fakeOPN) streamConnections(path string) int {
	var count int
	for _, call := range f.calls() {
		if call.Method == "GET" && call.Path == path {
			count++
		}
	}
	return count
}

// waitForConnections waits until path got n GET requests, failing the test after 5s
func (f *fakeOPN) waitForConnections(path string, n int) {
	f.t.Helper()
	var deadline = time.Now().Add(5 * time.Second)
	for f.streamConnections(path) < n {
		if time.Now().After(deadline) {
			f.t.Fatalf("timeout waiting for %d connections to %s, got %v", n, path, f.calls())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// done is closed when the test ends (before the server is closed), so held open streams do not block httptest.Server.Close
func (f *fakeOPN) done() <-chan struct{} {
	return f.doneCh
}

// --- background runs (--follow)

// syncBuffer is a bytes.Buffer safe for concurrent writes by exec and reads by the test
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type opnProcess struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	exited chan struct{}
	err    error
}

// start runs the CLI against the fake server in the background, it is killed when the test ends
func (f *fakeOPN) start(args ...string) *opnProcess {
	f.t.Helper()
	var p = &opnProcess{t: f.t, stdout: &syncBuffer{}, stderr: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(opnBinary, args...)
	p.cmd.Dir = f.t.TempDir()
	p.cmd.Env = append([]string{"TZ=UTC"}, f.env()...)
	p.cmd.Stdout = p.stdout
	p.cmd.Stderr = p.stderr
	if err := p.cmd.Start(); err != nil {
		f.t.Fatalf("starting opn %v: %v", args, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	f.t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.exited
	})
	return p
}

// waitFor waits until stdout contains all wants, failing the test after 5s
func (p *opnProcess) waitFor(wants ...string) {
	p.t.Helper()
	var deadline = time.Now().Add(5 * time.Second)
	for {
		var missing = false
		for _, want := range wants {
			if !strings.Contains(p.stdout.String(), want) {
				missing = true
			}
		}
		if !missing {
			return
		}
		select {
		case <-p.exited:
			p.t.Fatalf("opn exited before printing %q:\n%s", wants, p.result())
		default:
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("timeout waiting for %q:\n--- stdout:\n%s--- stderr:\n%s", wants, p.stdout, p.stderr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// interrupt sends SIGINT (Ctrl-C) and waits for the process to exit
func (p *opnProcess) interrupt() runResult {
	p.t.Helper()
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		p.t.Fatalf("sending SIGINT: %v", err)
	}
	return p.wait()
}

// wait waits up to 5s for the process to exit on its own
func (p *opnProcess) wait() runResult {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
		p.t.Fatalf("opn did not exit:\n%s", p.result())
	}
	return p.result()
}

// running reports whether the process is still running
func (p *opnProcess) running() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

func (p *opnProcess) result() runResult {
	var result = runResult{stdout: p.stdout.String(), stderr: p.stderr.String()}
	select {
	case <-p.exited:
		if exitErr, ok := p.err.(*exec.ExitError); ok {
			result.code = exitErr.ExitCode()
			if result.code == -1 { // killed by a signal
				result.code = 128
			}
		}
	default:
		result.code = -1
	}
	return result
}
