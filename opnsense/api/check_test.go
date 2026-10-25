package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const checkTestInfo = `{"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD 15.1-RELEASE-p1"],"updates":""}`

func checkTestOPN(t *testing.T, rawUrl string, noSslVerify bool) *OPNsense {
	t.Helper()
	var base, err = url.Parse(rawUrl)
	if err != nil {
		t.Fatal(err)
	}
	return &OPNsense{BaseUrl: *base, ApiKey: "key", ApiSecret: "secret", NoSslVerify: noSslVerify}
}

// checkTestServer answers the check endpoint with handler, behind TLS
func checkTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv = httptest.NewUnstartedServer(handler)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the TLS verification test makes the handshake fail
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func checkWantStep(t *testing.T, err error, step string, contains string) {
	t.Helper()
	var checkErr *CheckError
	if !errors.As(err, &checkErr) {
		t.Fatalf("got %v (%T), want a *CheckError", err, err)
	}
	if checkErr.Step != step || !strings.Contains(err.Error(), contains) {
		t.Errorf("got step %q: %v, want step %q containing %q", checkErr.Step, err, step, contains)
	}
}

func TestCheckOk(t *testing.T) {
	var srv = checkTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var user, pass, _ = r.BasicAuth()
		if r.Method != "GET" || r.URL.Path != "/api/diagnostics/system/system_information" || user != "key" || pass != "secret" {
			t.Errorf("unexpected request %s %s (user %q)", r.Method, r.URL.Path, user)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, checkTestInfo)
	})

	var result, err = checkTestOPN(t, srv.URL, true).Check(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Hostname != "fw.example.com" || len(result.Versions) != 2 || result.Tls != "not verified" ||
		result.Url != srv.URL || result.Protocol == "" || result.Latency <= 0 {
		t.Errorf("unexpected result %+v", result)
	}
}

func TestCheckPlainHttp(t *testing.T) {
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, checkTestInfo)
	}))
	t.Cleanup(srv.Close)

	var result, err = checkTestOPN(t, srv.URL, false).Check(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Tls != "none" {
		t.Errorf("Tls = %q, want none", result.Tls)
	}
}

func TestCheckHttpErrors(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		step, contains          string
	}{
		{"wrong credentials", "application/json", `{"status":401,"message":"Authentication Failed"}`, 401, "auth", "OPN_APIKEY"},
		{"missing privilege", "application/json", `{"status":403,"message":"Forbidden"}`, 403, "auth", "privilege"},
		{"server error", "application/json", `{"errorMessage":"oops"}`, 500, "api", "HTTP 500"},
		{"login page", "text/html; charset=UTF-8", "<html>login</html>", 200, "api", "got text/html"},
		{"empty answer", "", "", 200, "api", "no OPNsense API answer"},
		{"other JSON", "application/json", `{"foo":1}`, 200, "api", "no OPNsense API answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv = checkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			var _, err = checkTestOPN(t, srv.URL, true).Check(context.Background(), 5*time.Second)
			checkWantStep(t, err, tc.step, tc.contains)
		})
	}
}

func TestCheckRedirectNamesTarget(t *testing.T) {
	var srv = checkTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sub/") {
			http.Redirect(w, r, "/?url="+r.URL.Path, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>login</html>")
	})
	var _, err = checkTestOPN(t, srv.URL+"/sub", true).Check(context.Background(), 5*time.Second)
	checkWantStep(t, err, "api", "redirected to "+srv.URL+"/?url=")
}

func TestCheckUntrustedCertificate(t *testing.T) {
	var srv = checkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, checkTestInfo)
	})
	var _, err = checkTestOPN(t, srv.URL, false).Check(context.Background(), 5*time.Second)
	checkWantStep(t, err, "tls", "OPN_NOSSLVERIFY=1")
}

func TestCheckConnectionErrors(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		var listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var address = listener.Addr().String()
		_ = listener.Close()
		_, err = checkTestOPN(t, "https://"+address, true).Check(context.Background(), 5*time.Second)
		checkWantStep(t, err, "connect", "refused")
	})

	t.Run("https to a plain http server", func(t *testing.T) {
		var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		t.Cleanup(srv.Close)
		var _, err = checkTestOPN(t, strings.Replace(srv.URL, "http://", "https://", 1), true).Check(context.Background(), 5*time.Second)
		checkWantStep(t, err, "tls", "does not speak TLS")
	})

	t.Run("http to a TLS server", func(t *testing.T) {
		var srv = checkTestServer(t, func(w http.ResponseWriter, _ *http.Request) {})
		var _, err = checkTestOPN(t, strings.Replace(srv.URL, "https://", "http://", 1), true).Check(context.Background(), 5*time.Second)
		var checkErr *CheckError
		if !errors.As(err, &checkErr) {
			t.Fatalf("got %v, want a *CheckError", err)
		}
		// Go's TLS server answers plain HTTP with a 400, depending on timing the client may see a reset instead
		if checkErr.Step != "api" && checkErr.Step != "connect" {
			t.Errorf("got step %q: %v", checkErr.Step, err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		var release = make(chan struct{})
		var srv = checkTestServer(t, func(w http.ResponseWriter, _ *http.Request) { <-release })
		t.Cleanup(func() { close(release) })
		var _, err = checkTestOPN(t, srv.URL, true).Check(context.Background(), 200*time.Millisecond)
		checkWantStep(t, err, "connect", "in time")
	})
}
