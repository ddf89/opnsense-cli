package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// checkEndpoint is a cheap read-only call every API user with dashboard access may make, it answers
// {"name":"fw.example.com","versions":["OPNsense 26.7-amd64","FreeBSD ...","OpenSSL ..."],"updates":"..."}
const checkEndpoint = "diagnostics/system/system_information"

// CheckResult describes a working API connection
type CheckResult struct {
	// Url is the configured base URL
	Url string
	// Hostname and Versions as OPNsense reports them
	Hostname string
	Versions []string
	// Protocol is the HTTP version used, like HTTP/2.0
	Protocol string
	// Tls is "verified", "not verified" (OPN_NOSSLVERIFY=1) or "none" for plain http
	Tls string
	// Latency is the duration of the request
	Latency time.Duration
}

// CheckError tells which step of Check failed (dns, connect, tls, auth, api) and how to fix it
type CheckError struct {
	Step string
	Err  error
	Hint string
}

func (e *CheckError) Error() string {
	if e.Hint == "" {
		return fmt.Sprintf("%s: %v", e.Step, e.Err)
	}
	return fmt.Sprintf("%s: %v (%s)", e.Step, e.Err, e.Hint)
}

func (e *CheckError) Unwrap() error {
	return e.Err
}

// Check makes one authenticated read-only API call and reports whether OPNsense is reachable and accepts the
// credentials. Failures are returned as *CheckError naming the failed step with a hint
func (opn *OPNsense) Check(ctx context.Context, timeout time.Duration) (*CheckResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var endpoint = opn.EndpointForModule(checkEndpoint)
	var request, err = http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, &CheckError{Step: "url", Err: err, Hint: "check OPN_URL"}
	}
	request.Header.Set("Accept", "application/json")

	var start = time.Now()
	response, err := opn.Send(request)
	if err != nil {
		return nil, checkClassifyError(ctx, err, opn.BaseUrl.Host)
	}
	defer func() { _ = response.Body.Close() }()
	var body, readErr = io.ReadAll(response.Body)
	var latency = time.Since(start)
	if readErr != nil {
		return nil, checkClassifyError(ctx, readErr, opn.BaseUrl.Host)
	}

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, &CheckError{Step: "auth", Err: errors.New("authentication failed"),
			Hint: "check OPN_APIKEY and OPN_APISECRET, and that the key's user is not disabled"}
	case http.StatusForbidden:
		return nil, &CheckError{Step: "auth", Err: errors.New("the credentials work, but access was denied"),
			Hint: "the user of the API key needs the privilege for " + checkEndpoint}
	default:
		return nil, &CheckError{Step: "api", Err: fmt.Errorf("HTTP %s from %s", response.Status, endpoint),
			Hint: "is OPN_URL the address of the OPNsense web GUI, without a path?"}
	}

	// a wrong path is redirected to the HTML login page, which answers 200 too
	var mediaType, _, _ = mime.ParseMediaType(response.Header.Get("Content-Type"))
	var info struct {
		Name     string   `json:"name"`
		Versions []string `json:"versions"`
	}
	if mediaType == "text/html" || json.Unmarshal(body, &info) != nil || (info.Name == "" && len(info.Versions) == 0) {
		var got = mediaType
		if got == "" {
			got = "no content type"
		}
		var where = endpoint
		if response.Request != nil && response.Request.URL.String() != endpoint {
			where = endpoint + " (redirected to " + response.Request.URL.String() + ")"
		}
		return nil, &CheckError{Step: "api", Err: fmt.Errorf("no OPNsense API answer from %s, got %s", where, got),
			Hint: "is OPN_URL the address of the OPNsense web GUI, without a path?"}
	}

	var result = &CheckResult{
		Url:      opn.BaseUrl.String(),
		Hostname: info.Name,
		Versions: info.Versions,
		Protocol: response.Proto,
		Tls:      "none",
		Latency:  latency,
	}
	if response.TLS != nil {
		result.Tls = "verified"
		if opn.NoSslVerify {
			result.Tls = "not verified"
		}
	}
	return result, nil
}

// checkClassifyError turns a transport error into the failed step with a hint
func checkClassifyError(ctx context.Context, err error, host string) *CheckError {
	var dnsErr *net.DNSError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return &CheckError{Step: "connect", Err: errors.New("cancelled")}
	case errors.Is(ctx.Err(), context.DeadlineExceeded), isTimeout(err):
		return &CheckError{Step: "connect", Err: fmt.Errorf("no answer from %s in time", host),
			Hint: "is the host reachable and the port right, or a firewall rule dropping the connection?"}
	case errors.As(err, &dnsErr):
		return &CheckError{Step: "dns", Err: fmt.Errorf("can not resolve %s", dnsErr.Name), Hint: "check the host name in OPN_URL"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return &CheckError{Step: "connect", Err: fmt.Errorf("connection to %s refused", host),
			Hint: "check the port in OPN_URL, it must be the port of the web GUI"}
	case errors.As(err, &unknownAuthority), errors.As(err, &verifyErr) && errors.As(verifyErr.Err, &unknownAuthority):
		return &CheckError{Step: "tls", Err: errors.New("the certificate is not signed by a trusted CA"),
			Hint: "trust the CA on this machine, or set OPN_NOSSLVERIFY=1 for a self-signed certificate"}
	case errors.As(err, &hostnameErr):
		return &CheckError{Step: "tls", Err: fmt.Errorf("the certificate is not valid for %s", hostnameErr.Host),
			Hint: "use the host name the certificate was made for in OPN_URL, or set OPN_NOSSLVERIFY=1"}
	case errors.As(err, &invalidCert):
		return &CheckError{Step: "tls", Err: fmt.Errorf("invalid certificate: %v", invalidCert),
			Hint: "renew the web GUI certificate, or set OPN_NOSSLVERIFY=1"}
	case errors.As(err, &recordErr):
		return &CheckError{Step: "tls", Err: errors.New("the server does not speak TLS"),
			Hint: "use http:// in OPN_URL, or the HTTPS port"}
	}
	// drop the `Get "<url>": ` prefix of *url.Error, the step tells what was done
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	switch {
	case strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return &CheckError{Step: "tls", Err: errors.New("the server does not speak TLS"), Hint: "use http:// in OPN_URL, or the HTTPS port"}
	case strings.HasPrefix(err.Error(), "remote error: tls:"):
		return &CheckError{Step: "tls", Err: err, Hint: "the server refused the TLS handshake, check the host name and port in OPN_URL"}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return &CheckError{Step: "connect", Err: errors.New("the server closed the connection"),
			Hint: "check http:// or https:// and the port in OPN_URL"}
	}
	return &CheckError{Step: "connect", Err: err}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
