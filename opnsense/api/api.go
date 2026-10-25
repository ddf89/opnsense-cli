package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type OPNsense struct {
	BaseUrl     url.URL
	ApiKey      string
	ApiSecret   string
	NoSslVerify bool
	// Verbose logs every request with its status and duration to stderr
	Verbose bool
	client  *http.Client
	// streamClient has no overall timeout, streams stay open until cancelled
	streamClient *http.Client
}

func (opn *OPNsense) initClients() {
	if opn.client != nil {
		return
	}
	certPool, _ := x509.SystemCertPool()
	var transport = &http.Transport{
		// a custom transport disables HTTP/2 unless forced. OPNsense 26.7 breaks HTTP/1.1 chunked responses
		// after 64KB ("malformed chunked encoding"), HTTP/2 is fine
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opn.NoSslVerify,
			RootCAs:            certPool,
		},
	}
	opn.client = &http.Client{Timeout: 60 * time.Second, Transport: transport}
	opn.streamClient = &http.Client{Transport: transport}
}

func (opn *OPNsense) Send(request *http.Request) (*http.Response, error) {
	opn.initClients()
	return opn.do(opn.client, request)
}

// SendStream is Send without a timeout, for long-lived responses like text/event-stream. Cancel the request context to stop
func (opn *OPNsense) SendStream(request *http.Request) (*http.Response, error) {
	opn.initClients()
	return opn.do(opn.streamClient, request)
}

func (opn *OPNsense) do(client *http.Client, request *http.Request) (*http.Response, error) {
	request.SetBasicAuth(opn.ApiKey, opn.ApiSecret)
	if !opn.Verbose {
		return client.Do(request)
	}

	var start = time.Now()
	var response, err = client.Do(request)
	if err != nil {
		log.Printf("%s %s: %v (%s)", request.Method, request.URL, err, time.Since(start).Round(time.Millisecond))
	} else {
		log.Printf("%s %s: %s %s (%s)", request.Method, request.URL, response.Proto, response.Status, time.Since(start).Round(time.Millisecond))
	}
	return response, err
}

type NotFoundError struct {
	Name string
	Err  error
}

type TooManyFoundError struct {
	Name string
	Err  error
}

func (f *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", f.Name)
}

func (f *TooManyFoundError) Error() string {
	return fmt.Sprintf("too many found: %s", f.Name)
}

func ConfigureFromEnv() (*OPNsense, error) {
	_ = godotenv.Load()

	if os.Getenv("OPN_URL") == "" {
		return nil, errors.New("please set OPN_URL to the URL of your OPNsense, like https://myopnsense:10443")
	}

	if os.Getenv("OPN_APIKEY") == "" {
		return nil, errors.New("please set OPN_APIKEY to your OPNsense API key")
	}

	if os.Getenv("OPN_APISECRET") == "" {
		return nil, errors.New("please set OPN_APISECRET to your OPNsense API secret")
	}

	var parsedUrl, err = url.Parse(strings.TrimRight(os.Getenv("OPN_URL"), "/"))
	if err != nil {
		return nil, err
	}

	return &OPNsense{
		BaseUrl:     *parsedUrl,
		ApiKey:      os.Getenv("OPN_APIKEY"),
		ApiSecret:   os.Getenv("OPN_APISECRET"),
		NoSslVerify: os.Getenv("OPN_NOSSLVERIFY") == "1",
	}, nil
}

// EndpointForModule so basically api/<plugin>
func (opn *OPNsense) EndpointForModule(module string) string {
	return fmt.Sprintf("%s/api/%s", opn.BaseUrl.String(), module)
}

// EndpointForModuleController so basically api/<plugin>/<controller>
func (opn *OPNsense) EndpointForModuleController(module string, controller string) string {
	return fmt.Sprintf("%s/%s", opn.EndpointForModule(module), controller)
}

// EndpointForPluginControllerMethod so basically api/<plugin>/<controller>/<method>
func (opn *OPNsense) EndpointForPluginControllerMethod(module string, controller string, method string) string {
	return fmt.Sprintf("%s/%s", opn.EndpointForModuleController(module, controller), method)
}
