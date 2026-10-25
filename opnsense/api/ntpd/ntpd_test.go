package ntpd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

func newTestApi(t *testing.T, answers map[string]string) *NtpdApi {
	t.Helper()
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, answers[r.Method+" "+r.URL.Path])
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &NtpdApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}
}

const statusTestAnswer = `{"total":2,"rowCount":2,"current":1,"rows":[` +
	`{"status":"__pool","server":"0.opnsense.pool.ntp.org","refid":".POOL.","stratum":"16","type":"p","when":"-","poll":"64",` +
	`"reach":"0","delay":"0.000","offset":"+0.000","jitter":"0.000"},` +
	`{"status":"*","server":"193.203.3.171","refid":".GPS.","stratum":"1","type":"u","when":"24","poll":"64","reach":"377",` +
	`"delay":"50.195","offset":"-2.356","jitter":"9.305"}]}`

func TestStatus(t *testing.T) {
	var api = newTestApi(t, map[string]string{"GET /api/ntpd/service/status": statusTestAnswer})
	var peers, err = api.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %+v", peers)
	}
	var active = peers[1]
	if active.Status != "*" || active.Server != "193.203.3.171" || active.RefId != ".GPS." || active.Stratum != "1" ||
		active.Type != "u" || active.When != "24" || active.Reach != "377" || active.Offset != "-2.356" || active.Jitter != "9.305" {
		t.Errorf("unexpected %+v", active)
	}
	if !strings.Contains(string(active.Raw), `"refid":".GPS."`) {
		t.Errorf("Raw: %s", active.Raw)
	}
	if PeerStatusNames[peers[0].Status] != "DNS pool" {
		t.Errorf("status name of %q", peers[0].Status)
	}
}

func TestGps(t *testing.T) {
	var api = newTestApi(t, map[string]string{"GET /api/ntpd/service/gps": `{"ntpq_servers":[],"gps":[]}`})
	if gps, err := api.Gps(); err != nil || gps != nil {
		t.Errorf("no GPS: %v / %v", gps, err)
	}
	api = newTestApi(t, map[string]string{"GET /api/ntpd/service/gps": `{"ntpq_servers":[],"gps":{"sentence":"$GPRMC","ok":true,"lat":52.5}}`})
	var gps, err = api.Gps()
	if err != nil || gps["sentence"] != "$GPRMC" || gps["lat"] != 52.5 {
		t.Errorf("GPS: %v / %v", gps, err)
	}
	api = newTestApi(t, map[string]string{})
	if _, err := api.Gps(); err == nil {
		t.Error("want an error for an empty answer")
	}
}
