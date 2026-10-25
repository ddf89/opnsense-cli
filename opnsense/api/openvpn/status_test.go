package openvpn

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	coreapi "opnsense-cli/opnsense/api"
)

// statusTestSessions is shaped like search_sessions of 26.7: every row has the same keys (nulls for missing ones)
const statusTestSessions = `{"total":4,"rowCount":4,"current":1,"rows":[` +
	`{"socket":"/var/etc/openvpn/instance-u-srv.sock","status":"ok","type":"server","id":"u-srv_203.0.113.7:51820","description":"office","connected_since":"2026-10-25 14:03:12","timestamp":null,` +
	`"common_name":"alice","real_address":"203.0.113.7:51820","virtual_address":"10.8.0.2","virtual_ipv6_address":"fd00:8::2","bytes_received":"123456","bytes_sent":"7890",` +
	`"connected_since__time_t_":"1761401000","username":"UNDEF","client_id":"0","peer_id":"0","data_channel_cipher":"AES-256-GCM","is_client":true,"service_id":null},` +
	`{"socket":"/var/etc/openvpn/instance-u-cli.sock","status":"connected","type":"client","id":"u-cli","description":"uplink","connected_since":"2026-10-25 13:00:00","timestamp":1761397200,` +
	`"common_name":null,"real_address":"198.51.100.1:1194","virtual_address":"10.9.0.6","virtual_ipv6_address":null,"bytes_received":"100","bytes_sent":"200",` +
	`"connected_since__time_t_":null,"username":null,"client_id":null,"peer_id":null,"data_channel_cipher":null,"is_client":null,"service_id":null},` +
	`{"socket":"/var/etc/openvpn/instance-u-idle.sock","status":"ok","type":"server","id":"u-idle","description":"idle","connected_since":null,"timestamp":null,` +
	`"common_name":null,"real_address":null,"virtual_address":null,"virtual_ipv6_address":null,"bytes_received":null,"bytes_sent":null,` +
	`"connected_since__time_t_":null,"username":null,"client_id":null,"peer_id":null,"data_channel_cipher":null,"is_client":null,"service_id":null},` +
	`{"socket":null,"status":null,"type":"server","id":"u-down","description":"down","connected_since":null,"timestamp":null,` +
	`"common_name":null,"real_address":null,"virtual_address":null,"virtual_ipv6_address":null,"bytes_received":null,"bytes_sent":null,` +
	`"connected_since__time_t_":null,"username":null,"client_id":null,"peer_id":null,"data_channel_cipher":null,"is_client":null,"service_id":"openvpn/u-down"}]}`

const statusTestRoutes = `{"total":1,"rowCount":1,"current":1,"rows":[` +
	`{"virtual_address":"10.8.0.2","common_name":"alice","real_address":"203.0.113.7:51820","last_ref":"2026-10-25 14:05:00","last_ref__time_t_":"1761401100","type":"server","id":"u-srv","description":"office"}]}`

func TestSessionList(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return statusTestSessions })
	var sessions, err = api.SessionList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 4 {
		t.Fatalf("want 4 sessions, got %d", len(sessions))
	}

	var alice = sessions[0]
	if !alice.IsClient || alice.CommonName != "alice" || alice.RealAddress != "203.0.113.7:51820" || alice.InstanceId() != "u-srv" ||
		alice.BytesReceived != "123456" || alice.VirtualIpv6Address != "fd00:8::2" || alice.DataChannelCipher != "AES-256-GCM" ||
		alice.Description != "office" || !alice.Running() {
		t.Errorf("unexpected client session %+v", alice)
	}
	if since, ok := alice.ConnectedSinceTime(); !ok || !since.Equal(time.Unix(1761401000, 0)) {
		t.Errorf("connected since: %v %v", since, ok)
	}
	if !json.Valid(alice.Raw) || !strings.Contains(string(alice.Raw), `"is_client":true`) {
		t.Errorf("raw row not kept: %s", alice.Raw)
	}

	var uplink = sessions[1]
	if uplink.IsClient || uplink.InstanceId() != "u-cli" || uplink.Status != "connected" || uplink.ConnectedSinceEpoch != 1761397200 {
		t.Errorf("unexpected client instance %+v", uplink)
	}
	if down := sessions[3]; down.Running() || down.ServiceId != "openvpn/u-down" || down.Status != "" || down.CommonName != "" {
		t.Errorf("unexpected stopped instance %+v", down)
	}
	if got := requests()[0]; got.Method != "GET" || got.Path != "/api/openvpn/service/search_sessions" || len(got.Query) != 0 {
		t.Errorf("unexpected request %+v", got)
	}

	if _, err = api.SessionList("alice", "server"); err != nil {
		t.Fatal(err)
	}
	if got := requests()[1].Query; got.Get("searchPhrase") != "alice" || strings.Join(got["type[]"], ",") != "server" {
		t.Errorf("unexpected query %v", got)
	}
}

func TestRouteList(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return statusTestRoutes })
	var routes, err = api.RouteList("", "server", "client")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].VirtualAddress != "10.8.0.2" || routes[0].CommonName != "alice" || routes[0].Id != "u-srv" ||
		routes[0].LastRefEpoch != 1761401100 || routes[0].Description != "office" || len(routes[0].Raw) == 0 {
		t.Errorf("unexpected routes %+v", routes)
	}
	if got := requests()[0]; got.Path != "/api/openvpn/service/search_routes" || strings.Join(got.Query["type[]"], ",") != "server,client" {
		t.Errorf("unexpected request %+v", got)
	}
}

func TestSessionKill(t *testing.T) {
	for _, tc := range []struct {
		answer   string
		clients  int
		notFound bool
		err      string
	}{
		{answer: `{"status":"killed","clients":1}`, clients: 1},
		{answer: `{"status":"not_found"}`, notFound: true},
		{answer: `{"status":"server_not_found"}`, notFound: true, err: "is it running"},
		{answer: `{"result":"failed"}`, err: "failed"},
		{answer: `{"status":"invalid"}`, err: "invalid"},
	} {
		var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return tc.answer })
		var clients, err = api.SessionKill("u-srv", "203.0.113.7:51820")
		if clients != tc.clients || coreapi.IsNotFound(err) != tc.notFound || (tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err))) ||
			(tc.err == "" && !tc.notFound && err != nil) {
			t.Errorf("%s: got %d / %v", tc.answer, clients, err)
		}
		var request = requests()[0]
		var body map[string]string
		_ = json.Unmarshal([]byte(request.Body), &body)
		if request.Method != "POST" || request.Path != "/api/openvpn/service/kill_session" ||
			body["server_id"] != "u-srv" || body["session_id"] != "203.0.113.7:51820" {
			t.Errorf("unexpected request %+v", request)
		}
	}

	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return `{}` })
	if _, err := api.SessionKill("", "x"); err == nil || len(requests()) != 0 {
		t.Errorf("an empty instance must fail without request, got %v", err)
	}
	if _, err := api.SessionKill("u-srv", "", ""); err == nil || len(requests()) != 0 {
		t.Errorf("no session must fail without request, got %v", err)
	}
}

// like the GUI: the address first, then the common name (a reconnected client has a new address)
func TestSessionKillFallsBackToCommonName(t *testing.T) {
	var api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any {
		if strings.Contains(r.Body, `"session_id":"alice"`) {
			return `{"status":"killed","clients":2}`
		}
		return `{"status":"not_found"}`
	})
	var clients, err = api.SessionKill("u-srv", "203.0.113.7:51820", "alice")
	if err != nil || clients != 2 || len(requests()) != 2 {
		t.Errorf("got %d / %v after %d requests", clients, err, len(requests()))
	}

	clients, err = api.SessionKill("u-srv", "203.0.113.7:51820", "bob")
	if !coreapi.IsNotFound(err) || clients != 0 || !strings.Contains(err.Error(), "203.0.113.7:51820 / bob") {
		t.Errorf("want NotFoundError naming both, got %d / %v", clients, err)
	}

	// a server without socket ends the attempts
	api, requests = newClientOverrideTestApi(t, func(r clientOverrideTestRequest) any { return `{"status":"server_not_found"}` })
	if _, err = api.SessionKill("u-srv", "203.0.113.7:51820", "alice"); !coreapi.IsNotFound(err) || len(requests()) != 1 {
		t.Errorf("want one request and NotFoundError, got %v after %d", err, len(requests()))
	}
}
