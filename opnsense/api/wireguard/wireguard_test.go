package wireguard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]any
}

// testApi starts a fake OPNsense answering "METHOD /path" with the JSON in answers (a string is sent as it is,
// anything else encoded), unknown endpoints with an empty 200 like OPNsense. All requests are recorded
func testApi(t *testing.T, answers map[string]any) (*WireguardApi, func() []testRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []testRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = testRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		mu.Lock()
		requests = append(requests, recorded)
		mu.Unlock()
		var answer, found = answers[r.Method+" "+r.URL.Path]
		if !found {
			return
		}
		if text, isText := answer.(string); isText {
			_, _ = io.WriteString(w, text)
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(server.Close)
	var baseUrl, _ = url.Parse(server.URL)
	return &WireguardApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, func() []testRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]testRequest(nil), requests...)
	}
}

func testRows(items ...any) map[string]any {
	return map[string]any{"rows": items, "rowCount": len(items), "total": len(items), "current": 1}
}

func testMutations(requests []testRequest) []testRequest {
	var result []testRequest
	for _, request := range requests {
		if request.Method != "GET" {
			result = append(result, request)
		}
	}
	return result
}

const (
	testServerSearch = "/api/wireguard/server/search_server"
	testClientSearch = "/api/wireguard/client/search_client"
	// RFC 7748 6.1, Alice
	testPrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
	testPublicKey  = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
)

func testInstanceRow(overrides map[string]any) map[string]any {
	var row = map[string]any{
		"uuid": "i-1", "enabled": "1", "name": "wg-office", "instance": "0", "pubkey": testPublicKey, "privkey": testPrivateKey,
		"port": "51820", "mtu": "", "dns": "", "tunneladdress": "10.9.0.1/24", "disableroutes": "0", "gateway": "",
		"carp_depend_on": "", "peers": "p-1,p-2", "%peers": "laptop, phone", "debug": "0",
		"cnfFilename": "/usr/local/etc/wireguard/wg0.conf", "statFilename": "/usr/local/etc/wireguard/wg0.stat",
		"interface": "wg0", "endpoint": "vpn.example.com:51820", "peer_dns": "10.9.0.1",
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func testPeerRow(overrides map[string]any) map[string]any {
	var row = map[string]any{
		"uuid": "p-1", "enabled": "1", "name": "laptop", "pubkey": testPublicKey, "psk": "", "tunneladdress": "10.9.0.2/32",
		"serveraddress": "", "serverport": "", "endpoint": "", "keepalive": "", "servers": "i-1", "%servers": "wg-office",
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func TestKeys(t *testing.T) {
	if got, err := PublicKeyOf(testPrivateKey); err != nil || got != testPublicKey {
		t.Errorf("PublicKeyOf: %q %v", got, err)
	}
	for _, bad := range []string{"", "abc", "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LC==", "!!!"} {
		if _, err := PublicKeyOf(bad); err == nil {
			t.Errorf("PublicKeyOf(%q) must fail", bad)
		}
		if ValidateKey(bad) == nil {
			t.Errorf("ValidateKey(%q) must fail", bad)
		}
	}
	if err := ValidateKey(testPublicKey); err != nil {
		t.Error(err)
	}

	var api, requests = testApi(t, map[string]any{
		"GET /api/wireguard/server/key_pair": map[string]string{"status": "ok", "pubkey": testPublicKey, "privkey": testPrivateKey},
		"GET /api/wireguard/client/psk":      map[string]string{"status": "ok", "psk": testPublicKey},
	})
	if pair, err := api.KeyPair(); err != nil || pair.PublicKey != testPublicKey || pair.PrivateKey != testPrivateKey {
		t.Errorf("KeyPair: %+v %v", pair, err)
	}
	if psk, err := api.PresharedKey(); err != nil || psk != testPublicKey {
		t.Errorf("PresharedKey: %q %v", psk, err)
	}
	if len(testMutations(requests())) != 0 {
		t.Errorf("key generation must not POST: %+v", requests())
	}

	var failing, _ = testApi(t, map[string]any{
		"GET /api/wireguard/server/key_pair": map[string]string{"status": "failed"},
		"GET /api/wireguard/client/psk":      map[string]string{"status": "ok", "psk": "short"},
	})
	if _, err := failing.KeyPair(); err == nil {
		t.Error("a failed key pair must be an error")
	}
	if _, err := failing.PresharedKey(); err == nil {
		t.Error("an invalid psk must be an error")
	}
}

func TestInstanceLookups(t *testing.T) {
	var api, requests = testApi(t, map[string]any{"GET " + testServerSearch: testRows(
		testInstanceRow(nil),
		testInstanceRow(map[string]any{"uuid": "i-2", "name": "dup"}),
		testInstanceRow(map[string]any{"uuid": "i-3", "name": "DUP"}),
	)})
	var raw, instances, err = api.InstanceListRaw("")
	if err != nil || len(raw) != 3 || len(instances) != 3 {
		t.Fatalf("InstanceListRaw: %v", err)
	}
	if instances[0].Number != "0" || instances[0].PeerNames != "laptop, phone" || instances[0].PrivateKey != testPrivateKey ||
		instances[0].Interface != "wg0" || instances[0].Endpoint != "vpn.example.com:51820" {
		t.Errorf("decoded: %+v", instances[0])
	}
	if instance, err := api.InstanceGet("I-1"); err != nil || instance.Name != "wg-office" {
		t.Errorf("InstanceGet: %+v %v", instance, err)
	}
	if _, err := api.InstanceGet("i-nope"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	if instance, err := api.InstanceGetByName("WG-Office"); err != nil || instance.Uuid != "i-1" {
		t.Errorf("by name: %+v %v", instance, err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.InstanceGetByName("dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "i-2, i-3") {
		t.Errorf("duplicates: %v", err)
	}
	if _, err := api.InstanceGetByName("wg"); !coreapi.IsNotFound(err) {
		t.Errorf("substring must not match: %v", err)
	}
	if got := requests()[len(requests())-1].Query.Get("searchPhrase"); got != "wg" {
		t.Errorf("searchPhrase %q", got)
	}
}

func TestInstanceChanges(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET " + testServerSearch:                     testRows(testInstanceRow(nil), testInstanceRow(map[string]any{"uuid": "i-off", "enabled": "0"})),
		"POST /api/wireguard/server/add_server":       `{"result":"saved","uuid":"i-new"}`,
		"POST /api/wireguard/server/set_server/i-1":   `{"result":"saved"}`,
		"POST /api/wireguard/server/set_server/i-off": `{"result":"saved"}`,
		"POST /api/wireguard/server/del_server/i-1":   `{"result":"deleted"}`,
		"POST /api/wireguard/server/del_server/i-x":   `{"result":"not found"}`,
	})
	var uuid, err = api.InstanceCreate(InstanceFields{"name": "wg-new", "enabled": "0", "privkey": testPrivateKey})
	if err != nil || uuid != "i-new" {
		t.Fatalf("create: %q %v", uuid, err)
	}
	if _, err := api.InstanceCreate(InstanceFields{"bogus": "x"}); err == nil {
		t.Error("unknown fields must fail")
	}
	if err := api.InstanceUpdate("i-1", InstanceFields{"port": "51821"}); err != nil {
		t.Fatal(err)
	}
	if err := api.InstanceUpdate("i-ghost", InstanceFields{"port": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("update of an unknown uuid must not post: %v", err)
	}
	if changed, err := api.InstanceSetEnabled("i-1", true); err != nil || changed {
		t.Errorf("enabling an enabled instance: %v %v", changed, err)
	}
	if changed, err := api.InstanceSetEnabled("i-off", true); err != nil || !changed {
		t.Errorf("enable: %v %v", changed, err)
	}
	if err := api.InstanceRemove("i-1"); err != nil {
		t.Error(err)
	}
	if err := api.InstanceRemove("i-x"); !coreapi.IsNotFound(err) {
		t.Errorf("remove unknown: %v", err)
	}
	if err := api.InstanceRemove("a,b"); err == nil {
		t.Error("a uuid list must be refused")
	}

	var posted = testMutations(requests())
	var want = []testRequest{
		{Method: "POST", Path: "/api/wireguard/server/add_server", Body: map[string]any{"server": map[string]any{"name": "wg-new", "enabled": "0", "privkey": testPrivateKey}}},
		{Method: "POST", Path: "/api/wireguard/server/set_server/i-1", Body: map[string]any{"server": map[string]any{"port": "51821"}}},
		{Method: "POST", Path: "/api/wireguard/server/set_server/i-off", Body: map[string]any{"server": map[string]any{"enabled": "1"}}},
		{Method: "POST", Path: "/api/wireguard/server/del_server/i-1"},
		{Method: "POST", Path: "/api/wireguard/server/del_server/i-x"},
	}
	if len(posted) != len(want) {
		t.Fatalf("posted %+v", posted)
	}
	for i := range want {
		if posted[i].Path != want[i].Path || !reflect.DeepEqual(posted[i].Body, want[i].Body) {
			t.Errorf("request %d: %+v, want %+v", i, posted[i], want[i])
		}
	}
}

func TestInstanceSetMalformedUuid(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET " + testServerSearch:                   testRows(testInstanceRow(map[string]any{"uuid": "odd"})),
		"POST /api/wireguard/server/set_server/odd": `{"result":"failed"}`,
	})
	if err := api.InstanceUpdate("odd", InstanceFields{"port": "1"}); !coreapi.IsNotFound(err) {
		t.Errorf("a bare failed is not found: %v", err)
	}
}

func TestInstanceOptionsAndServerInfo(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET /api/wireguard/server/get_server": `{"server":{"name":"","carp_depend_on":{"":{"value":"None","selected":1},` +
			`"vip-1":{"value":"192.0.2.9 (carp)","selected":0}},"peers":[],"tunneladdress":{"":{"value":"","selected":1}}}}`,
		"GET /api/wireguard/client/get_server_info/i-1": `{"status":"ok","endpoint":"vpn.example.com:51820","peer_dns":"10.9.0.1",` +
			`"mtu":"1420","pubkey":"` + testPublicKey + `","address":"10.9.0.3/32,fd00:9::2/128"}`,
		"GET /api/wireguard/client/get_server_info/i-x": `{"status":"failed"}`,
	})
	var options, err = api.InstanceOptions()
	if err != nil {
		t.Fatal(err)
	}
	var want = []Option{{Key: "", Description: "None", Selected: true}, {Key: "vip-1", Description: "192.0.2.9 (carp)"}}
	if !reflect.DeepEqual(options["carp_depend_on"], want) {
		t.Errorf("carp options %+v", options["carp_depend_on"])
	}
	if _, isOption := options["name"]; isOption {
		t.Error("plain fields are no options")
	}
	info, err := api.InstanceServerInfo("i-1")
	if err != nil || info.Address != "10.9.0.3/32,fd00:9::2/128" || info.Mtu != "1420" || info.PublicKey != testPublicKey || info.PeerDns != "10.9.0.1" {
		t.Errorf("server info %+v %v", info, err)
	}
	if _, err := api.InstanceServerInfo("i-x"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown instance: %v", err)
	}
}

func TestPeerLookupsAndChanges(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET " + testClientSearch: testRows(
			testPeerRow(nil),
			testPeerRow(map[string]any{"uuid": "p-2", "name": "phone", "enabled": "0", "servers": "i-1,i-2", "%servers": "wg-office,wg-home", "psk": testPrivateKey}),
		),
		"POST /api/wireguard/client/add_client":     `{"result":"saved","uuid":"p-new"}`,
		"POST /api/wireguard/client/set_client/p-1": `{"result":"saved"}`,
		"POST /api/wireguard/client/set_client/p-2": `{"result":"saved"}`,
		"POST /api/wireguard/client/del_client/p-1": `{"result":"deleted"}`,
	})
	var peers, err = api.PeerList("")
	if err != nil || len(peers) != 2 || peers[1].Psk != testPrivateKey || !reflect.DeepEqual(peers[1].InstanceUuids(), []string{"i-1", "i-2"}) {
		t.Fatalf("PeerList: %+v %v", peers, err)
	}
	if peer, err := api.PeerGetByName("PHONE"); err != nil || peer.Uuid != "p-2" {
		t.Errorf("by name: %+v %v", peer, err)
	}
	if _, err := api.PeerGet("p-x"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	if uuid, err := api.PeerCreate(PeerFields{"name": "new", "servers": "i-1"}); err != nil || uuid != "p-new" {
		t.Errorf("create %q %v", uuid, err)
	}
	if err := api.PeerUpdate("p-2", PeerFields{"keepalive": "25"}); err != nil {
		t.Error(err)
	}
	if err := api.PeerUpdate("p-1", PeerFields{"servers": ""}); err != nil {
		t.Error(err)
	}
	if err := api.PeerUpdate("p-x", PeerFields{"keepalive": "25"}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	if changed, err := api.PeerSetEnabled("p-2", true); err != nil || !changed {
		t.Errorf("enable %v %v", changed, err)
	}
	if changed, err := api.PeerSetEnabled("p-1", true); err != nil || changed {
		t.Errorf("enable enabled %v %v", changed, err)
	}
	if err := api.PeerRemove("p-1"); err != nil {
		t.Error(err)
	}

	var posted = testMutations(requests())
	var wantBodies = []map[string]any{
		{"client": map[string]any{"name": "new", "servers": "i-1"}},
		// the current instances are always sent, set_client would unlink the peer otherwise
		{"client": map[string]any{"keepalive": "25", "servers": "i-1,i-2"}},
		{"client": map[string]any{"servers": ""}},
		{"client": map[string]any{"enabled": "1", "servers": "i-1,i-2"}},
		nil,
	}
	if len(posted) != len(wantBodies) {
		t.Fatalf("posted %+v", posted)
	}
	for i, want := range wantBodies {
		if !reflect.DeepEqual(posted[i].Body, want) {
			t.Errorf("request %d %s: %v, want %v", i, posted[i].Path, posted[i].Body, want)
		}
	}
}

func TestGeneralAndService(t *testing.T) {
	var api, requests = testApi(t, map[string]any{
		"GET /api/wireguard/general/get":          `{"general":{"enabled":"1"}}`,
		"POST /api/wireguard/general/set":         `{"result":"saved"}`,
		"GET /api/wireguard/service/status":       `{"status":"running","widget":{}}`,
		"POST /api/wireguard/service/reconfigure": `{"result":"ok"}`,
		"POST /api/wireguard/service/start":       `{"response":"OK"}`,
		"POST /api/wireguard/service/stop":        `{"response":"Execute error"}`,
	})
	if enabled, err := api.GeneralEnabled(); err != nil || !enabled {
		t.Errorf("GeneralEnabled %v %v", enabled, err)
	}
	if err := api.GeneralSetEnabled(false); err != nil {
		t.Error(err)
	}
	if status, err := api.ServiceStatus(); err != nil || status != "running" {
		t.Errorf("status %q %v", status, err)
	}
	if err := api.ServiceReconfigure(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStart(); err != nil {
		t.Error(err)
	}
	if err := api.ServiceStop(); err == nil || !strings.Contains(err.Error(), "Execute error") {
		t.Errorf("stop: %v", err)
	}
	if err := api.ServiceRestart(); err == nil {
		t.Error("an empty answer must fail")
	}
	var posted = testMutations(requests())
	if !reflect.DeepEqual(posted[0].Body, map[string]any{"general": map[string]any{"enabled": "0"}}) {
		t.Errorf("general set body %v", posted[0].Body)
	}

	var failing, _ = testApi(t, map[string]any{"POST /api/wireguard/service/reconfigure": `{"result":"failed"}`})
	if err := failing.ServiceReconfigure(); err == nil {
		t.Error("failed reconfigure must be an error")
	}
}

func TestStatusList(t *testing.T) {
	var api, requests = testApi(t, map[string]any{"GET /api/wireguard/service/show": `{"rows":[
		{"if":"wg0","type":"interface","public-key":"pub0","listen-port":"51820","fwmark":"off","endpoint":"51820","status":"up","name":"wg-office","latest-handshake-age":null,"latest-handshake-epoch":null,"peer-status":"offline","ifname":"wg-office"},
		{"if":"wg0","type":"peer","public-key":"pub1","endpoint":"198.51.100.7:40000","allowed-ips":"10.9.0.2/32","latest-handshake":1761400000,"transfer-rx":1234,"transfer-tx":5678,"persistent-keepalive":"off","name":"laptop","latest-handshake-age":42,"latest-handshake-epoch":"2025-10-25 15:46:40","peer-status":"online","ifname":"wg-office"}
	],"rowCount":2,"total":2,"current":1}`})
	var statuses, err = api.StatusList("lap", "peer", "interface")
	if err != nil || len(statuses) != 2 {
		t.Fatalf("StatusList: %+v %v", statuses, err)
	}
	if statuses[0].HandshakeAge != nil || !statuses[0].Online() || statuses[0].ListenPort != "51820" {
		t.Errorf("interface %+v", statuses[0])
	}
	var peer = statuses[1]
	if peer.HandshakeAge == nil || *peer.HandshakeAge != 42 || peer.TransferRx != 1234 || peer.TransferTx != 5678 ||
		peer.LatestHandshake != 1761400000 || !peer.Online() || peer.InstanceName != "wg-office" || !strings.Contains(string(peer.Raw), `"pub1"`) {
		t.Errorf("peer %+v", peer)
	}
	var query = requests()[0].Query
	if !reflect.DeepEqual(query["type[]"], []string{"peer", "interface"}) || query.Get("searchPhrase") != "lap" {
		t.Errorf("query %v", query)
	}
}

func TestClientConfig(t *testing.T) {
	var config = ClientConfig{PrivateKey: "priv=", Address: "10.9.0.3/32,fd00:9::3/128", Dns: "10.9.0.1", Mtu: "1420",
		ServerPublicKey: "pub=", PresharedKey: "psk=", Endpoint: "vpn.example.com:51820", AllowedIps: DefaultAllowedIps, Keepalive: "25"}
	var want = "[Interface]\nPrivateKey = priv=\nAddress = 10.9.0.3/32, fd00:9::3/128\nDNS = 10.9.0.1\nMTU = 1420\n\n" +
		"[Peer]\nPublicKey = pub=\nPresharedKey = psk=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
	if got := config.String(); got != want {
		t.Errorf("config:\n%s\nwant:\n%s", got, want)
	}
	if err := config.Validate(); err != nil {
		t.Error(err)
	}
	var minimal = ClientConfig{PrivateKey: "priv=", ServerPublicKey: "pub=", Endpoint: "192.0.2.1:51820", AllowedIps: "10.0.0.0/8"}
	if got := minimal.String(); got != "[Interface]\nPrivateKey = priv=\n\n[Peer]\nPublicKey = pub=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.0.0.0/8\n" {
		t.Errorf("minimal:\n%s", got)
	}
	if err := (ClientConfig{PrivateKey: "x"}).Validate(); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("incomplete: %v", err)
	}
}
