package system

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type tunableTestRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   map[string]map[string]string
}

// newTunableTestApi starts a fake OPNsense answering every request with handler, all requests are recorded
func newTunableTestApi(t *testing.T, handler func(r tunableTestRequest) any) (*SystemApi, *[]tunableTestRequest) {
	t.Helper()
	var requests []tunableTestRequest
	var server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var recorded = tunableTestRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query()}
		var raw, _ = io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.Body); err != nil {
				t.Errorf("invalid request body %q: %v", raw, err)
			}
		}
		requests = append(requests, recorded)
		_ = json.NewEncoder(w).Encode(handler(recorded))
	}))
	t.Cleanup(server.Close)

	var baseUrl, _ = url.Parse(server.URL)
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *baseUrl}}, &requests
}

func tunableSearchAnswer(tunables ...Tunable) any {
	return map[string]any{"rows": tunables, "rowCount": len(tunables), "total": len(tunables), "current": 1}
}

const (
	tunableTestBuiltinUuid = "ca1670d744475726d64bc45bdc19bad5" // md5("kern.msgbuf_show_timestamp")
	tunableTestCustomUuid  = "bb2e96cd-780b-4128-ba37-6a9b8f9fa84a"
)

var tunableTestRows = []Tunable{
	{Uuid: tunableTestBuiltinUuid, Tunable: "kern.msgbuf_show_timestamp", Value: "0", DefaultValue: "1", Type: "w"},
	{Uuid: "e042e8fc-0000-4000-8000-000000000001", Tunable: "kern.ipc.maxsockbuf", Value: "8388608", DefaultValue: "4262144", Type: "w"},
	{Uuid: "e042e8fc-0000-4000-8000-000000000002", Tunable: "kern.ipc.maxsockbuf.extra", Value: "1"},
	{Uuid: tunableTestCustomUuid, Tunable: "a2sys.cli.dummy", Value: "42", Description: "a2-sys-test"},
}

func TestTunableGetByNameExactMatch(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		// the real search is a substring match
		return tunableSearchAnswer(tunableTestRows...)
	})

	var tunable, err = api.TunableGetByName("kern.ipc.maxsockbuf")
	if err != nil || tunable.Uuid != "e042e8fc-0000-4000-8000-000000000001" {
		t.Fatalf("expected kern.ipc.maxsockbuf, got %+v / %v", tunable, err)
	}
	if got := (*requests)[0]; got.Path != "/api/core/tunables/search_item" || got.Query.Get("searchPhrase") != "kern.ipc.maxsockbuf" {
		t.Errorf("unexpected search request %+v", got)
	}

	for _, name := range []string{"kern.ipc", "maxsockbuf", "KERN.IPC.MAXSOCKBUF"} {
		if _, err = api.TunableGetByName(name); !coreapi.IsNotFound(err) {
			t.Errorf("%s: expected NotFoundError, got %v", name, err)
		}
	}
}

func TestTunableGetByNameDuplicates(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		return tunableSearchAnswer(
			Tunable{Uuid: "u-2", Tunable: "a2sys.dup", Value: "1"},
			Tunable{Uuid: "u-1", Tunable: "a2sys.dup", Value: "2"},
		)
	})

	var _, err = api.TunableGetByName("a2sys.dup")
	var tooMany *coreapi.TooManyFoundError
	if !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "u-1, u-2") {
		t.Fatalf("expected TooManyFoundError naming the uuids, got %v", err)
	}

	if _, _, err = api.TunableSet("a2sys.dup", "3", nil); !errors.As(err, &tooMany) {
		t.Errorf("expected TooManyFoundError from set, got %v", err)
	}
	if len(*requests) != 2 {
		t.Errorf("set must not write anything on duplicates, got %d requests", len(*requests))
	}
}

func TestTunableSetUpdatesConfiguredEntryPartially(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_item") {
			return tunableSearchAnswer(tunableTestRows...)
		}
		return map[string]string{"result": "saved"}
	})

	var uuid, created, err = api.TunableSet("a2sys.cli.dummy", "43", nil)
	if err != nil || created || uuid != tunableTestCustomUuid {
		t.Fatalf("expected update of %s, got %s %v %v", tunableTestCustomUuid, uuid, created, err)
	}
	var set = (*requests)[1]
	if set.Method != "POST" || set.Path != "/api/core/tunables/set_item/"+tunableTestCustomUuid {
		t.Errorf("unexpected request %s %s", set.Method, set.Path)
	}
	if sent := set.Body["sysctl"]; len(sent) != 1 || sent["value"] != "43" {
		t.Errorf("expected only the value to be sent, got %v", sent)
	}

	var description = ""
	if _, _, err = api.TunableSet("a2sys.cli.dummy", "", &description); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent := (*requests)[3].Body["sysctl"]; len(sent) != 2 || sent["value"] != "" || sent["descr"] != "" {
		t.Errorf("expected value and descr to be sent, got %v", sent)
	}
}

func TestTunableSetOverridesBuiltinAndCreatesUnknown(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_item") {
			return tunableSearchAnswer(tunableTestRows...)
		}
		return map[string]string{"result": "saved", "uuid": "u-new"}
	})

	for _, name := range []string{"kern.msgbuf_show_timestamp", "a2sys.cli.new"} {
		*requests = nil
		var uuid, created, err = api.TunableSet(name, "1", nil)
		if err != nil || !created || uuid != "u-new" {
			t.Fatalf("%s: expected create, got %s %v %v", name, uuid, created, err)
		}
		// a built-in must be overridden with a complete add_item, set_item on its md5 key would create an empty entry
		var add = (*requests)[1]
		if add.Path != "/api/core/tunables/add_item" {
			t.Errorf("%s: expected add_item, got %s", name, add.Path)
		}
		if sent := add.Body["sysctl"]; sent["tunable"] != name || sent["value"] != "1" || len(sent) != 3 {
			t.Errorf("%s: unexpected body %v", name, sent)
		}
	}
}

func TestTunableValidation(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		return tunableSearchAnswer()
	})

	for _, invalid := range [][2]string{{"", "1"}, {"bad name", "1"}, {"kern..x", "1"}, {"a2sys.x", "a\nb"}, {"a2sys.x", `"1"`}} {
		if _, _, err := api.TunableSet(invalid[0], invalid[1], nil); err == nil {
			t.Errorf("%q=%q: expected validation error", invalid[0], invalid[1])
		}
	}
	if err := api.TunableUpdate(tunableTestCustomUuid, TunableFields{"tunable": "bad name"}); err == nil {
		t.Errorf("expected validation error for name update")
	}
	if err := api.TunableUpdate(tunableTestCustomUuid, TunableFields{"description": "typo"}); err == nil {
		t.Errorf("expected error for unknown field")
	}
	if err := api.TunableUpdate(tunableTestBuiltinUuid, TunableFields{"value": "1"}); err == nil {
		t.Errorf("expected error for updating a built-in")
	}
	if len(*requests) != 0 {
		t.Errorf("invalid input must not be sent, got %d requests", len(*requests))
	}

	for _, valid := range []string{"kern.ipc.maxsockbuf", "hint.uart.0.at", "dev.em.0.%desc", "if_em_load", "net.inet.tcp.cc.algorithm"} {
		if err := TunableValidate(valid, "some value 1,2"); err != nil {
			t.Errorf("%s: unexpected error %v", valid, err)
		}
	}
}

func TestTunableValidationErrorSurfaced(t *testing.T) {
	var api, _ = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_item") {
			return tunableSearchAnswer(tunableTestRows...)
		}
		return map[string]any{"result": "failed", "validations": map[string]any{"sysctl.value": []string{"too long", "invalid"}}}
	})

	var err = api.TunableUpdate(tunableTestCustomUuid, TunableFields{"value": "1"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "sysctl.value: too long; invalid") {
		t.Errorf("expected ValidationError, got %v", err)
	}
}

func TestTunableUpdateUnknownUuid(t *testing.T) {
	// OPNsense 26.7 set_item creates a new entry for any uuid which does not exist, even malformed ones
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_item") {
			return tunableSearchAnswer(tunableTestRows...)
		}
		return map[string]string{"result": "saved"}
	})

	for _, uuid := range []string{"0b3c6a1e-2f4d-4e5a-9b7c-8d9e0f1a2b3c", "not-a-uuid"} {
		if err := api.TunableUpdate(uuid, TunableFields{"value": "1"}); !coreapi.IsNotFound(err) {
			t.Errorf("%s: expected NotFoundError, got %v", uuid, err)
		}
	}
	for _, request := range *requests {
		if request.Method != "GET" {
			t.Errorf("an unknown uuid must not be written: %s %s", request.Method, request.Path)
		}
	}
}

func TestTunableUpdateChecksExistenceFirst(t *testing.T) {
	var answer = map[string]string{"result": "saved"}
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/search_item") {
			return tunableSearchAnswer(tunableTestRows...)
		}
		return answer
	})

	if err := api.TunableUpdate(tunableTestCustomUuid, TunableFields{"descr": "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*requests) != 2 || (*requests)[0].Path != "/api/core/tunables/search_item" ||
		(*requests)[1].Path != "/api/core/tunables/set_item/"+tunableTestCustomUuid {
		t.Errorf("expected search_item then set_item, got %+v", *requests)
	}

	// deleted between the existence check and the write: bare failure
	answer = map[string]string{"result": "failed"}
	if err := api.TunableUpdate(tunableTestCustomUuid, TunableFields{"descr": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
}

func TestTunableRemove(t *testing.T) {
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		if strings.HasSuffix(r.Path, "/"+tunableTestCustomUuid) {
			return map[string]string{"result": "deleted"}
		}
		return map[string]string{"result": "not found"}
	})

	if err := api.TunableRemove(tunableTestCustomUuid); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/core/tunables/del_item/"+tunableTestCustomUuid {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	if err := api.TunableRemove("00000000-0000-0000-0000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("expected NotFoundError, got %v", err)
	}
	if err := api.TunableRemove(tunableTestBuiltinUuid); err == nil || coreapi.IsNotFound(err) {
		t.Errorf("expected built-in error, got %v", err)
	}
	if len(*requests) != 2 {
		t.Errorf("removing a built-in must not be sent")
	}
}

func TestTunableReconfigure(t *testing.T) {
	var status = "ok"
	var api, requests = newTunableTestApi(t, func(r tunableTestRequest) any {
		return map[string]string{"status": status}
	})

	if err := api.TunableReconfigure(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != "/api/core/tunables/reconfigure" {
		t.Errorf("unexpected request %s %s", got.Method, got.Path)
	}
	status = "failed"
	if err := api.TunableReconfigure(); err == nil {
		t.Errorf("expected error for status failed")
	}
}

func TestTunableIsChanged(t *testing.T) {
	var cases = []struct {
		tunable Tunable
		changed bool
	}{
		{Tunable{Uuid: tunableTestBuiltinUuid, Value: "0", DefaultValue: "1"}, false}, // runtime value of a built-in
		{Tunable{Uuid: tunableTestCustomUuid, Value: "", DefaultValue: "1"}, false},   // configured to use the default
		{Tunable{Uuid: tunableTestCustomUuid, Value: "1", DefaultValue: "1"}, false},
		{Tunable{Uuid: tunableTestCustomUuid, Value: "2", DefaultValue: "1"}, true},
		{Tunable{Uuid: tunableTestCustomUuid, Value: "2"}, true}, // custom tunable
	}
	for _, c := range cases {
		if c.tunable.IsChanged() != c.changed {
			t.Errorf("%+v: expected changed=%v", c.tunable, c.changed)
		}
	}
}
