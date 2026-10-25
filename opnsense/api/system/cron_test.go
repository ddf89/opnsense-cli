package system

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"testing"
)

// cronTestApi returns a SystemApi talking to a test server which answers with handler
func cronTestApi(t *testing.T, handler http.HandlerFunc) *SystemApi {
	t.Helper()
	var server = httptest.NewServer(handler)
	t.Cleanup(server.Close)

	var serverUrl, err = url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &SystemApi{OPNsense: &coreapi.OPNsense{BaseUrl: *serverUrl, ApiKey: "key", ApiSecret: "secret"}}
}

const cronTestSearchAnswer = `{"rows":[
 {"uuid":"u1","origin":"cron","enabled":"1","minutes":"0","hours":"3","days":"*","months":"*","weekdays":"*","who":"root",
  "command":"firmware poll","%command":"Firmware update check","parameters":"","description":"nightly"},
 {"uuid":"u2","origin":"cron","enabled":"0","minutes":"*/5","hours":"*","days":"*","months":"*","weekdays":"1-5","who":"root",
  "command":"dns reload","%command":"Reload system DNS resolver configuration","parameters":"-v","description":"nightly backup"},
 {"uuid":"u3","origin":"cron","enabled":"1","minutes":"0","hours":"0","days":"*","months":"*","weekdays":"*","who":"root",
  "command":"dns reload","%command":"Reload system DNS resolver configuration","parameters":"","description":"dup"},
 {"uuid":"u4","origin":"cron","enabled":"1","minutes":"0","hours":"0","days":"*","months":"*","weekdays":"*","who":"root",
  "command":"dns reload","%command":"Reload system DNS resolver configuration","parameters":"","description":"dup"}
],"rowCount":4,"total":4,"current":1}`

func cronTestSearchHandler(t *testing.T, searchPhrase *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/cron/settings/search_jobs" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if searchPhrase != nil {
			*searchPhrase = r.URL.Query().Get("searchPhrase")
		}
		_, _ = io.WriteString(w, cronTestSearchAnswer)
	}
}

func TestCronJobListDecodesRows(t *testing.T) {
	var api = cronTestApi(t, cronTestSearchHandler(t, nil))

	var jobs, err = api.CronJobList()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 4 {
		t.Fatalf("expected 4 jobs, got %d", len(jobs))
	}
	var job = jobs[1]
	if job.Uuid != "u2" || job.Enabled != "0" || job.Command != "dns reload" || job.Parameters != "-v" ||
		job.CommandDescription != "Reload system DNS resolver configuration" || job.Origin != "cron" {
		t.Errorf("unexpected job %+v", job)
	}
	if job.Schedule() != "*/5 * * * 1-5" {
		t.Errorf("unexpected schedule %q", job.Schedule())
	}
}

func TestCronJobGet(t *testing.T) {
	var api = cronTestApi(t, cronTestSearchHandler(t, nil))

	var job, err = api.CronJobGet("u2")
	if err != nil {
		t.Fatal(err)
	}
	if job.Description != "nightly backup" {
		t.Errorf("unexpected job %+v", job)
	}
	if _, err = api.CronJobGet("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestCronJobGetByDescriptionMatchesExactly(t *testing.T) {
	var searchPhrase string
	var api = cronTestApi(t, cronTestSearchHandler(t, &searchPhrase))

	// "nightly" is also a substring of "nightly backup"
	var job, err = api.CronJobGetByDescription("nightly")
	if err != nil {
		t.Fatal(err)
	}
	if job.Uuid != "u1" {
		t.Errorf("expected u1, got %q", job.Uuid)
	}
	if searchPhrase != "nightly" {
		t.Errorf("expected searchPhrase nightly, got %q", searchPhrase)
	}

	var tooMany *coreapi.TooManyFoundError
	if _, err = api.CronJobGetByDescription("dup"); !errors.As(err, &tooMany) {
		t.Errorf("expected TooManyFoundError, got %v", err)
	}
	if _, err = api.CronJobGetByDescription("night"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	if _, err = api.CronJobGetByDescription(""); err == nil {
		t.Errorf("expected an error for an empty description")
	}
}

func TestCronJobCreateSendsOnlySetFields(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/cron/settings/add_job" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		var expected = map[string]string{"command": "firmware poll", "description": "poll", "hours": "4", "enabled": "0"}
		if len(body["job"]) != len(expected) {
			t.Errorf("expected body %v, got %v", expected, body)
		}
		for key, value := range expected {
			if body["job"][key] != value {
				t.Errorf("expected %s=%q, got %v", key, value, body)
			}
		}
		_, _ = io.WriteString(w, `{"result":"saved","uuid":"new-uuid"}`)
	})

	// uuid, origin and empty fields are not sent
	var uuid, err = api.CronJobCreate(CronJob{Uuid: "ignored", Origin: "ignored", Command: "firmware poll", Description: "poll", Hours: "4", Enabled: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "new-uuid" {
		t.Errorf("expected new-uuid, got %q", uuid)
	}
}

func TestCronJobCreateSurfacesValidationError(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"result":"failed","validations":{"job.command":"Select a command from the list.","job.hours":["Value needs to be between 0 and 23"]}}`)
	})

	var _, err = api.CronJobCreate(CronJob{Command: "bogus", Description: "x", Hours: "25"})
	var validationErr *coreapi.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	if validationErr.Validations["job.command"] == "" || validationErr.Validations["job.hours"] == "" {
		t.Errorf("expected messages for job.command and job.hours, got %v", validationErr.Validations)
	}
}

func TestCronJobUpdateSendsPatch(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/cron/settings/set_job/u1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		// an empty value given explicitly is sent, nil fields are not
		if len(body["job"]) != 2 || body["job"]["hours"] != "5" {
			t.Errorf("unexpected body %v", body)
		}
		if parameters, sent := body["job"]["parameters"]; !sent || parameters != "" {
			t.Errorf("expected empty parameters to be sent, got %v", body)
		}
		_, _ = io.WriteString(w, `{"result":"saved"}`)
	})

	var hours, parameters = "5", ""
	if err := api.CronJobUpdate("u1", CronJobPatch{Hours: &hours, Parameters: &parameters}); err != nil {
		t.Fatal(err)
	}
}

func TestCronJobUpdateUnknownUuid(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"result":"failed"}`)
	})

	var hours = "5"
	if err := api.CronJobUpdate("unknown", CronJobPatch{Hours: &hours}); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	if err := api.CronJobUpdate("", CronJobPatch{Hours: &hours}); err == nil {
		t.Errorf("expected an error for an empty uuid")
	}
}

func TestCronJobRemove(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/cron/settings/del_job/u1":
			_, _ = io.WriteString(w, `{"result":"deleted"}`)
		case "/api/cron/settings/del_job/registered":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"errorMessage":"Cannot delete this automatically registered cron job.","errorTitle":""}`)
		default:
			_, _ = io.WriteString(w, `{"result":"not found"}`)
		}
	})

	if err := api.CronJobRemove("u1"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := api.CronJobRemove("unknown"); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
	var httpErr *coreapi.HttpError
	if err := api.CronJobRemove("registered"); !errors.As(err, &httpErr) || httpErr.Message != "Cannot delete this automatically registered cron job." {
		t.Errorf("expected HttpError with message, got %v", err)
	}
	if err := api.CronJobRemove(""); err == nil {
		t.Errorf("expected an error for an empty uuid")
	}
}

func TestCronJobSetEnabled(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/cron/settings/toggle_job/u1/1":
			_, _ = io.WriteString(w, `{"result":"Enabled","changed":true}`)
		case "/api/cron/settings/toggle_job/u1/0":
			_, _ = io.WriteString(w, `{"result":"Disabled","changed":false}`)
		default:
			_, _ = io.WriteString(w, `{"result":"failed"}`)
		}
	})

	if changed, err := api.CronJobSetEnabled("u1", true); err != nil || !changed {
		t.Errorf("expected changed without error, got %v, %v", changed, err)
	}
	if changed, err := api.CronJobSetEnabled("u1", false); err != nil || changed {
		t.Errorf("expected unchanged without error, got %v, %v", changed, err)
	}
	if _, err := api.CronJobSetEnabled("unknown", true); !coreapi.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestCronCommands(t *testing.T) {
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/cron/settings/get_job" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"job":{"origin":"cron","enabled":"1","command":{
			"system reboot":{"value":"Reboot the system","selected":0},
			"dns reload":{"value":"Reload system DNS resolver configuration","selected":0},
			"":{"value":"","selected":1}}}}`)
	})

	var commands, err = api.CronCommands()
	if err != nil {
		t.Fatal(err)
	}
	var expected = []CronCommand{
		{Key: "dns reload", Description: "Reload system DNS resolver configuration"},
		{Key: "system reboot", Description: "Reboot the system"},
	}
	if len(commands) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, commands)
	}
	for i := range expected {
		if commands[i] != expected[i] {
			t.Errorf("expected %v, got %v", expected[i], commands[i])
		}
	}
}

func TestCronReconfigure(t *testing.T) {
	var answer string
	var api = cronTestApi(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/cron/service/reconfigure" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, answer)
	})

	answer = `{"status":"ok"}`
	if err := api.CronReconfigure(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	answer = `{"status":"failed"}`
	if err := api.CronReconfigure(); err == nil {
		t.Errorf("expected an error")
	}
}
