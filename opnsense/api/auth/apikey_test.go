package auth

import (
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const apiKeyTestSearch = `{"total":2,"rowCount":2,"current":1,"rows":[` +
	`{"username":"root","key":"cm9vdGtleQ+/","id":"Y205dmRHdGxlUSsv"},` +
	`{"username":"alice","key":"YWxpY2VrZXk=","id":"WVd4cFkyVnJaWGs9"}]}`

func apiKeyTestHandler(add *string, del *string) func(r testRequest) (int, string) {
	return func(r testRequest) (int, string) {
		switch {
		case strings.HasSuffix(r.Path, "/search_api_key"):
			return 200, apiKeyTestSearch
		case strings.HasSuffix(r.Path, "/user/search"):
			return 200, userTestSearch
		case strings.Contains(r.Path, "/add_api_key/"):
			return 200, *add
		}
		return 200, *del
	}
}

func TestApiKeyList(t *testing.T) {
	var api, _ = newTestApi(t, apiKeyTestHandler(new(string), new(string)))
	var keys, err = api.ApiKeyList()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != (ApiKey{Id: "Y205dmRHdGxlUSsv", Key: "cm9vdGtleQ+/", Username: "root"}) {
		t.Errorf("unexpected %+v", keys)
	}
	if ApiKeyId(keys[1].Key) != keys[1].Id {
		t.Errorf("ApiKeyId(%q) = %q, OPNsense says %q", keys[1].Key, ApiKeyId(keys[1].Key), keys[1].Id)
	}
}

func TestApiKeyCreate(t *testing.T) {
	var add = `{"result":"ok","hostname":"fw.example.lan","key":"bmV3a2V5","secret":"bmV3c2VjcmV0"}`
	var api, requests = newTestApi(t, apiKeyTestHandler(&add, new(string)))
	var created, err = api.ApiKeyCreate("alice")
	if err != nil {
		t.Fatal(err)
	}
	if created != (NewApiKey{Key: "bmV3a2V5", Secret: "bmV3c2VjcmV0", Hostname: "fw.example.lan"}) {
		t.Errorf("unexpected %+v", created)
	}
	var calls = posts(*requests)
	if len(calls) != 1 || calls[0].Path != "/api/auth/user/add_api_key/alice" {
		t.Errorf("unexpected requests %+v", *requests)
	}

	if _, err := api.ApiKeyCreate("ghost"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	add = `{"result":"failed"}`
	if _, err := api.ApiKeyCreate("alice"); err == nil {
		t.Error("want an error for result failed")
	}
}

func TestApiKeyRemove(t *testing.T) {
	var del = `{"result":"deleted"}`
	var api, requests = newTestApi(t, apiKeyTestHandler(new(string), &del))
	if err := api.ApiKeyRemove("WVd4cFkyVnJaWGs9"); err != nil {
		t.Fatal(err)
	}
	if calls := posts(*requests); len(calls) != 1 || calls[0].Path != "/api/auth/user/del_api_key/WVd4cFkyVnJaWGs9" {
		t.Errorf("unexpected requests %+v", *requests)
	}
	del = `{"result":"not found"}`
	if err := api.ApiKeyRemove("WVd4cFkyVnJaWGs9"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	for _, id := range []string{"", "a/b", "not base64!"} {
		if err := api.ApiKeyRemove(id); err == nil {
			t.Errorf("id %q: want an error", id)
		}
	}
	if len(posts(*requests)) != 2 {
		t.Errorf("invalid ids were sent: %+v", posts(*requests))
	}
}
