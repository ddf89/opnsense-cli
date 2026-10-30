package auth

import (
	"reflect"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

func TestUserExportImportCsv(t *testing.T) {
	const export = "name;disabled;apikeys\nroot;0;\nalice;1;\n"
	var api, requests = newTestApi(t, func(r testRequest) (int, string) {
		if r.Path == userTestPath+"download" {
			return 200, export
		}
		return 200, `{"validations":[],"inserted":1,"updated":0,"uuids":{"` + userTestUuid + `":0},"fieldnames":["name"]}`
	})

	var content, err = api.UserExportCsv()
	if err != nil || string(content) != export {
		t.Fatalf("export: %q, %v", content, err)
	}
	result, err := api.UserImportCsv([]byte("name\nbob\n"), "users.csv")
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.Uuids[userTestUuid] != 0 {
		t.Errorf("result: %+v", result)
	}
	var upload = (*requests)[1]
	if upload.Method != "POST" || upload.Path != userTestPath+"upload" || upload.Body["payload"] != "name\nbob\n" {
		t.Errorf("unexpected upload %+v", upload)
	}
	if download := (*requests)[0]; download.Method != "GET" || download.Path != userTestPath+"download" {
		t.Errorf("unexpected download %+v", download)
	}
}

func TestUserCsvSecrets(t *testing.T) {
	var parse = func(content string) coreapi.Csv {
		var parsed, err = coreapi.ParseCsv([]byte(content), "users")
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	if got := UserCsvSecrets(parse("name;apikeys;priv\nroot;;page-all\n")); got != nil {
		t.Errorf("an export of 26.7 has no secrets: %v", got)
	}
	var got = UserCsvSecrets(parse("name;otp_seed;apikeys;password\na;;;x\nb;SEED;key|hash;\n"))
	if want := []string{"apikeys", "password", "otp_seed"}; !reflect.DeepEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
}
