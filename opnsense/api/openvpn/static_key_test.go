package openvpn

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	staticKeySearchPath = "/api/openvpn/instances/search_static_key"
	staticKeyTestKey    = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n0123abcd\n-----END OpenVPN Static key V1-----"
)

var staticKeyTestKeys = []StaticKey{
	{Uuid: "k-1", Description: "office", Mode: "crypt", ModeDescription: "crypt (...)", Key: staticKeyTestKey},
	{Uuid: "k-2", Description: "office old", Mode: "auth", Key: staticKeyTestKey},
	{Uuid: "k-3", Description: "dup", Mode: "auth", Key: staticKeyTestKey},
	{Uuid: "k-4", Description: "Dup", Mode: "auth", Key: staticKeyTestKey},
}

func TestStaticKeyListAndLookups(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"GET " + staticKeySearchPath: instanceTestRows(staticKeyTestKeys[0], staticKeyTestKeys[1], staticKeyTestKeys[2], staticKeyTestKeys[3])})

	var keys, err = api.StaticKeyList("")
	if err != nil || len(keys) != 4 || keys[0].Key != staticKeyTestKey || keys[0].ModeDescription != "crypt (...)" {
		t.Fatalf("StaticKeyList: %+v %v", keys, err)
	}
	if key, err := api.StaticKeyGet("K-2"); err != nil || key.Uuid != "k-2" {
		t.Errorf("StaticKeyGet: %+v %v", key, err)
	}
	if _, err := api.StaticKeyGet("k-nope"); !coreapi.IsNotFound(err) {
		t.Errorf("StaticKeyGet unknown: %v", err)
	}
	if key, err := api.StaticKeyGetByDescription("OFFICE"); err != nil || key.Uuid != "k-1" {
		t.Errorf("by description: %+v %v", key, err)
	}
	var tooMany *coreapi.TooManyFoundError
	if _, err := api.StaticKeyGetByDescription("dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "k-3, k-4") {
		t.Errorf("duplicates: %v", err)
	}
	if _, err := api.StaticKeyGetByDescription("offic"); !coreapi.IsNotFound(err) {
		t.Errorf("substring: %v", err)
	}
	if got := requests()[3].Query.Get("searchPhrase"); got != "OFFICE" {
		t.Errorf("searchPhrase %q", got)
	}
}

func TestStaticKeyCreate(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{"POST /api/openvpn/instances/add_static_key": `{"result":"saved","uuid":"k-new"}`})
	var uuid, err = api.StaticKeyCreate(StaticKey{Description: "office", Key: staticKeyTestKey})
	if err != nil || uuid != "k-new" {
		t.Fatalf("create: %q %v", uuid, err)
	}
	if _, err := api.StaticKeyCreate(StaticKey{Description: "x", Mode: "auth", Key: "k", ModeDescription: "ignored"}); err != nil {
		t.Fatal(err)
	}
	var got = requests()
	var want0 = map[string]any{"statickey": map[string]any{"description": "office", "key": staticKeyTestKey}}
	var want1 = map[string]any{"statickey": map[string]any{"description": "x", "mode": "auth", "key": "k"}}
	if !reflect.DeepEqual(got[0].Body, want0) || !reflect.DeepEqual(got[1].Body, want1) {
		t.Errorf("bodies: %v / %v", got[0].Body, got[1].Body)
	}
}

func TestStaticKeyUpdate(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"GET " + staticKeySearchPath:                         instanceTestRows(staticKeyTestKeys[0]),
		"POST /api/openvpn/instances/set_static_key/k-1":     `{"result":"saved"}`,
		"POST /api/openvpn/instances/set_static_key/k-ghost": `{"result":"failed"}`,
	})
	if err := api.StaticKeyUpdate("k-1", StaticKeyFields{"description": "renamed"}); err != nil {
		t.Fatal(err)
	}
	if err := api.StaticKeyUpdate("k-ghost", StaticKeyFields{"description": "x"}); !coreapi.IsNotFound(err) {
		t.Errorf("unknown uuid: %v", err)
	}
	if err := api.StaticKeyUpdate("k-1", StaticKeyFields{"bogus": "x"}); err == nil {
		t.Errorf("unknown field must fail")
	}
	var posted = instanceTestMutations(requests())
	if len(posted) != 1 || posted[0].Path != "/api/openvpn/instances/set_static_key/k-1" ||
		!reflect.DeepEqual(posted[0].Body, map[string]any{"statickey": map[string]any{"description": "renamed"}}) {
		t.Errorf("posted: %+v", posted)
	}
}

func TestStaticKeyRemoveAndUsage(t *testing.T) {
	var api, _ = instanceTestApi(t, map[string]any{
		"POST /api/openvpn/instances/del_static_key/k-1":    `{"result":"deleted"}`,
		"POST /api/openvpn/instances/del_static_key/k-nope": `{"result":"not found"}`,
		"GET " + instanceTestSearchPath:                     instanceTestRows(instanceTestInstances[0], instanceTestInstances[1], instanceTestInstances[2], instanceTestInstances[3]),
	})
	if err := api.StaticKeyRemove("k-1"); err != nil {
		t.Fatal(err)
	}
	if err := api.StaticKeyRemove("k-nope"); !coreapi.IsNotFound(err) {
		t.Errorf("unknown: %v", err)
	}
	var users, err = api.InstancesUsingStaticKey("K-1")
	if err != nil || len(users) != 2 || users[0].Uuid != "u-office" || users[1].Uuid != "u-dup-2" {
		t.Errorf("users: %+v %v", users, err)
	}
	if users, _ := api.InstancesUsingStaticKey(""); len(users) != 0 {
		t.Errorf("empty uuid matches nothing: %+v", users)
	}
}

func TestGenerateKey(t *testing.T) {
	var api, requests = instanceTestApi(t, map[string]any{
		"GET /api/openvpn/instances/gen_key/tls-crypt": map[string]string{"result": "ok", "key": staticKeyTestKey},
		"GET /api/openvpn/instances/gen_key/tls-auth":  `{"result":"failed","message":"unknown key type"}`,
	})
	var key, err = api.GenerateKey("tls-crypt")
	if err != nil || key != staticKeyTestKey {
		t.Fatalf("GenerateKey: %q %v", key, err)
	}
	if _, err := api.GenerateKey("tls-auth"); err == nil || !strings.Contains(err.Error(), "unknown key type") {
		t.Errorf("failed: %v", err)
	}
	if _, err := api.GenerateKey("tls-crypt-v2-client"); err == nil || len(requests()) != 2 {
		t.Errorf("unsupported types must fail without request: %v", err)
	}
}

func TestKeyTypeForMode(t *testing.T) {
	for mode, want := range map[string]string{"auth": "tls-auth", "crypt": "tls-crypt", "crypt-v2": "tls-crypt-v2-server"} {
		if got, err := KeyTypeForMode(mode); err != nil || got != want {
			t.Errorf("%s: %q %v", mode, got, err)
		}
	}
	if _, err := KeyTypeForMode("x"); err == nil {
		t.Errorf("unknown mode must fail")
	}
	if !StaticKeyPattern.MatchString(staticKeyTestKey) || StaticKeyPattern.MatchString("bad!key") {
		t.Errorf("StaticKeyPattern")
	}
}
