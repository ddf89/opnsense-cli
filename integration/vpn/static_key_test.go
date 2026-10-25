//go:build integration

package integrationvpn

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// Live tests of the OpenVPN static key library

func TestStaticKeyGenerate(t *testing.T) {
	var vpn = instanceTestApi(t)
	for _, keyType := range openvpn.KeyTypes {
		var key, err = vpn.GenerateKey(keyType)
		if err != nil {
			t.Errorf("GenerateKey(%s): %v", keyType, err)
			continue
		}
		if !strings.Contains(key, "-----BEGIN") || !openvpn.StaticKeyPattern.MatchString(key) {
			t.Errorf("GenerateKey(%s) returned an unexpected key: %q", keyType, key)
		}
	}
	// gen_key refuses other types with {"result":"failed","message":"unknown key type"}
	var result struct {
		Result  string `json:"result"`
		Message string `json:"message"`
	}
	var core = coreApi(t)
	if err := core.DoJSON("GET", core.EndpointForModule("openvpn/instances/gen_key/tls-crypt-v2-client"), nil, &result); err != nil ||
		result.Result != "failed" || result.Message != "unknown key type" {
		t.Errorf("gen_key of an unsupported type: %+v %v", result, err)
	}
}

func TestStaticKeyLifecycle(t *testing.T) {
	var vpn = instanceTestApi(t)
	var uuid, description = instanceTestStaticKey(t, vpn, "static-key-lifecycle", "auth")

	var key, err = vpn.StaticKeyGet(uuid)
	if err != nil || key.Description != description || key.Mode != "auth" || !strings.HasPrefix(key.ModeDescription, "auth (") ||
		!strings.Contains(key.Key, "BEGIN OpenVPN Static key V1") {
		t.Fatalf("StaticKeyGet: %+v %v", key, err)
	}
	if found, err := vpn.StaticKeyGetByDescription(strings.ToUpper(description)); err != nil || found.Uuid != uuid {
		t.Errorf("StaticKeyGetByDescription: %+v %v", found, err)
	}

	// partial update keeps the key
	var renamed = testDescription("static-key-lifecycle renamed")
	if err := vpn.StaticKeyUpdate(uuid, openvpn.StaticKeyFields{"description": renamed, "mode": "crypt"}); err != nil {
		t.Fatalf("StaticKeyUpdate: %v", err)
	}
	updated, err := vpn.StaticKeyGet(uuid)
	if err != nil || updated.Description != renamed || updated.Mode != "crypt" || updated.Key != key.Key {
		t.Errorf("updated: %+v %v", updated, err)
	}
	newKey, err := vpn.GenerateKey("tls-crypt")
	if err != nil {
		t.Fatal(err)
	}
	if err := vpn.StaticKeyUpdate(uuid, openvpn.StaticKeyFields{"key": newKey}); err != nil {
		t.Fatalf("StaticKeyUpdate key: %v", err)
	}
	if updated, _ := vpn.StaticKeyGet(uuid); updated.Key != strings.TrimSpace(newKey) && updated.Key != newKey {
		t.Errorf("key not replaced")
	}

	var validation *api.ValidationError
	err = vpn.StaticKeyUpdate(uuid, openvpn.StaticKeyFields{"key": "not a key!"})
	if !errors.As(err, &validation) || validation.Validations["statickey.key"] == "" {
		t.Errorf("want a key validation error, got %v", err)
	}
	err = vpn.StaticKeyUpdate(uuid, openvpn.StaticKeyFields{"mode": "crypt-v3"})
	if !errors.As(err, &validation) || validation.Validations["statickey.mode"] == "" {
		t.Errorf("want a mode validation error, got %v", err)
	}

	if err := vpn.StaticKeyRemove(uuid); err != nil {
		t.Fatalf("StaticKeyRemove: %v", err)
	}
	if _, err := vpn.StaticKeyGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the removed key still exists: %v", err)
	}
	if err := vpn.StaticKeyRemove(uuid); !api.IsNotFound(err) {
		t.Errorf("removing again: want NotFoundError, got %v", err)
	}
}

func TestStaticKeyCreateValidation(t *testing.T) {
	var vpn = instanceTestApi(t)
	var uuid, err = vpn.StaticKeyCreate(openvpn.StaticKey{Description: testDescription("static-key-nokey")})
	if uuid != "" {
		staticKeyTestCleanup(t, vpn, uuid)
	}
	var validation *api.ValidationError
	if !errors.As(err, &validation) || validation.Validations["statickey.key"] == "" {
		t.Errorf("want a key validation error, got %v", err)
	}
}

func TestStaticKeyUnknownUuid(t *testing.T) {
	var vpn = instanceTestApi(t)
	var core = coreApi(t)
	var ghost = instanceTestUuid()
	if err := vpn.StaticKeyUpdate(ghost, openvpn.StaticKeyFields{"description": testDescription("ghost key")}); !api.IsNotFound(err) {
		t.Errorf("StaticKeyUpdate: want NotFoundError, got %v", err)
	}
	if err := vpn.StaticKeyRemove(ghost); !api.IsNotFound(err) {
		t.Errorf("StaticKeyRemove: want NotFoundError, got %v", err)
	}

	// quirk check (why StaticKeyUpdate checks the existence first): set_static_key/<well-formed unknown uuid>
	// creates the key, a malformed uuid is answered with a bare "failed"
	var material, err = vpn.GenerateKey("tls-crypt")
	if err != nil {
		t.Fatal(err)
	}
	staticKeyTestCleanup(t, vpn, ghost)
	_, err = core.Mutate(core.EndpointForModule("openvpn/instances/set_static_key/"+ghost), map[string]any{"statickey": map[string]string{
		"description": testDescription("ghost key"), "mode": "crypt", "key": material,
	}})
	if err != nil {
		t.Errorf("raw set on an unknown uuid: %v", err)
	}
	if _, err := vpn.StaticKeyGet(ghost); err != nil {
		t.Errorf("quirk changed? set_static_key did not create the unknown uuid %s: %v", ghost, err)
	}
	_, err = core.Mutate(core.EndpointForModule("openvpn/instances/set_static_key/not-a-uuid"), map[string]any{"statickey": map[string]string{
		"description": testDescription("ghost key 2"), "mode": "crypt", "key": material,
	}})
	var validation *api.ValidationError
	if !errors.As(err, &validation) || len(validation.Validations) != 0 {
		t.Errorf("raw set on a malformed uuid: want a bare failed, got %v", err)
	}
}

// OPNsense deletes a static key that instances still use, the CLI refuses that
func TestStaticKeyRemoveInUse(t *testing.T) {
	var vpn = instanceTestApi(t)
	var keyUuid, _ = instanceTestStaticKey(t, vpn, "static-key-in-use", "crypt")
	var instance = instanceTestCreate(t, vpn, openvpn.InstanceFields{
		"description": testDescription("static-key-in-use instance"), "role": "server", "server": "10.213.245.0/24",
		"verify_client_cert": "none", "authmode": "Local Database", "tls_key": keyUuid,
	})
	if users, err := vpn.InstancesUsingStaticKey(keyUuid); err != nil || len(users) != 1 || users[0].Uuid != instance {
		t.Fatalf("InstancesUsingStaticKey: %+v %v", users, err)
	}
	if err := vpn.StaticKeyRemove(keyUuid); err != nil {
		t.Fatalf("quirk changed? removing a key in use failed: %v", err)
	}
	if got, _ := vpn.InstanceGet(instance); got.TlsKey != keyUuid {
		t.Logf("the instance reference was cleaned up: %q", got.TlsKey)
	}
}
