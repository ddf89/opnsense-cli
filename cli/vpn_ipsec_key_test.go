package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	vpnIpsecPskUuid  = "95c00000-0000-4000-8000-000000000001"
	vpnIpsecPubKey   = "-----BEGIN PUBLIC KEY-----\nPUBLICPART\n-----END PUBLIC KEY-----\n"
	vpnIpsecPrivKey  = "-----BEGIN PRIVATE KEY-----\nSECRETPART\n-----END PRIVATE KEY-----\n"
	vpnIpsecPskValue = "verysecretpsk"
)

func vpnIpsecKeyFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = vpnIpsecFake(t, false)
	f.search("/api/ipsec/pre_shared_keys/search_item",
		map[string]any{"uuid": vpnIpsecPskUuid, "ident": "fw.example.com", "remote_ident": "192.0.2.1", "keyType": "PSK",
			"Key": vpnIpsecPskValue, "description": "site b"})
	f.search("/api/ipsec/key_pairs/search_item",
		map[string]any{"uuid": vpnIpsecKeyUuid, "name": "fw key", "keyType": "ecdsa", "%keyType": "ECDSA", "publicKey": vpnIpsecPubKey,
			"privateKey": vpnIpsecPrivKey, "keySize": "256", "keyFingerprint": "a0:a6"})
	f.on("GET", "/api/ipsec/pre_shared_keys/get_item", 200, `{"preSharedKey":{"ident":"","remote_ident":"","keyType":{"PSK":{"value":"PSK","selected":1},"EAP":{"value":"EAP","selected":0}},"Key":"","description":""}}`)
	f.on("GET", "/api/ipsec/key_pairs/get_item", 200, `{"keyPair":{"name":"","keyType":{"rsa":{"value":"RSA","selected":1},"ecdsa":{"value":"ECDSA","selected":0}},"publicKey":"","privateKey":"","keySize":"","keyFingerprint":""}}`)
	return f
}

func TestVpnIpsecPreSharedKey(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecKeyFake(t)
	for _, args := range [][]string{{"print"}, {"print", "detail"}, {"print", "json"}, {"show", "fw.example.com/192.0.2.1"}, {"show", "FW.example.com"}} {
		var r = f.run(append([]string{"/vpn/ipsec/pre-shared-key"}, args...)...)
		wantExit(t, r, 0)
		wantNotContains(t, "output", r.stdout+r.stderr, vpnIpsecPskValue)
		if args[0] == "show" {
			wantContains(t, "stdout", r.stdout, "key:          ********\n", "remote-id:    192.0.2.1\n")
		}
	}
	f.on("POST", "/api/ipsec/pre_shared_keys/add_item", 200, answerAdded("k-new"))
	wantExit(t, f.run("/vpn/ipsec/pre-shared-key", "add", "local-id=fw.example.com", "key=s3cret", "type=eap"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/pre_shared_keys/add_item"), map[string]any{"preSharedKey": map[string]any{
		"ident": "fw.example.com", "Key": "s3cret", "keyType": "EAP"}})

	t.Run("the identity pair names the key", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		wantFailure(t, f.run("/vpn/ipsec/pre-shared-key", "add", "local-id=FW.example.com", "remote-id=192.0.2.1", "key=x"), "exists already")
		wantFailure(t, f.run("/vpn/ipsec/pre-shared-key", "add", "local-id=fw.example.com"), "key")
		wantFailure(t, f.run("/vpn/ipsec/pre-shared-key", "add", "local-id=a b", "key=x"), "local-id")
		wantFailure(t, f.run("/vpn/ipsec/pre-shared-key", "enable", "0"), "no such")
		wantNoMutations(t, f)
	})
}

func TestVpnIpsecKeyPair(t *testing.T) {
	t.Parallel()
	var f = vpnIpsecKeyFake(t)
	for _, args := range [][]string{{"print"}, {"print", "detail"}, {"print", "json"}, {"show", "FW KEY"}} {
		var r = f.run(append([]string{"/vpn/ipsec/key-pair"}, args...)...)
		wantExit(t, r, 0)
		wantNotContains(t, "output", r.stdout+r.stderr, "SECRETPART")
	}
	var r = f.run("/vpn/ipsec/key-pair", "show", "0")
	wantContains(t, "stdout", r.stdout, "type:         ecdsa\n", "key-size:     256\n", "private-key:  yes\n")

	t.Run("export writes the public key only", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		var r = f.run("/vpn/ipsec/key-pair", "export", "fw key")
		wantExit(t, r, 0)
		if r.stdout != vpnIpsecPubKey {
			t.Errorf("unexpected export %q", r.stdout)
		}
		var file = filepath.Join(t.TempDir(), "fw.pem")
		wantExit(t, f.run("/vpn/ipsec/key-pair", "export", "fw key", "file="+file), 0)
		if content, err := os.ReadFile(file); err != nil || string(content) != vpnIpsecPubKey {
			t.Errorf("file: %q %v", content, err)
		}
		wantFailure(t, f.run("/vpn/ipsec/key-pair", "export", "fw key", "file="+file), "already exists")
		wantExit(t, f.run("/vpn/ipsec/key-pair", "export", "fw key", "file="+file, "overwrite"), 0)
		wantNoMutations(t, f)
	})
	t.Run("generate", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		f.on("GET", "/api/ipsec/key_pairs/gen_key_pair/ecdsa/521", 200,
			`{"pubkey":"-----BEGIN PUBLIC KEY-----\nNEWPUB\n","privkey":"-----BEGIN PRIVATE KEY-----\nNEWSECRET\n","status":"ok"}`)
		f.on("POST", "/api/ipsec/key_pairs/add_item", 200, answerAdded("kp-new"))
		var r = f.run("/vpn/ipsec/key-pair", "generate", "name=vpn key", "type=ecdsa", "size=521")
		wantExit(t, r, 0)
		if r.stdout != "kp-new\n" {
			t.Errorf("want the uuid, got %q", r.stdout)
		}
		wantNotContains(t, "output", r.stdout+r.stderr, "NEWSECRET")
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/key_pairs/add_item"), map[string]any{"keyPair": map[string]any{
			"name": "vpn key", "keyType": "ecdsa", "publicKey": "-----BEGIN PUBLIC KEY-----\nNEWPUB\n", "privateKey": "-----BEGIN PRIVATE KEY-----\nNEWSECRET\n"}})
	})
	t.Run("generate refuses an existing name and invalid sizes", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		wantFailure(t, f.run("/vpn/ipsec/key-pair", "generate", "name=FW key"), "exists already")
		wantFailure(t, f.run("/vpn/ipsec/key-pair", "generate", "name=x", "type=ecdsa", "size=2048"), "size")
		wantNoMutations(t, f)
		for _, call := range f.calls() {
			if strings.Contains(call.Path, "gen_key_pair") {
				t.Errorf("no key must be generated: %v", call)
			}
		}
	})
	t.Run("add reads the key files", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		var dir = t.TempDir()
		var pub = filepath.Join(dir, "peer.pub")
		if err := os.WriteFile(pub, []byte(vpnIpsecPubKey), 0o600); err != nil {
			t.Fatal(err)
		}
		f.on("POST", "/api/ipsec/key_pairs/add_item", 200, answerAdded("kp-peer"))
		wantExit(t, f.run("/vpn/ipsec/key-pair", "add", "name=peer", "type=rsa", "public-key-file="+pub), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/ipsec/key_pairs/add_item"), map[string]any{"keyPair": map[string]any{
			"name": "peer", "keyType": "rsa", "publicKey": vpnIpsecPubKey}})
		wantFailure(t, f.run("/vpn/ipsec/key-pair", "add", "name=peer2", "public-key-file="+filepath.Join(dir, "missing")), "missing")
	})
	t.Run("remove refused while a round uses it", func(t *testing.T) {
		t.Parallel()
		var f = vpnIpsecKeyFake(t)
		f.search(vpnIpsecConnPath+"search_local", vpnIpsecLocalRow(map[string]any{"auth": "pubkey", "pubkeys": vpnIpsecKeyUuid}))
		wantFailure(t, f.run("/vpn/ipsec/key-pair", "remove", "fw key"), "used by", vpnIpsecLocalUuid)
		wantNoMutations(t, f)
	})
}
