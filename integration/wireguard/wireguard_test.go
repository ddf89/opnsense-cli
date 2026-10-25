//go:build integration

package integrationwireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/wireguard"
)

// cleanupInstance / cleanupPeer remove a record by uuid when the test ends (unless it is gone already)
func cleanupInstance(t *testing.T, wg *wireguard.WireguardApi, uuid string) {
	t.Cleanup(func() {
		if err := wg.InstanceRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of instance %s: %v", uuid, err)
		}
	})
}

func cleanupPeer(t *testing.T, wg *wireguard.WireguardApi, uuid string) {
	t.Cleanup(func() {
		if err := wg.PeerRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of peer %s: %v", uuid, err)
		}
	})
}

// requireGlobalState records that WireGuard is disabled globally and checks at the end that it stayed so
func requireGlobalState(t *testing.T, wg *wireguard.WireguardApi) {
	t.Helper()
	var before, err = wg.GeneralEnabled()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if after, err := wg.GeneralEnabled(); err != nil || after != before {
			t.Errorf("the global WireGuard state changed: %v -> %v (%v)", before, after, err)
		}
	})
}

func TestLibraryLifecycle(t *testing.T) {
	var wg = testApi(t)
	requireGlobalState(t, wg)

	pair, err := wg.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if derived, err := wireguard.PublicKeyOf(pair.PrivateKey); err != nil || derived != pair.PublicKey {
		t.Fatalf("PublicKeyOf does not match OPNsense: %v", err)
	}
	var name = testName("lib-i1")
	uuid, err := wg.InstanceCreate(wireguard.InstanceFields{"enabled": "0", "name": name, "privkey": pair.PrivateKey,
		"pubkey": pair.PublicKey, "port": "61931", "tunneladdress": "192.0.2.1/24,2001:db8:a9::1/64"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupInstance(t, wg, uuid)
	instance, err := wg.InstanceGetByName(name)
	if err != nil || instance.Uuid != uuid || instance.Enabled != "0" || instance.PrivateKey != pair.PrivateKey || !strings.HasPrefix(instance.Interface, "wg") {
		t.Fatalf("instance %+v %v", instance.Uuid, err)
	}

	// toggle quirk: InstanceSetEnabled must not flip a disabled instance when disabling
	if changed, err := wg.InstanceSetEnabled(uuid, false); err != nil || changed {
		t.Errorf("disable a disabled instance: %v %v", changed, err)
	}
	if err := wg.InstanceUpdate(uuid, wireguard.InstanceFields{"port": "61932", "endpoint": "vpn.example.com:61932"}); err != nil {
		t.Fatal(err)
	}
	if err := wg.InstanceUpdate("00000000-0000-4000-8000-0000000000a9", wireguard.InstanceFields{"port": "1"}); !api.IsNotFound(err) {
		t.Errorf("update of an unknown uuid: %v", err)
	}

	peerPair, err := wg.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wg.PresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	peerUuid, err := wg.PeerCreate(wireguard.PeerFields{"enabled": "0", "name": testName("lib-p1"), "pubkey": peerPair.PublicKey, "psk": psk,
		"tunneladdress": "192.0.2.2/32", "servers": uuid})
	if err != nil {
		t.Fatal(err)
	}
	cleanupPeer(t, wg, peerUuid)
	// set_client without servers would unlink the peer, PeerUpdate keeps the instances
	if err := wg.PeerUpdate(peerUuid, wireguard.PeerFields{"keepalive": "25"}); err != nil {
		t.Fatal(err)
	}
	peer, err := wg.PeerGet(peerUuid)
	if err != nil || peer.Servers != uuid || peer.Keepalive != "25" || peer.Psk != psk {
		t.Errorf("peer after update: servers %q keepalive %q %v", peer.Servers, peer.Keepalive, err)
	}
	if changed, err := wg.PeerSetEnabled(peerUuid, false); err != nil || changed {
		t.Errorf("disable a disabled peer: %v %v", changed, err)
	}
	info, err := wg.InstanceServerInfo(uuid)
	if err != nil || info.PublicKey != pair.PublicKey || info.Endpoint != "vpn.example.com:61932" || !strings.HasPrefix(info.Address, "192.0.2.3/32") {
		t.Errorf("server info %+v %v", info, err)
	}
	if _, err := wg.InstanceServerInfo("00000000-0000-4000-8000-0000000000a9"); !api.IsNotFound(err) {
		t.Errorf("server info of an unknown instance: %v", err)
	}
	instance, _ = wg.InstanceGet(uuid)
	if instance.Peers != peerUuid || instance.Enabled != "0" {
		t.Errorf("instance peers %q enabled %q", instance.Peers, instance.Enabled)
	}

	if err := wg.InstanceRemove(uuid); err != nil {
		t.Fatal(err)
	}
	if peer, err := wg.PeerGet(peerUuid); err != nil || peer.Servers != "" {
		t.Errorf("the peer of a removed instance: %q %v", peer.Servers, err)
	}
	if err := wg.PeerRemove(peerUuid); err != nil {
		t.Fatal(err)
	}
	if err := wg.PeerRemove(peerUuid); !api.IsNotFound(err) {
		t.Errorf("second remove: %v", err)
	}
}

func TestStatusAndService(t *testing.T) {
	var wg = testApi(t)
	if _, err := wg.StatusList("", "peer"); err != nil {
		t.Error(err)
	}
	if status, err := wg.ServiceStatus(); err != nil || status == "" {
		t.Errorf("status %q %v", status, err)
	}
	mustOpn(t, "/vpn/wireguard/status", "print")
	mustOpn(t, "/vpn/wireguard/service", "status")
	var result = mustOpn(t, "/vpn/wireguard/settings", "print")
	requireContains(t, result, result.stdout, "enabled:")
	// stop / restart refuse without confirmation and do nothing
	for _, action := range []string{"stop", "restart"} {
		mustFailOpn(t, "/vpn/wireguard/service", action)
	}
}

func TestCli(t *testing.T) {
	var wg = testApi(t)
	requireGlobalState(t, wg)
	const instanceMenu, peerMenu = "/vpn/wireguard/instance", "/vpn/wireguard/peer"
	var name = testName("cli-i1")

	var result = mustOpn(t, instanceMenu, "add", "name="+name, "disabled", "port=61941", "tunnel-address=192.0.2.65/27,2001:db8:a9:1::1/64")
	var uuid = uuidFrom(t, result)
	cleanupInstance(t, wg, uuid)
	requireContains(t, result, result.stderr, "public key")
	instance, err := wg.InstanceGet(uuid)
	if err != nil || instance.Enabled != "0" || instance.PrivateKey == "" {
		t.Fatalf("added instance: %v", err)
	}
	for _, args := range [][]string{{"show", name}, {"print", "detail", "search=" + name}, {"print", "json", "search=" + name}} {
		result = mustOpn(t, append([]string{instanceMenu}, args...)...)
		requireContains(t, result, result.stdout, instance.PublicKey, "********")
		if strings.Contains(result.stdout+result.stderr, instance.PrivateKey) {
			t.Errorf("the private key is shown:\n%s", result)
		}
	}
	mustFailOpn(t, instanceMenu, "add", "name="+name, "disabled")
	result = mustOpn(t, instanceMenu, "disable", name)
	requireContains(t, result, result.stderr, "already disabled")
	requireNoStdout(t, mustOpn(t, instanceMenu, "set", name, "mtu=1400", "new-keys"))
	if updated, _ := wg.InstanceGet(uuid); updated.Mtu != "1400" || updated.PublicKey == instance.PublicKey || updated.Enabled != "0" {
		t.Errorf("set: mtu %q, keys changed %v", updated.Mtu, updated.PublicKey != instance.PublicKey)
	}
	result = mustFailOpn(t, instanceMenu, "set", name, "gateway=192.0.2.70")
	requireContains(t, result, result.stderr, "disable-routes: You have to enable Disable Routes")

	var peerName = testName("cli-p1")
	pair, err := wg.KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	result = mustOpn(t, peerMenu, "add", "name="+peerName, "disabled", "public-key="+pair.PublicKey, "tunnel-address=192.0.2.66/32",
		"instance="+name, "generate-psk", "keepalive=25")
	var peerUuid = uuidFrom(t, result)
	cleanupPeer(t, wg, peerUuid)
	peer, err := wg.PeerGet(peerUuid)
	if err != nil || peer.Servers != uuid || peer.Psk == "" || peer.Enabled != "0" {
		t.Fatalf("added peer: %v", err)
	}
	result = mustOpn(t, peerMenu, "print", "instance="+name)
	requireContains(t, result, result.stdout, peerName, "192.0.2.66/32")
	for _, args := range [][]string{{"show", peerName}, {"print", "json", "search=" + peerName}} {
		result = mustOpn(t, append([]string{peerMenu}, args...)...)
		if strings.Contains(result.stdout, peer.Psk) {
			t.Errorf("the psk is shown:\n%s", result)
		}
	}
	requireNoStdout(t, mustOpn(t, peerMenu, "set", peerName, "keepalive=30"))
	if updated, _ := wg.PeerGet(peerUuid); updated.Servers != uuid || updated.Keepalive != "30" {
		t.Errorf("set lost the instance: %q %q", updated.Servers, updated.Keepalive)
	}

	// the peer generator: a disabled peer and its configuration file
	var dir = t.TempDir()
	var genName = testName("cli-gen")
	result = runOpnIn(t, dir, peerMenu, "generate", "name="+genName, "instance="+name, "disabled", "psk",
		"endpoint=vpn.example.com:61941", "dns=192.0.2.53", "keepalive=25")
	if result.exitCode != 0 {
		t.Fatalf("generate:\n%s", result)
	}
	var genUuid = uuidFrom(t, result)
	cleanupPeer(t, wg, genUuid)
	content, err := os.ReadFile(filepath.Join(dir, genName+".conf"))
	if err != nil {
		t.Fatal(err)
	}
	var config = string(content)
	updated, _ := wg.InstanceGet(uuid)
	for _, want := range []string{"[Interface]\nPrivateKey = ", "Address = 192.0.2.67/32", "DNS = 192.0.2.53", "PublicKey = " + updated.PublicKey,
		"PresharedKey = ", "Endpoint = vpn.example.com:61941", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"} {
		if !strings.Contains(config, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if updated.Endpoint != "vpn.example.com:61941" || updated.PeerDns != "192.0.2.53" {
		t.Errorf("generate must store the defaults: %q %q", updated.Endpoint, updated.PeerDns)
	}
	generated, err := wg.PeerGet(genUuid)
	if err != nil || generated.Enabled != "0" || generated.Servers != uuid || !strings.HasPrefix(generated.TunnelAddress, "192.0.2.67/32") {
		t.Errorf("generated peer: %+v %v", generated.TunnelAddress, err)
	}
	// 26.7 does not store the private key, so config is refused
	result = mustFailOpn(t, peerMenu, "config", genName, "file=-")
	requireContains(t, result, result.stderr, "does not store the private key")

	requireNoStdout(t, mustOpn(t, peerMenu, "remove", genName))
	requireNoStdout(t, mustOpn(t, peerMenu, "remove", peerName))
	requireNoStdout(t, mustOpn(t, instanceMenu, "remove", name))
	if _, err := wg.InstanceGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the removed instance still exists: %v", err)
	}
}
