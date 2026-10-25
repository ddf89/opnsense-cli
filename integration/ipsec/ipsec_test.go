//go:build integration

package integrationipsec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ipsec"
)

// Live tests of the IPsec library: every configuration list, created disabled with documentation addresses

func mustCreate(t *testing.T, what string, create func() (string, error), remove func(uuid string) error) string {
	t.Helper()
	var uuid, err = create()
	if err != nil {
		t.Fatalf("creating the %s: %v", what, err)
	}
	t.Cleanup(func() {
		if err := remove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("removing the %s %s: %v", what, uuid, err)
		}
	})
	return uuid
}

func TestConnectionLifecycle(t *testing.T) {
	var vpn = ipsecApi(t)
	requireIPsecOff(t, vpn)
	var description = testName("connection")
	var conn = mustCreate(t, "connection", func() (string, error) {
		return vpn.ConnectionCreate(ipsec.Fields{"enabled": "0", "description": description, "version": "2",
			"local_addrs": "198.51.100.10", "remote_addrs": "192.0.2.10", "proposals": "aes256gcm16-sha256-x25519"})
	}, vpn.ConnectionRemove)

	var record, err = vpn.ConnectionGetByDescription(strings.ToUpper(description))
	if err != nil || record.Uuid() != conn || record.Enabled() || record.Display("version") != "IKEv2" || record.Value("remote_addrs") != "192.0.2.10" {
		t.Fatalf("ConnectionGetByDescription: %v %v", record.Values(), err)
	}
	if exists, err := vpn.ConnectionExists(conn); err != nil || !exists {
		t.Errorf("ConnectionExists: %v %v", exists, err)
	}
	if err := vpn.ConnectionUpdate(conn, ipsec.Fields{"dpd_delay": "30"}); err != nil {
		t.Fatal(err)
	}
	if record, _ := vpn.ConnectionGet(conn); record.Value("dpd_delay") != "30" || record.Value("remote_addrs") != "192.0.2.10" {
		t.Errorf("partial update: %v", record.Values())
	}
	var validation *api.ValidationError
	if err := vpn.ConnectionUpdate(conn, ipsec.Fields{"remote_addrs": "not an addr!", "rekey_time": "x"}); !errors.As(err, &validation) ||
		validation.Validations["connection.remote_addrs"] == "" || validation.Validations["connection.rekey_time"] == "" {
		t.Errorf("want validation errors, got %v", err)
	}
	// set_connection would create an unknown uuid, the library checks first
	if err := vpn.ConnectionUpdate("00000000-0000-4000-8000-00000000c0de", ipsec.Fields{"description": testName("ghost")}); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if changed, err := vpn.ConnectionSetEnabled(conn, false); err != nil || changed {
		t.Errorf("disabling a disabled connection: %v %v", changed, err)
	}
	form, err := vpn.ConnectionForm()
	if err != nil || form.Value("proposals") != "default" || len(form.Options("proposals")) < 10 || form.Value("version") == "" {
		t.Errorf("ConnectionForm: %v", err)
	}

	// rounds and children
	var local = mustCreate(t, "local", func() (string, error) {
		return vpn.LocalCreate(ipsec.Fields{"enabled": "0", "connection": conn, "auth": "psk", "id": "fw.example.com", "description": testName("local")})
	}, vpn.LocalRemove)
	var remote = mustCreate(t, "remote", func() (string, error) {
		return vpn.RemoteCreate(ipsec.Fields{"enabled": "0", "connection": conn, "auth": "psk", "id": "192.0.2.10", "round": "1"})
	}, vpn.RemoteRemove)
	var child = mustCreate(t, "child", func() (string, error) {
		return vpn.ChildCreate(ipsec.Fields{"enabled": "0", "connection": conn, "local_ts": "198.51.100.0/24", "remote_ts": "192.0.2.0/24,2001:db8::/64",
			"start_action": "trap|start", "reqid": fmt.Sprint(runReqid), "description": testName("child")})
	}, vpn.ChildRemove)
	if locals, err := vpn.LocalList(conn); err != nil || len(locals) != 1 || locals[0].Uuid() != local || locals[0].Display("connection") != description {
		t.Errorf("LocalList(conn): %v %v", locals, err)
	}
	if remotes, err := vpn.RemoteList(conn); err != nil || len(remotes) != 1 || remotes[0].Uuid() != remote || remotes[0].Value("round") != "1" {
		t.Errorf("RemoteList(conn): %v %v", remotes, err)
	}
	if record, err := vpn.ChildGet(child); err != nil || record.Value("start_action") != "trap|start" || record.Value("rekey_time") != "3600" {
		t.Errorf("ChildGet: %v %v", record.Values(), err)
	}
	if _, err := vpn.LocalCreate(ipsec.Fields{"enabled": "0", "connection": "00000000-0000-4000-8000-00000000c0de"}); !errors.As(err, &validation) ||
		validation.Validations["local.connection"] == "" {
		t.Errorf("an unknown connection must be refused, got %v", err)
	}

	// a manual SPD entry on the child
	var spd = mustCreate(t, "manual spd entry", func() (string, error) {
		return vpn.ManualSpdCreate(ipsec.Fields{"enabled": "0", "connection_child": child, "source": "198.51.100.0/24", "description": testName("spd")})
	}, vpn.ManualSpdRemove)
	if record, err := vpn.ManualSpdGet(spd); err != nil || record.Display("connection_child") != description+" - "+testName("child") {
		t.Errorf("ManualSpdGet: %v %v", record.Values(), err)
	}
	if _, err := vpn.ManualSpdCreate(ipsec.Fields{"enabled": "0", "source": "198.51.100.0/24"}); !errors.As(err, &validation) ||
		validation.Validations["spd.connection_child"] == "" {
		t.Errorf("either reqid or child: %v", err)
	}
	if err := vpn.ManualSpdRemove(spd); err != nil {
		t.Fatal(err)
	}

	// removing the connection removes its rounds and children
	if err := vpn.ConnectionRemove(conn); err != nil {
		t.Fatal(err)
	}
	for _, get := range []func() error{
		func() error { _, err := vpn.LocalGet(local); return err },
		func() error { _, err := vpn.RemoteGet(remote); return err },
		func() error { _, err := vpn.ChildGet(child); return err },
	} {
		if err := get(); !api.IsNotFound(err) {
			t.Errorf("want the rounds and children removed with the connection, got %v", err)
		}
	}
	if err := vpn.ConnectionRemove(conn); !api.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
}

func TestPoolVtiPskLifecycle(t *testing.T) {
	var vpn = ipsecApi(t)
	requireIPsecOff(t, vpn)
	var poolName = runPrefix + "-pool"
	var pool = mustCreate(t, "pool", func() (string, error) {
		return vpn.PoolCreate(ipsec.Fields{"enabled": "0", "name": poolName, "addrs": "198.51.100.128/25", "dns": "192.0.2.53"})
	}, vpn.PoolRemove)
	if record, err := vpn.PoolGetByName(poolName); err != nil || record.Uuid() != pool {
		t.Errorf("PoolGetByName: %v %v", record.Values(), err)
	}
	var validation *api.ValidationError
	if _, err := vpn.PoolCreate(ipsec.Fields{"enabled": "0", "name": poolName, "addrs": "198.51.100.0/24"}); !errors.As(err, &validation) ||
		validation.Validations["pool.name"] == "" {
		t.Errorf("duplicate pool names must be refused, got %v", err)
	}
	// the connection form offers the pool by name
	if form, err := vpn.ConnectionForm(); err != nil || !strings.Contains(fmt.Sprint(form.Options("pools")), poolName) {
		t.Errorf("pool not offered: %v", err)
	}

	var reqid = fmt.Sprint(runReqid + 1)
	var vti = mustCreate(t, "vti", func() (string, error) {
		return vpn.VtiCreate(ipsec.Fields{"enabled": "0", "reqid": reqid, "local": "198.51.100.10", "remote": "192.0.2.10",
			"tunnel_local": "198.51.100.201", "tunnel_remote": "198.51.100.202", "description": testName("vti")})
	}, vpn.VtiRemove)
	if record, err := vpn.VtiGet(vti); err != nil || record.Value("origin") != "vti" || record.Value("reqid") != reqid {
		t.Errorf("VtiGet: %v %v", record.Values(), err)
	}
	if _, err := vpn.VtiCreate(ipsec.Fields{"enabled": "0", "reqid": reqid, "tunnel_local": "198.51.100.201", "tunnel_remote": "2001:db8::2"}); !errors.As(err, &validation) ||
		validation.Validations["vti.reqid"] == "" || validation.Validations["vti.tunnel_local"] == "" {
		t.Errorf("want reqid and family errors, got %v", err)
	}

	var psk = mustCreate(t, "pre-shared key", func() (string, error) {
		return vpn.PreSharedKeyCreate(ipsec.Fields{"ident": runPrefix + ".example.com", "remote_ident": "192.0.2.10", "keyType": "PSK",
			"Key": "probe-secret", "description": testName("psk")})
	}, vpn.PreSharedKeyRemove)
	if record, err := vpn.PreSharedKeyGet(psk); err != nil || record.Value("Key") != "probe-secret" {
		t.Errorf("the search rows contain the key (quirk), got %v", err)
	}
	if _, err := vpn.PreSharedKeyCreate(ipsec.Fields{"ident": runPrefix + ".example.com", "remote_ident": "192.0.2.10", "Key": "x"}); !errors.As(err, &validation) {
		t.Errorf("duplicate identity pairs must be refused, got %v", err)
	}
}

func TestKeyPairLifecycle(t *testing.T) {
	var vpn = ipsecApi(t)
	requireIPsecOff(t, vpn)
	var keys, err = vpn.KeyPairGenerate("ecdsa", "256")
	if err != nil || !strings.Contains(keys.PublicKey, "BEGIN PUBLIC KEY") || !strings.Contains(keys.PrivateKey, "PRIVATE KEY") {
		t.Fatalf("KeyPairGenerate: %v", err)
	}
	var name = testName("key pair")
	var uuid = mustCreate(t, "key pair", func() (string, error) {
		return vpn.KeyPairCreate(ipsec.Fields{"name": name, "keyType": "ecdsa", "publicKey": keys.PublicKey, "privateKey": keys.PrivateKey})
	}, vpn.KeyPairRemove)
	record, err := vpn.KeyPairGetByName(name)
	if err != nil || record.Uuid() != uuid || record.Value("keySize") != "256" || record.Value("keyFingerprint") == "" {
		t.Errorf("KeyPairGetByName: %v", err)
	}
	other, err := vpn.KeyPairGenerate("rsa", "")
	if err != nil {
		t.Fatal(err)
	}
	var validation *api.ValidationError
	if err := vpn.KeyPairUpdate(uuid, ipsec.Fields{"privateKey": other.PrivateKey}); !errors.As(err, &validation) ||
		validation.Validations["keyPair.privateKey"] == "" {
		t.Errorf("a private key of another pair must be refused, got %v", err)
	}
	if _, err := vpn.KeyPairCreate(ipsec.Fields{"name": testName("bad"), "keyType": "rsa", "publicKey": "garbage"}); !errors.As(err, &validation) {
		t.Errorf("an invalid public key must be refused, got %v", err)
	}
	if _, err := vpn.KeyPairGenerate("rsa", "99"); err == nil {
		t.Error("want an error for an invalid size")
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	var vpn = ipsecApi(t)
	var before, err = vpn.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var threads, ike = before.Value("charon.threads"), before.Value("charon.syslog.daemon.ike")
	t.Cleanup(func() {
		if err := vpn.SettingsUpdate(ipsec.Fields{"charon.threads": threads, "charon.syslog.daemon.ike": ike}); err != nil {
			t.Errorf("restoring the settings: %v", err)
		}
		if after, _ := vpn.SettingsGet(); after.Value("charon.threads") != threads || after.Value("charon.syslog.daemon.ike") != ike {
			t.Errorf("settings not restored")
		}
	})
	if err := vpn.SettingsUpdate(ipsec.Fields{"charon.threads": "17", "charon.syslog.daemon.ike": "2"}); err != nil {
		t.Fatal(err)
	}
	var changed, _ = vpn.SettingsGet()
	if changed.Value("charon.threads") != "17" || changed.Value("charon.syslog.daemon.ike") != "2" ||
		changed.Value("charon.ikesa_table_size") != before.Value("charon.ikesa_table_size") || changed.Value("general.enabled") != before.Value("general.enabled") {
		t.Errorf("partial settings update: %v", changed.Values())
	}
	var validation *api.ValidationError
	if err := vpn.SettingsUpdate(ipsec.Fields{"charon.threads": "0"}); !errors.As(err, &validation) || validation.Validations["ipsec.charon.threads"] == "" {
		t.Errorf("want a validation error, got %v", err)
	}
}

func TestStatusReadOnly(t *testing.T) {
	var vpn = ipsecApi(t)
	if _, err := vpn.ServiceStatus(); err != nil {
		t.Error(err)
	}
	if _, err := vpn.IsEnabled(); err != nil {
		t.Error(err)
	}
	if _, err := vpn.LegacyStatus(); err != nil {
		t.Error(err)
	}
	if _, err := vpn.SessionList(); err != nil {
		t.Error(err)
	}
	sad, err := vpn.SadList()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range sad {
		if row.Value("src") == "No" && row.Value("dst") == "SAD" {
			t.Errorf("the \"No SAD entries.\" row must be dropped")
		}
	}
	for _, list := range []func() ([]ipsec.Record, error){vpn.SpdList, vpn.LeaseList, vpn.LeasePools} {
		if _, err := list(); err != nil {
			t.Error(err)
		}
	}
	if children, err := vpn.SessionChildren(runPrefix); err != nil || len(children) != 0 {
		t.Errorf("SessionChildren of an unknown name: %v %v", children, err)
	}
}
