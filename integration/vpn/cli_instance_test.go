//go:build integration

package integrationvpn

import (
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
)

// Live tests of /vpn/openvpn/instance and /vpn/openvpn/static-key. Instances are always added with disabled,
// start / stop / restart are only run against disabled instances (refused by the CLI without a request)

const (
	cliInstanceMenu  = "/vpn/openvpn/instance"
	cliStaticKeyMenu = "/vpn/openvpn/static-key"
)

func TestCliStaticKey(t *testing.T) {
	var vpn = instanceTestApi(t)
	var description = testDescription("cli-static-key")

	var uuid = uuidFrom(t, mustOpn(t, cliStaticKeyMenu, "add", "description="+description, "mode=auth"))
	staticKeyTestCleanup(t, vpn, uuid)
	var key, err = vpn.StaticKeyGet(uuid)
	if err != nil || key.Mode != "auth" || !strings.Contains(key.Key, "BEGIN OpenVPN Static key V1") {
		t.Fatalf("the generated key: %+v %v", key, err)
	}
	var keyLine = strings.Split(strings.TrimSpace(key.Key), "\n")[5]

	var result = mustOpn(t, cliStaticKeyMenu, "print", "search="+runPrefix)
	requireContains(t, result, result.stdout, description, "auth")
	if strings.Contains(result.stdout, "BEGIN") || strings.Contains(result.stdout, keyLine) {
		t.Errorf("print shows key material:\n%s", result)
	}
	result = mustOpn(t, cliStaticKeyMenu, "print", "detail", "search="+runPrefix)
	if strings.Contains(result.stdout, keyLine) {
		t.Errorf("print detail shows key material:\n%s", result)
	}
	result = mustOpn(t, cliStaticKeyMenu, "show", description)
	requireContains(t, result, result.stdout, "uuid:         "+uuid, "mode:         auth", "key:\n", "BEGIN OpenVPN Static key V1", keyLine)
	result = mustOpn(t, cliStaticKeyMenu, "print", "json", "search="+runPrefix)
	requireContains(t, result, result.stdout, `"uuid":"`+uuid+`"`, `"key":"#`)

	// duplicates, replace, set
	mustFailOpn(t, cliStaticKeyMenu, "add", "description="+description)
	result = mustOpn(t, cliStaticKeyMenu, "add", "description="+description, "mode=crypt", "replace")
	if uuidFrom(t, result) != uuid {
		t.Errorf("replace returned another uuid:\n%s", result)
	}
	replaced, _ := vpn.StaticKeyGet(uuid)
	if replaced.Mode != "crypt" || replaced.Key == key.Key {
		t.Errorf("replace must set the mode and generate a new key: %+v", replaced)
	}

	var renamed = testDescription("cli-static-key renamed")
	requireNoStdout(t, mustOpn(t, cliStaticKeyMenu, "set", description, "description="+renamed, "mode=crypt-v2", "regenerate"))
	updated, _ := vpn.StaticKeyGet(uuid)
	if updated.Description != renamed || updated.Mode != "crypt-v2" || updated.Key == replaced.Key ||
		!strings.Contains(updated.Key, "BEGIN OpenVPN tls-crypt-v2 server key") {
		t.Errorf("set: %+v", updated)
	}
	mustFailOpn(t, cliStaticKeyMenu, "set", renamed, "key=bad!key")
	mustFailOpn(t, cliStaticKeyMenu, "set", renamed, "key=abc", "regenerate")

	requireNoStdout(t, mustOpn(t, cliStaticKeyMenu, "remove", renamed))
	if _, err := vpn.StaticKeyGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the removed key still exists: %v", err)
	}
	mustFailOpn(t, cliStaticKeyMenu, "show", uuid)
}

func TestCliInstance(t *testing.T) {
	var vpn = instanceTestApi(t)
	var trust = instanceTestCertificates(t, "cli-instance")
	var keyDescription = testDescription("cli-instance key")
	var keyUuid = uuidFrom(t, mustOpn(t, cliStaticKeyMenu, "add", "description="+keyDescription))
	staticKeyTestCleanup(t, vpn, keyUuid)

	var description = testDescription("cli-instance")
	// every add carries disabled: nothing may run on the shared box
	var result = mustOpn(t, cliInstanceMenu, "add", "description="+description, "disabled", "role=server", "tunnel-network=10.213.246.0/24",
		"ca="+trust.CaDescr, "cert="+trust.CertDescr, "tls-key="+keyDescription, "protocol=UDP4", "port=11946",
		"data-ciphers=aes-256-gcm,chacha20-poly1305", "local-networks=10.213.0.0/16", "dns-servers=10.213.0.53", "verbosity=4",
		"authentication=Local Database", "strict-user-cn=case-insensitive", "keepalive-interval=10", "keepalive-timeout=60")
	var uuid = uuidFrom(t, result)
	instanceTestCleanup(t, vpn, uuid)

	instance, err := vpn.InstanceGet(uuid)
	if err != nil || instance.Enabled != "0" || instance.Ca != trust.CaRef || instance.Cert != trust.CertRef || instance.TlsKey != keyUuid ||
		instance.Proto != "udp4" || instance.DataCiphers != "AES-256-GCM,CHACHA20-POLY1305" || instance.Authmode != "Local Database" ||
		instance.Strictusercn != "2" || instance.Verb != "4" || instance.DnsServers != "10.213.0.53" {
		t.Fatalf("the added instance: %+v %v", instance, err)
	}

	result = mustOpn(t, cliInstanceMenu, "show", description)
	requireContains(t, result, result.stdout, "uuid:", uuid, "disabled:", "yes", trust.CaDescr, trust.CertDescr, keyDescription,
		"case-insensitive", "AES-256-GCM,CHACHA20-POLY1305", "10.213.246.0/24")
	result = mustOpn(t, cliInstanceMenu, "print", "search="+description)
	requireContains(t, result, result.stdout, "VPNID", instance.Vpnid, "10.213.246.0/24", description)
	result = mustOpn(t, cliInstanceMenu, "print", "json", "search="+description)
	requireContains(t, result, result.stdout, `"uuid":"`+uuid+`"`, `"tls_key":"`+keyUuid+`"`)

	// set, rename collisions, OPNsense validation
	requireNoStdout(t, mustOpn(t, cliInstanceMenu, "set", uuid, "port=11947", "local-networks=", "tls-key="))
	updated, _ := vpn.InstanceGet(uuid)
	if updated.Port != "11947" || updated.PushRoute != "" || updated.TlsKey != "" || updated.Ca != trust.CaRef || updated.Vpnid != instance.Vpnid {
		t.Errorf("set: %+v", updated)
	}
	result = mustFailOpn(t, cliInstanceMenu, "set", description, "tunnel-network=10.213.246.0/30")
	requireContains(t, result, result.stderr, "tunnel-network:")
	mustFailOpn(t, cliInstanceMenu, "set", description, "ca=a8-vpn-no-such-ca")

	// add with the same description fails, replace resets the other fields and keeps the vpnid
	mustFailOpn(t, cliInstanceMenu, "add", "description="+description, "disabled", "tunnel-network=10.213.246.0/24")
	result = mustOpn(t, cliInstanceMenu, "add", "description="+description, "disabled", "tunnel-network=10.213.247.0/24",
		"cert="+trust.CertDescr, "replace")
	if uuidFrom(t, result) != uuid {
		t.Errorf("replace returned another uuid:\n%s", result)
	}
	replaced, _ := vpn.InstanceGet(uuid)
	if replaced.Enabled != "0" || replaced.Server != "10.213.247.0/24" || replaced.Port != "" || replaced.Ca != "" ||
		replaced.Verb != "3" || replaced.Proto != "udp" || replaced.Vpnid != instance.Vpnid || replaced.Authmode != "" {
		t.Errorf("replace: %+v", replaced)
	}

	// the instance is disabled: disable is a no-op, start / stop / restart are refused without touching OPNsense
	result = mustOpn(t, cliInstanceMenu, "disable", description)
	requireContains(t, result, result.stderr, "already disabled")
	for _, args := range [][]string{{"start"}, {"stop", "confirm=yes"}, {"restart", "confirm=yes"}} {
		result = mustFailOpn(t, append([]string{cliInstanceMenu, args[0], description}, args[1:]...)...)
		requireContains(t, result, result.stderr, "is disabled")
	}

	// the static key in use can't be removed
	requireNoStdout(t, mustOpn(t, cliInstanceMenu, "set", description, "tls-key="+keyUuid))
	mustFailOpn(t, cliStaticKeyMenu, "remove", keyDescription)
	if _, err := vpn.StaticKeyGet(keyUuid); err != nil {
		t.Errorf("the key in use was removed: %v", err)
	}

	requireNoStdout(t, mustOpn(t, cliInstanceMenu, "remove", description))
	if _, err := vpn.InstanceGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the removed instance still exists: %v", err)
	}
	requireNoStdout(t, mustOpn(t, cliStaticKeyMenu, "remove", keyDescription))
}

func TestCliInstanceClientPasswordMasked(t *testing.T) {
	var vpn = instanceTestApi(t)
	var trust = instanceTestCertificates(t, "cli-client")
	var description = testDescription("cli-client")
	const password = "a8-very-secret"

	var uuid = uuidFrom(t, mustOpn(t, cliInstanceMenu, "add", "description="+description, "disabled", "role=client",
		"remote=vpn.example.com:1194", "ca="+trust.CaDescr, "username=a8user", "password="+password))
	instanceTestCleanup(t, vpn, uuid)

	for _, args := range [][]string{{"show", description}, {"print", "detail", "search=" + description}, {"print", "json", "search=" + description}} {
		var result = mustOpn(t, append([]string{cliInstanceMenu}, args...)...)
		requireContains(t, result, result.stdout, "********", "a8user")
		if strings.Contains(result.stdout+result.stderr, password) {
			t.Errorf("the password is shown:\n%s", result)
		}
	}
}

func TestCliInstanceApply(t *testing.T) {
	var vpn = instanceTestApi(t)
	instanceTestRequireNoneEnabled(t, vpn)
	requireNoStdout(t, mustOpn(t, cliInstanceMenu, "apply"))
}
