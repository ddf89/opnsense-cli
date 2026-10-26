//go:build integration

package integrationddclient

import (
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
)

func TestDdclientReadOnly(t *testing.T) {
	var lib = ddclientApi(t)
	var status, err = lib.ServiceStatus()
	if err != nil {
		t.Fatal(err)
	}
	var shown = mustOpn(t, "/ddclient/service", "status")
	requireContains(t, shown, shown.stdout, "status:", status)
	var settings = mustOpn(t, "/ddclient/settings", "print")
	requireContains(t, settings, settings.stdout, "enabled:", "interval:", "backend:")
	var accounts = mustOpn(t, "/ddclient/account", "print")
	requireContains(t, accounts, accounts.stdout, "DESCRIPTION", "CURRENT-IP", "UPDATED")
	var services = mustOpn(t, "/ddclient/account", "print", "options=service")
	requireContains(t, services, services.stdout, "dyndns2", "cloudflare")
	var checks = mustOpn(t, "/ddclient/account", "print", "options=check-ip")
	requireContains(t, checks, checks.stdout, "web_icanhazip", "if")
	mustOpn(t, "/ddclient/settings", "print", "options=backend")
}

func TestDdclientAccountCli(t *testing.T) {
	var lib = ddclientApi(t)
	var name, secret = runPrefix + "-home", runPrefix + "-s3cret"
	var host = runPrefix + ".example.com"

	var uuid = uuidFrom(t, mustOpn(t, "/ddclient/account", "add", "description="+name, "disabled", "service=dyndns2",
		"username=ddc-user", "password="+secret, "hostnames="+host+","+runPrefix+".example.org", "check-ip=web_icanhazip", "ttl=120"))
	t.Cleanup(func() {
		if err := lib.AccountRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of account %s: %v", uuid, err)
		}
	})
	var account, err = lib.AccountGet(uuid)
	if err != nil || account.Enabled != "0" || account.Service != "dyndns2" || !account.PasswordSet || account.Ttl != "120" ||
		account.Hostnames != host+","+runPrefix+".example.org" {
		t.Fatalf("added account %+v %v", account, err)
	}

	// the password is never printed
	for _, args := range [][]string{{"show", name}, {"print"}, {"print", "detail"}, {"print", "json", "search=" + runPrefix}} {
		var out = mustOpn(t, append([]string{"/ddclient/account"}, args...)...)
		if strings.Contains(out.stdout+out.stderr, secret) {
			t.Errorf("the password is printed:\n%s", out)
		}
	}
	var shown = mustOpn(t, "/ddclient/account", "show", name)
	requireContains(t, shown, shown.stdout, "password:", "(set)", "disabled:", "yes", "ttl:", "120")

	// set changes only the given fields, the password stays
	mustOpn(t, "/ddclient/account", "set", name, "hostnames="+host, "check-ip=if", "interface=wan", "wildcard", "force-ssl=no")
	account, err = lib.AccountGet(uuid)
	if err != nil || account.Hostnames != host || account.Checkip != "if" || account.Interface != "wan" || account.Wildcard != "1" ||
		account.ForceSsl != "0" || account.Ttl != "120" || !account.PasswordSet || account.Enabled != "0" {
		t.Errorf("after set %+v %v", account, err)
	}
	mustOpn(t, "/ddclient/account", "disable", name)

	// OPNsense validations and the client side checks
	var refusedService = mustFailOpn(t, "/ddclient/account", "add", "description="+runPrefix+"-bad", "disabled", "service=nosuch",
		"hostnames="+host, "check-ip=web_icanhazip")
	requireContains(t, refusedService, refusedService.stderr, "unknown value")
	var refusedInterface = mustFailOpn(t, "/ddclient/account", "set", name, "check-ip=if6", "interface=")
	requireContains(t, refusedInterface, refusedInterface.stderr, "needs an interface")
	var refusedHostname = mustFailOpn(t, "/ddclient/account", "set", name, "zone=-bad-")
	requireContains(t, refusedHostname, refusedHostname.stderr, "zone")
	var duplicate = mustFailOpn(t, "/ddclient/account", "add", "description="+strings.ToUpper(name), "disabled", "service=dyndns2",
		"hostnames="+host, "check-ip=web_icanhazip")
	requireContains(t, duplicate, duplicate.stderr, "exists already", uuid)

	// replace resets the fields not given (the account stays disabled)
	var replaced = uuidFrom(t, mustOpn(t, "/ddclient/account", "add", "description="+name, "disabled", "service=cloudflare",
		"zone=example.net", "hostnames="+runPrefix+".example.net", "check-ip=web_icanhazip", "replace"))
	if replaced != uuid {
		t.Errorf("replace created %s instead of changing %s", replaced, uuid)
	}
	account, err = lib.AccountGet(uuid)
	if err != nil || account.Service != "cloudflare" || account.Zone != "example.net" || account.Ttl != "300" || account.Interface != "" ||
		account.Username != "" || account.Wildcard != "0" || account.Enabled != "0" || !account.PasswordSet {
		t.Errorf("after replace %+v %v", account, err)
	}

	// rename, then remove by the new name
	mustOpn(t, "/ddclient/account", "set", name, "description="+name+"-renamed")
	mustOpn(t, "/ddclient/account", "remove", name+"-renamed")
	if _, err := lib.AccountGet(uuid); !api.IsNotFound(err) {
		t.Errorf("account not removed: %v", err)
	}
	mustFailOpn(t, "/ddclient/account", "show", name+"-renamed")
}

func TestDdclientSettingsRoundTrip(t *testing.T) {
	var lib = ddclientApi(t)
	var before, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lib.SettingsSet(before.SettingsFields()); err != nil {
			t.Errorf("restoring the settings failed: %v", err)
		}
	})
	var interval = "317"
	if before.DaemonDelay == interval {
		interval = "318"
	}
	mustOpn(t, "/ddclient/settings", "set", "interval="+interval, "verbose", "backend=ddclient")
	var after, _ = lib.SettingsGet()
	if after.DaemonDelay != interval || after.Verbose != "1" || after.Backend != "ddclient" || after.Enabled != before.Enabled {
		t.Errorf("after set %+v", after)
	}
	// the services depend on the backend
	var services = mustOpn(t, "/ddclient/account", "print", "options=service")
	requireContains(t, services, services.stdout, "changeip")
	mustOpn(t, "/ddclient/settings", "set", "backend=native", "verbose="+map[bool]string{true: "yes", false: "no"}[before.Verbose == "1"])
	after, _ = lib.SettingsGet()
	if after.Backend != "opnsense" {
		t.Errorf("backend not native: %+v", after)
	}
	mustFailOpn(t, "/ddclient/settings", "set", "interval=0")
}

// TestDdclientService runs the service (and a force refresh of a disabled test account) only when the firewall has
// no enabled account, so nothing is sent to a DDNS provider; TestMain restores the running state
func TestDdclientService(t *testing.T) {
	var lib = ddclientApi(t)
	requireNoEnabledAccounts(t, lib)
	var settings, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Enabled != "1" {
		t.Skip("the Dynamic DNS service is disabled")
	}
	var before, _ = lib.ServiceStatus()
	t.Cleanup(func() {
		var now, _ = lib.ServiceStatus()
		if now == "running" && before != "running" {
			_ = lib.ServiceStop()
		}
	})

	mustOpn(t, "/ddclient/service", "start")
	requireStatus(t, "running")
	mustOpn(t, "/ddclient/service", "restart")
	requireStatus(t, "running")
	mustOpn(t, "/ddclient/service", "stop")
	requireStatus(t, "stopped")
	mustOpn(t, "/ddclient/service", "reconfigure")
	requireStatus(t, "running")

	if settings.Backend == "opnsense" {
		var name = runPrefix + "-refresh"
		var uuid = uuidFrom(t, mustOpn(t, "/ddclient/account", "add", "description="+name, "disabled", "service=dyndns2",
			"hostnames="+runPrefix+".example.org", "check-ip=web_icanhazip"))
		t.Cleanup(func() { _ = lib.AccountRemove(uuid) })
		requireNoEnabledAccounts(t, lib)
		mustFailOpn(t, "/ddclient/account", "refresh", name)
		var refreshed = mustOpn(t, "/ddclient/account", "refresh", name, "confirm=yes")
		requireContains(t, refreshed, refreshed.stderr, "is disabled")
		requireStatus(t, "running")
	}
	mustOpn(t, "/ddclient/service", "stop")
	requireStatus(t, "stopped")
}

func requireStatus(t *testing.T, want string) {
	t.Helper()
	var shown = mustOpn(t, "/ddclient/service", "status")
	requireContains(t, shown, shown.stdout, "status:", want)
}
