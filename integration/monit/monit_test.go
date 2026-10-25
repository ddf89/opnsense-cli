//go:build integration

package integrationmonit

import (
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/monit"
)

func TestMonitReadOnly(t *testing.T) {
	var lib = monitApi(t)
	var status, err = lib.DaemonStatus()
	if err != nil {
		t.Fatal(err)
	}
	var shown = mustOpn(t, "/monit/service-control", "status")
	requireContains(t, shown, shown.stdout, "status:", status)
	var settings = mustOpn(t, "/monit/settings", "print")
	requireContains(t, settings, settings.stdout, "interval:", "mail-server:", "httpd-port:")
	mustOpn(t, "/monit/service", "print")
	mustOpn(t, "/monit/test", "print")
	mustOpn(t, "/monit/alert", "print")

	// the status report needs a running Monit
	var report = runOpn(t, "/monit/status", "print")
	if status == monit.DaemonRunning {
		if report.exitCode != 0 || !strings.Contains(report.stdout, "status") {
			t.Errorf("status of a running Monit:\n%s", report)
		}
	} else if report.exitCode != 1 || !strings.Contains(report.stderr, "monit.sock") {
		t.Errorf("want the not running explanation:\n%s", report)
	}
}

func TestMonitSettingsRoundTrip(t *testing.T) {
	var lib = monitApi(t)
	var before, err = lib.SettingsGet()
	if err != nil {
		t.Fatal(err)
	}
	var restore = map[string]string{"mmonitTimeout": before["mmonitTimeout"].Value, "sslversion": before["sslversion"].Value,
		"httpdAllow": before["httpdAllow"].Value}
	t.Cleanup(func() {
		if err := lib.SettingsSet(restore); err != nil {
			t.Errorf("restoring the settings failed: %v", err)
		}
	})
	var timeout = "7"
	if before["mmonitTimeout"].Value == timeout {
		timeout = "8"
	}
	mustOpn(t, "/monit/settings", "set", "mmonit-timeout="+timeout, "mail-ssl-version=TLSV12", "httpd-allow=192.0.2.0/24,198.51.100.1")
	var after, _ = lib.SettingsGet()
	if after["mmonitTimeout"].Value != timeout || after["sslversion"].Value != "tlsv12" || after["httpdAllow"].Value != "192.0.2.0/24,198.51.100.1" {
		t.Errorf("not changed: %v %v %v", after["mmonitTimeout"], after["sslversion"], after["httpdAllow"])
	}
	if after["enabled"].Value != before["enabled"].Value {
		t.Errorf("set changed enabled")
	}
	mustFailOpn(t, "/monit/settings", "set", "mail-ssl-version=a8nope")
}

func TestMonitServiceAndTestCli(t *testing.T) {
	var lib = monitApi(t)
	var testName, serviceName = runPrefix + "-cpu", runPrefix + "-svc"

	var testUuid = uuidFrom(t, mustOpn(t, "/monit/test", "add", "name="+testName, "condition=cpu is greater than 95%", "action=alert"))
	t.Cleanup(func() {
		if err := lib.TestRemove(testUuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of test %s: %v", testUuid, err)
		}
	})
	var test, err = lib.TestGet(testUuid)
	if err != nil || test.Type != "ProcessResource" || test.Action != "alert" {
		t.Errorf("added test %+v %v", test, err)
	}

	var serviceUuid = uuidFrom(t, mustOpn(t, "/monit/service", "add", "name="+serviceName, "type=process", "match=a8nothing",
		"tests="+testName, "disabled", "description="+runPrefix))
	t.Cleanup(func() {
		if err := lib.ServiceRemove(serviceUuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of service %s: %v", serviceUuid, err)
		}
	})
	var service, getErr = lib.ServiceGet(serviceUuid)
	if getErr != nil || service.Enabled != "0" || service.Tests != testUuid || service.Timeout != "300" {
		t.Errorf("added service %+v %v", service, getErr)
	}
	var printed = mustOpn(t, "/monit/service", "print", "search="+runPrefix)
	requireContains(t, printed, printed.stdout, serviceName, "match a8nothing", testName, "yes")
	var exists = mustFailOpn(t, "/monit/service", "add", "name="+serviceName, "type=process", "match=x")
	requireContains(t, exists, exists.stderr, "exists already")
	// a system test does not fit a process service, a used test can not change its type
	mustFailOpn(t, "/monit/service", "set", serviceName, "tests=MemoryUsage")
	mustFailOpn(t, "/monit/test", "set", testName, "condition=space usage is greater than 80%")

	mustOpn(t, "/monit/service", "set", serviceName, "start-timeout=45", "polltime=every 2 cycles")
	if service, _ = lib.ServiceGet(serviceUuid); service.StartTimeout != "45" || service.Polltime != "every 2 cycles" || service.Tests != testUuid {
		t.Errorf("after set %+v", service)
	}
	mustOpn(t, "/monit/test", "set", testName, "condition=cpu is greater than 96%")

	var inUse = mustFailOpn(t, "/monit/test", "remove", testName)
	requireContains(t, inUse, inUse.stderr, "in use", serviceName)
	if _, err := lib.TestGet(testUuid); err != nil {
		t.Errorf("the used test must still exist: %v", err)
	}
	mustOpn(t, "/monit/service", "remove", serviceName)
	mustOpn(t, "/monit/test", "remove", testName)
	if _, err := lib.TestGet(testUuid); !api.IsNotFound(err) {
		t.Errorf("the test must be gone: %v", err)
	}
	if _, err := lib.ServiceGet(serviceUuid); !api.IsNotFound(err) {
		t.Errorf("the service must be gone: %v", err)
	}
}

func TestMonitAlertCli(t *testing.T) {
	var lib = monitApi(t)
	var description = runPrefix + "-alert"
	var uuid = uuidFrom(t, mustOpn(t, "/monit/alert", "add", "recipient="+runPrefix+"@example.com", "events=pid,nonexist",
		"disabled", "description="+description, "reminder=5"))
	t.Cleanup(func() {
		if err := lib.AlertRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of alert %s: %v", uuid, err)
		}
	})
	var alert, err = lib.AlertGet(uuid)
	if err != nil || alert.Enabled != "0" || alert.Events != "pid,nonexist" || alert.Reminder != "5" {
		t.Errorf("added alert %+v %v", alert, err)
	}
	mustOpn(t, "/monit/alert", "set", description, "not-on", "format=subject: $SERVICE $EVENT")
	if alert, _ = lib.AlertGet(uuid); alert.NotOn != "1" || alert.Format != "subject: $SERVICE $EVENT" {
		t.Errorf("after set %+v", alert)
	}
	// an invalid recipient is refused before anything is sent
	var refused = mustFailOpn(t, "/monit/alert", "set", description, "events=pid", "not-on", "recipient=a8")
	requireContains(t, refused, refused.stderr, "email")
	var shown = mustOpn(t, "/monit/alert", "show", description)
	requireContains(t, shown, shown.stdout, "recipient:", "@example.com", "not-on:", "yes", "disabled:", "yes")
	mustOpn(t, "/monit/alert", "remove", description)
	if _, err := lib.AlertGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the alert must be gone: %v", err)
	}
}
