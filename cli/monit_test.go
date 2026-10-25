package cli

import (
	"strings"
	"testing"
)

const (
	monitServiceSearchPath = "/api/monit/settings/search_service"
	monitTestSearchPath    = "/api/monit/settings/search_test"
	monitTestServiceUuid   = "69cf0fbc-020c-4cfb-9b86-fdb538de9dea"
	monitTestTestUuid      = "aa7d0e55-f0c0-4653-a59d-a75cf8025311"
)

func TestMonitSettings(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/monit/settings/get_general", 200, `{"monit":{"enabled":"0","interval":"120",`+
		`"mailserver":{"127.0.0.1":{"value":"127.0.0.1","selected":1}},"password":"s3cret","httpdPassword":"",`+
		`"sslversion":{"auto":{"value":"AUTO","selected":1},"tlsv13":{"value":"TLSV13","selected":0}},`+
		`"mmonitUrl":"http://admin:hunter2@mmonit.example.com:8080/collector"},"result":"ok"}`)
	f.on("POST", "/api/monit/settings/set", 200, answerSaved)
	var r = f.run("/monit/settings", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "interval:", "120", "mail-server:", "127.0.0.1", "mail-password:", "(set)",
		"mail-ssl-version:", "auto", "mmonit-url:", "http://admin:********@mmonit.example.com:8080/collector")
	var asJSON = f.run("/monit/settings", "print", "json")
	wantExit(t, asJSON, 0)
	for _, output := range []string{r.stdout, asJSON.stdout} {
		wantNotContains(t, "stdout", output, "s3cret", "hunter2")
	}

	wantFailure(t, f.run("/monit/settings", "set", "mail-ssl-version=tlsv9"), "must be one of")
	wantFailure(t, f.run("/monit/settings", "set", "interval=100000"), "0 to 86400")
	wantFailure(t, f.run("/monit/settings", "set", "mail-password=a b"), "spaces")
	wantNoMutations(t, f)
	wantExit(t, f.run("/monit/settings", "set", "interval=60", "mail-server=mx1.example.com,mx2.example.com", "mail-ssl-version=TLSV13", "mail-ssl"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/monit/settings/set"), map[string]any{"monit": map[string]any{"general": map[string]any{
		"interval": "60", "mailserver": "mx1.example.com,mx2.example.com", "sslversion": "tlsv13", "ssl": "1"}}})
}

func monitFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.search(monitServiceSearchPath,
		map[string]any{"uuid": monitTestServiceUuid, "enabled": "0", "name": "probe", "type": "process", "match": "probed",
			"tests": monitTestTestUuid, "%tests": "HighCpu", "depends": "", "timeout": "300", "starttimeout": "30"},
		map[string]any{"uuid": "s2", "enabled": "1", "name": "web", "type": "process", "pidfile": "/var/run/web.pid",
			"tests": "", "depends": monitTestServiceUuid})
	f.search(monitTestSearchPath,
		map[string]any{"uuid": monitTestTestUuid, "name": "HighCpu", "type": "ProcessResource", "condition": "cpu is greater than 90%", "action": "alert", "path": ""},
		map[string]any{"uuid": "t2", "name": "Unused", "type": "Custom", "condition": "status != 0", "action": "alert", "path": ""})
	f.on("GET", "/api/monit/settings/get_service", 200, `{"service":{"interface":{"":{"value":"None","selected":1},"lan":{"value":"LAN","selected":0}}}}`)
	f.on("POST", "/api/monit/settings/add_service", 200, answerAdded("s-new"))
	f.on("POST", "/api/monit/settings/set_service/"+monitTestServiceUuid, 200, answerSaved)
	f.on("POST", "/api/monit/settings/del_test/t2", 200, answerDeleted)
	f.on("POST", "/api/monit/settings/del_service/s2", 200, answerDeleted)
	return f
}

func TestMonitService(t *testing.T) {
	t.Parallel()
	var f = monitFake(t)
	var r = f.run("/monit/service", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  yes       probe", "match probed", "HighCpu", "/var/run/web.pid")
	var shown = f.run("/monit/service", "show", "web")
	wantContains(t, "stdout", shown.stdout, "depends:", "probe")

	var added = f.run("/monit/service", "add", "name=db", "type=process", "pidfile=/var/run/db.pid", "tests=highcpu",
		"depends=web", "start=/usr/local/etc/rc.d/db start", "disabled")
	wantExit(t, added, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/monit/settings/add_service"), map[string]any{"service": map[string]any{
		"name": "db", "enabled": "0", "description": "", "type": "process", "pidfile": "/var/run/db.pid", "match": "", "path": "",
		"address": "", "interface": "", "start": "/usr/local/etc/rc.d/db start", "stop": "", "timeout": "300", "starttimeout": "30",
		"tests": monitTestTestUuid, "depends": "s2", "polltime": ""}})

	t.Run("set and enable", func(t *testing.T) {
		t.Parallel()
		var f = monitFake(t)
		wantExit(t, f.run("/monit/service", "set", "probe", "interface=LAN", "tests="), 0)
		wantJSON(t, wantOneMutation(t, f, "POST", "/api/monit/settings/set_service/"+monitTestServiceUuid),
			map[string]any{"service": map[string]any{"interface": "lan", "tests": ""}})
		var g = monitFake(t)
		wantExit(t, g.run("/monit/service", "enable", "probe"), 0)
		wantJSON(t, wantOneMutation(t, g, "POST", "/api/monit/settings/set_service/"+monitTestServiceUuid),
			map[string]any{"service": map[string]any{"enabled": "1"}})
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		var f = monitFake(t)
		wantFailure(t, f.run("/monit/service", "add", "name=probe", "type=process"), "exists already")
		wantFailure(t, f.run("/monit/service", "add", "name=a b", "type=process"), "letters, digits")
		wantFailure(t, f.run("/monit/service", "add", "name=x"), "type=")
		wantFailure(t, f.run("/monit/service", "add", "name=x", "type=process", "tests=nope"), "not found", "nope")
		wantFailure(t, f.run("/monit/service", "add", "name=x", "type=network", "interface=opt9"), "unknown interface", "lan")
		wantFailure(t, f.run("/monit/service", "add", "name=x", "type=file", "path=relative"), "absolute path")
		wantFailure(t, f.run("/monit/service", "remove", "probe"), "in use", "web")
		wantFailure(t, f.run("/monit/test", "remove", "HighCpu"), "in use", "probe")
		wantNoMutations(t, f)
		wantExit(t, f.run("/monit/test", "remove", "Unused"), 0)
		wantExit(t, f.run("/monit/service", "remove", "web"), 0)
		if calls := f.mutations(); len(calls) != 2 {
			t.Errorf("want two removals, got %v", calls)
		}
	})
}

func TestMonitTestAndAlert(t *testing.T) {
	t.Parallel()
	var f = monitFake(t)
	f.on("POST", "/api/monit/settings/add_test", 200, answerAdded("t-new"))
	var r = f.run("/monit/test", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "HighCpu", "ProcessResource", "cpu is greater than 90%")
	wantExit(t, f.run("/monit/test", "add", "name=Disk", "condition=space usage is greater than 90%", "action=Alert"), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/monit/settings/add_test"), map[string]any{"test": map[string]any{
		"name": "Disk", "condition": "space usage is greater than 90%", "action": "alert", "path": ""}})
	wantFailure(t, monitFake(t).run("/monit/test", "add", "name=has space", "condition=x", "action=alert"), "no spaces")

	var alerts = newFakeOPN(t)
	alerts.search("/api/monit/settings/search_alert", map[string]any{"uuid": "a1", "enabled": "0", "recipient": "root@localhost.local",
		"noton": "0", "events": "", "format": "", "reminder": "", "description": ""})
	alerts.on("POST", "/api/monit/settings/add_alert", 200, answerAdded("a-new"))
	wantExit(t, alerts.run("/monit/alert", "add", "recipient=ops@example.com", "events=PID,nonexist", "reminder=10", "disabled"), 0)
	wantJSON(t, wantOneMutation(t, alerts, "POST", "/api/monit/settings/add_alert"), map[string]any{"alert": map[string]any{
		"recipient": "ops@example.com", "enabled": "0", "description": "", "events": "pid,nonexist", "noton": "0", "format": "", "reminder": "10"}})

	var refused = newFakeOPN(t)
	wantFailure(t, refused.run("/monit/alert", "add", "recipient=not an address"), "email address")
	wantFailure(t, refused.run("/monit/alert", "add", "recipient=a@example.com", "events=bogus"), "must be one of")
	wantFailure(t, refused.run("/monit/alert", "add", "recipient=a@example.com", "format={x}"), `"{"`)
	wantFailure(t, refused.run("/monit/alert", "add", "recipient=a@example.com", "not-on", "events="), "at least one event")
	wantNoCalls(t, refused)
}

func TestMonitStatusAndControl(t *testing.T) {
	t.Parallel()
	var f = newFakeOPN(t)
	f.on("GET", "/api/monit/status/get/text", 200, `{"result":"ok","status":"<div class=\"alert\"><pre>Monit 5.34 uptime: 1m\n\n`+
		`System 'fw'\n  status                       <span class=\"text-success\">OK<\/span><\/pre><\/div>"}`)
	f.on("GET", "/api/monit/status/get/xml", 200, `{"result":"ok","status":{"server":{"uptime":"60"},"service":[{"name":"fw","status":"0"}]}}`)
	f.on("GET", "/api/monit/service/status", 200, `{"status":"running"}`)
	f.on("POST", "/api/monit/service/reconfigure", 200, `{"status":"ok"}`)
	var r = f.run("/monit/status", "print")
	wantExit(t, r, 0)
	if r.stdout != "Monit 5.34 uptime: 1m\n\nSystem 'fw'\n  status                       OK\n" {
		t.Errorf("status text %q", r.stdout)
	}
	var asJSON = f.run("/monit/status", "print", "json")
	wantContains(t, "stdout", asJSON.stdout, `{"server":{"uptime":"60"},"service":[{"name":"fw","status":"0"}]}`)
	var withCredentials = newFakeOPN(t)
	withCredentials.on("GET", "/api/monit/status/get/xml", 200,
		`{"result":"ok","status":{"server":{"uptime":"60","credentials":{"username":"root","password":"s3cret"}}}}`)
	var masked = withCredentials.run("/monit/status", "print", "json")
	wantExit(t, masked, 0)
	wantContains(t, "stdout", masked.stdout, `"username":"root"`, `"password":"********"`)
	if strings.Contains(masked.stdout, "s3cret") {
		t.Errorf("the httpd password must be masked: %s", masked.stdout)
	}
	wantContains(t, "stdout", f.run("/monit/service-control", "status").stdout, "running")
	wantExit(t, f.run("/monit/service-control", "reconfigure"), 0)
	wantOneMutation(t, f, "POST", "/api/monit/service/reconfigure")

	var down = newFakeOPN(t)
	down.on("GET", "/api/monit/status/get/text", 200, `{"result":"failed","status":"<div class=\"alert\"><pre>\nEither the file \/var\/run\/monit.sock does not exists<\/pre><\/div>"}`)
	wantFailure(t, down.run("/monit/status", "print"), "monit.sock does not exists")
}
