package cli

import "testing"

const systemHaGet = `{"hasync":{"disablepreempt":"0","disconnectppps":"0","pfsyncinterface":{"":{"value":"Disabled","selected":1},` +
	`"lan":{"value":"LAN","selected":0},"opt2":{"value":"SYNC","selected":0}},"pfsyncpeerip":"",` +
	`"pfsyncversion":{"1301":{"value":"OPNsense 24.1 or below","selected":0},"1400":{"value":"OPNsense 24.7 or above","selected":1}},` +
	`"pfsyncdefer":"0","synchronizetoip":"10.99.0.2","verifypeer":"0","username":"root","password":"s3cret",` +
	`"syncitems":{"aliases":{"value":"Aliases","selected":1},"nat":{"value":"NAT","selected":0},"rules":{"value":"Firewall Rules","selected":0}}}}`

func systemHaFake(t *testing.T) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", "/api/core/hasync/get", 200, systemHaGet)
	f.on("POST", "/api/core/hasync/set", 200, answerSaved)
	f.on("POST", "/api/core/hasync/reconfigure", 200, `{"status":"ok"}`)
	f.on("GET", "/api/core/hasync_status/version", 200, `{"response":{"firmware":{"version":"26.7.6","_my_version":"26.7.7"},`+
		`"base":{"version":"26.7.6"},"kernel":{"version":"26.7.6"}}}`)
	f.search("/api/core/hasync_status/services",
		map[string]any{"name": "unbound", "description": "Unbound DNS", "status": true, "uid": "unbound"},
		map[string]any{"name": "openvpn", "id": "1", "description": "OpenVPN", "status": true, "nocheck": true, "uid": "openvpn_1"})
	f.on("POST", "/api/core/hasync_status/restart_all", 200, `{"status":"ok","count":2}`)
	f.on("POST", "/api/core/hasync_status/restart/openvpn/1", 200, `{"response":true,"status":"ok"}`)
	return f
}

func TestSystemHaPrint(t *testing.T) {
	t.Parallel()
	var f = systemHaFake(t)
	var r = f.run("/system/ha", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "pfsync-interface:   (disabled)", "pfsync-version:     1400", "synchronize-to-ip:  10.99.0.2",
		"password:           (set)", "sync-items:         aliases")
	wantNotContains(t, "stdout", r.stdout, "s3cret")
	r = f.run("/system/ha", "print", "json")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"password":"(set)"`, `"pfsyncinterface":""`)
	wantNotContains(t, "stdout", r.stdout, "s3cret")
	r = f.run("/system/ha", "print", "options=sync-items")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "aliases  Aliases         yes", "nat      NAT             no")
	r = f.run("/system/ha", "status")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "peer:            reachable", "firmware:        26.7.6")
	wantContains(t, "stderr", r.stderr, "warning: the backup node runs 26.7.6, this firewall 26.7.7")
	wantNoMutations(t, f)
}

func TestSystemHaSet(t *testing.T) {
	t.Parallel()
	var f = systemHaFake(t)
	wantFailure(t, f.run("/system/ha", "set"), "nothing to change")
	wantFailure(t, f.run("/system/ha", "set", "pfsync-interface=wan"), "unknown value", "lan, opt2")
	wantFailure(t, f.run("/system/ha", "set", "pfsync-interface=lan,opt2"), "takes one value")
	wantFailure(t, f.run("/system/ha", "set", "pfsync-version="), "must not be empty")
	wantFailure(t, f.run("/system/ha", "set", "sync-items=aliases,bogus"), "unknown value")
	wantFailure(t, f.run("/system/ha", "set", "pfsync-peer-ip=10.0.0"), "IP address")
	wantNoMutations(t, f)
	var r = f.run("/system/ha", "set", "pfsync-interface=OPT2", "pfsync-peer-ip=10.99.0.2", "sync-items=NAT,rules", "verify-peer",
		"password= p w ")
	wantExit(t, r, 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/core/hasync/set"), map[string]any{"hasync": map[string]any{
		"pfsyncinterface": "opt2", "pfsyncpeerip": "10.99.0.2", "syncitems": "nat,rules", "verifypeer": "1", "password": " p w "}})
}

func TestSystemHaSetDisablePfsync(t *testing.T) {
	t.Parallel()
	var f = systemHaFake(t)
	wantExit(t, f.run("/system/ha", "set", "pfsync-interface=", "sync-items="), 0)
	wantJSON(t, wantOneMutation(t, f, "POST", "/api/core/hasync/set"),
		map[string]any{"hasync": map[string]any{"pfsyncinterface": "", "syncitems": ""}})
}

func TestSystemHaApplyAndSync(t *testing.T) {
	t.Parallel()
	var f = systemHaFake(t)
	wantExit(t, f.run("/system/ha", "apply"), 0)
	wantOneMutation(t, f, "POST", "/api/core/hasync/reconfigure")

	var g = systemHaFake(t)
	wantFailure(t, g.run("/system/ha", "sync"), "pushes the configuration", "confirm=yes")
	wantFailure(t, g.run("/system/ha/service", "restart", "openvpn_1"), "confirm=yes")
	wantFailure(t, g.run("/system/ha/service", "start", "unbound"), "confirm=yes")
	wantFailure(t, g.runScript("/system/ha sync\n"), "confirm=yes")
	wantNoCalls(t, g)
	var r = g.run("/system/ha", "sync", "confirm=yes")
	wantExit(t, r, 0)
	wantContains(t, "stderr", r.stderr, "2 services restarted")
	wantOneMutation(t, g, "POST", "/api/core/hasync_status/restart_all")
}

func TestSystemHaService(t *testing.T) {
	t.Parallel()
	var f = systemHaFake(t)
	var r = f.run("/system/ha/service", "print")
	wantExit(t, r, 0)
	wantContains(t, "stdout", r.stdout, "0  unbound    Unbound DNS  running  no", "1  openvpn_1  OpenVPN      running  yes")
	wantFailure(t, f.run("/system/ha/service", "stop", "openvpn_1", "confirm=yes"), "locked")
	wantFailure(t, f.run("/system/ha/service", "restart", "nosuch", "confirm=yes"), "not found")
	wantNoMutations(t, f)
	wantExit(t, f.run("/system/ha/service", "restart", "openvpn", "confirm=yes"), 0)
	wantOneMutation(t, f, "POST", "/api/core/hasync_status/restart/openvpn/1")

	var g = newFakeOPN(t)
	g.on("POST", "/api/core/hasync_status/restart_all", 200, `{"status":"error","message":"Connection refused"}`)
	wantFailure(t, g.run("/system/ha", "sync", "confirm=yes"), "Connection refused")
}
