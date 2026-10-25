package cmd

import (
	"strings"
	"testing"
)

const sysDestUuid = "2e9349d9-ee68-47ce-9cfc-f4ba1d5bb47a"

// sysLoggingFake serves the general settings, the destination search (target "siem" plus decoys) and get_destination
func sysLoggingFake(t *testing.T, extraRows ...map[string]any) *fakeOPN {
	t.Helper()
	var f = newFakeOPN(t)
	f.on("GET", sysSyslogGetPath, 200, sysSyslogSettings)
	var rows = append([]map[string]any{
		sysDestinationRow(map[string]any{"uuid": sysDestUuid}),
		sysDestinationRow(map[string]any{"uuid": "d-siem-backup", "description": "siem backup", "enabled": "1"}),
		sysDestinationRow(map[string]any{"uuid": "d-old-siem", "description": "old siem"}),
	}, extraRows...)
	f.search(sysSyslogSearchDestPath, rows...)
	f.on("GET", sysSyslogGetDestPath+sysDestUuid, 200, sysDestinationGet("siem"))
	f.on("GET", sysSyslogGetDestPath+"d-unknown", 200, `[]`) // OPNsense answers unknown uuids with an empty array
	return f
}

func TestSysLoggingShow(t *testing.T) {
	t.Parallel()
	var f = sysLoggingFake(t)
	var r = f.run("system", "logging", "show")
	wantExit(t, r, 0)
	var fields = map[string]string{}
	for _, row := range sysTable(r.stdout) {
		fields[strings.TrimSuffix(row[0], ":")] = strings.Join(row[1:], " ")
	}
	for key, want := range map[string]string{"enabled": "1", "loglocal": "1", "maxpreserve": "31", "maxfilesize": ""} {
		if got, ok := fields[key]; !ok || got != want {
			t.Errorf("%s: got %q (present %v), want %q\n%s", key, got, ok, want, r.stdout)
		}
	}
	wantNoMutations(t, f)
}

func TestSysLoggingSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args []string
		want map[string]any
	}{
		{[]string{"--maxpreserve", "10"}, map[string]any{"maxpreserve": "10"}},
		{[]string{"--loglocal=false"}, map[string]any{"loglocal": "0"}},
		{[]string{"--enabled"}, map[string]any{"enabled": "1"}},
		{[]string{"--maxfilesize", ""}, map[string]any{"maxfilesize": ""}},
		{[]string{"--maxfilesize", "100", "--enabled=false"}, map[string]any{"maxfilesize": "100", "enabled": "0"}},
	} {
		t.Run(sysName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			f.on("POST", sysSyslogSetPath, 200, answerSaved)
			var r = f.run(append([]string{"system", "logging", "set"}, tc.args...)...)
			wantExit(t, r, 0)
			wantJSON(t, wantOneMutation(t, f, "POST", sysSyslogSetPath), map[string]any{"syslog": map[string]any{"general": tc.want}})
		})
	}

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"nothing to change", nil, []string{"Nothing to change"}},
		{"maxpreserve not a number", []string{"--maxpreserve", "abc"}, []string{"maxpreserve"}},
		{"maxpreserve negative", []string{"--maxpreserve", "-1"}, []string{"maxpreserve"}},
		{"maxpreserve empty", []string{"--maxpreserve", ""}, []string{"maxpreserve"}},
		{"maxfilesize not a number", []string{"--maxfilesize", "10M"}, []string{"maxfilesize"}},
		{"invalid bool", []string{"--loglocal=maybe"}, []string{"loglocal"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			wantFailure(t, f.run(append([]string{"system", "logging", "set"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogSetPath, 200, answerValidation("syslog.general.maxpreserve", "Value out of range."))
		wantFailure(t, f.run("system", "logging", "set", "--maxpreserve", "99999"), "syslog.general.maxpreserve", "Value out of range.")
	})
}

func TestSysLoggingDestinationList(t *testing.T) {
	t.Parallel()
	var f = sysLoggingFake(t)
	var r = f.run("system", "logging", "destination", "list")
	wantExit(t, r, 0)
	var rows = sysWantTable(t, r.stdout,
		[]string{"UUID", "ENABLED", "TRANSPORT", "HOSTNAME", "PORT", "PROGRAM", "LEVEL", "FACILITY", "DESCRIPTION"},
		sysDestUuid, "d-siem-backup", "d-old-siem")
	if len(rows) > 1 {
		if got := strings.Join(rows[1][1:], "|"); got != "0|udp4|192.0.2.10|1514|filterlog,unbound|info,err|kern,local0|siem" {
			t.Errorf("row 1: %s", got)
		}
	}
	wantSearchPhrases(t, f, sysSyslogSearchDestPath, "")
	wantNoMutations(t, f)

	t.Run("--search is passed on", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		wantExit(t, f.run("system", "logging", "destination", "list", "--search", "192.0.2"), 0)
		wantSearchPhrases(t, f, sysSyslogSearchDestPath, "192.0.2")
	})
}

func TestSysLoggingDestinationShow(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--uuid", sysDestUuid}, {"--description", "siem"}} {
		t.Run(sysName(args), func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			var r = f.run(append([]string{"system", "logging", "destination", "show"}, args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, sysDestUuid, "udp4", "192.0.2.10", "1514", "filterlog,unbound", "info,err", "kern,local0", "siem")
			wantNotContains(t, "stdout", r.stdout, "d-siem-backup", "d-old-siem", "udp6", "Web GUI")
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description lists the uuids", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t, sysDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
		wantFailure(t, f.run("system", "logging", "destination", "show", "--description", "siem"), sysDestUuid, "d-dup", "--uuid")
	})
	t.Run("unknown uuid", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		wantFailure(t, f.run("system", "logging", "destination", "show", "--uuid", "d-unknown"), "not found")
	})
	t.Run("unknown description", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		wantFailure(t, f.run("system", "logging", "destination", "show", "--description", "sie"), "not found")
	})
	for _, args := range [][]string{{}, {"--uuid", sysDestUuid, "--description", "siem"}} {
		t.Run("selector "+sysName(args)+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			wantFailure(t, f.run(append([]string{"system", "logging", "destination", "show"}, args...)...), "uuid", "description")
			wantNoCalls(t, f)
		})
	}
}

func TestSysLoggingDestinationCreate(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogAddDestPath, 200, answerAdded("d-new"))
		var r = f.run("system", "logging", "destination", "create", "--hostname", "192.0.2.10")
		wantExit(t, r, 0)
		wantContains(t, "stdout", r.stdout, "d-new")
		wantJSON(t, wantOneMutation(t, f, "POST", sysSyslogAddDestPath), map[string]any{"destination": map[string]any{
			"enabled": "1", "transport": "udp4", "program": "", "level": "", "facility": "", "hostname": "192.0.2.10",
			"certificate": "", "port": "514", "rfc5424": "0", "description": "",
		}})
	})
	t.Run("all flags", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogAddDestPath, 200, answerAdded("d-new"))
		var r = f.run("system", "logging", "destination", "create", "--hostname", "2001:db8::10", "--transport", "tls6",
			"--port", "6514", "--program", "filterlog", "--level", "err,crit", "--facility", "local0,local7",
			"--certificate", "6add3e24dc0a9", "--rfc5424", "--enabled=false", "--description", "remote")
		wantExit(t, r, 0)
		wantJSON(t, wantOneMutation(t, f, "POST", sysSyslogAddDestPath), map[string]any{"destination": map[string]any{
			"enabled": "0", "transport": "tls6", "program": "filterlog", "level": "err,crit", "facility": "local0,local7",
			"hostname": "2001:db8::10", "certificate": "6add3e24dc0a9", "port": "6514", "rfc5424": "1", "description": "remote",
		}})
	})

	for _, tc := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{"hostname is required", nil, []string{"hostname"}},
		{"empty hostname", []string{"--hostname", " "}, []string{"hostname"}},
		{"unknown transport", []string{"--hostname", "h", "--transport", "udp"}, []string{"transport", "udp"}},
		{"two transports", []string{"--hostname", "h", "--transport", "udp4,tcp4"}, []string{"transport"}},
		{"port out of range", []string{"--hostname", "h", "--port", "65536"}, []string{"port"}},
		{"port not a number", []string{"--hostname", "h", "--port", "syslog"}, []string{"port"}},
		{"unknown level", []string{"--hostname", "h", "--level", "info,verbose"}, []string{"level", "verbose"}},
		{"unknown facility", []string{"--hostname", "h", "--facility", "kernel"}, []string{"facility", "kernel"}},
	} {
		t.Run(tc.name+", no API call", func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			wantFailure(t, f.run(append([]string{"system", "logging", "destination", "create"}, tc.args...)...), tc.wants...)
			wantNoCalls(t, f)
		})
	}

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogAddDestPath, 200,
			`{"result":"failed","validations":{"destination.transport":"Transport protocol does not match address in hostname"}}`)
		wantFailure(t, f.run("system", "logging", "destination", "create", "--hostname", "192.0.2.10", "--transport", "udp6"),
			"destination.transport", "does not match")
	})
}

func TestSysLoggingDestinationUpdate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"by uuid, only the changed field", []string{"--uuid", sysDestUuid, "--port", "1515"}, map[string]any{"port": "1515"}},
		{"by description", []string{"--description", "siem", "--level", "err"}, map[string]any{"level": "err"}},
		{"clear a list", []string{"--uuid", sysDestUuid, "--program", ""}, map[string]any{"program": ""}},
		{"booleans", []string{"--uuid", sysDestUuid, "--enabled=false", "--rfc5424"}, map[string]any{"enabled": "0", "rfc5424": "1"}},
		{"rename", []string{"--description", "siem", "--new-description", "siem2"}, map[string]any{"description": "siem2"}},
		{"transport and hostname", []string{"--uuid", sysDestUuid, "--transport", "tcp6", "--hostname", "2001:db8::1"},
			map[string]any{"transport": "tcp6", "hostname": "2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			f.on("POST", sysSyslogSetDestPath+sysDestUuid, 200, answerSaved)
			var r = f.run(append([]string{"system", "logging", "destination", "update"}, tc.args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, sysDestUuid)
			wantJSON(t, wantOneMutation(t, f, "POST", sysSyslogSetDestPath+sysDestUuid), map[string]any{"destination": tc.want})
		})
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wants   []string
		noCalls bool
	}{
		{"nothing to update", []string{"--uuid", sysDestUuid}, []string{"Nothing to update"}, true},
		{"empty transport", []string{"--uuid", sysDestUuid, "--transport", ""}, []string{"transport"}, true},
		{"empty hostname", []string{"--uuid", sysDestUuid, "--hostname", ""}, []string{"hostname"}, true},
		{"invalid port", []string{"--uuid", sysDestUuid, "--port", "0"}, []string{"port"}, true},
		{"invalid level", []string{"--uuid", sysDestUuid, "--level", "loud"}, []string{"loud"}, true},
		{"no selector", []string{"--port", "1515"}, []string{"uuid", "description"}, true},
		{"unknown uuid", []string{"--uuid", "d-unknown", "--port", "1515"}, []string{"not found"}, false},
		{"description is a substring only", []string{"--description", "sie", "--port", "1515"}, []string{"not found"}, false},
	} {
		t.Run(tc.name+", no change", func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			wantFailure(t, f.run(append([]string{"system", "logging", "destination", "update"}, tc.args...)...), tc.wants...)
			if tc.noCalls {
				wantNoCalls(t, f)
			}
			wantNoMutations(t, f)
		})
	}

	t.Run("ambiguous description", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t, sysDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
		wantFailure(t, f.run("system", "logging", "destination", "update", "--description", "siem", "--port", "1"), sysDestUuid, "d-dup")
		wantNoMutations(t, f)
	})
	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogSetDestPath+sysDestUuid, 200, answerValidation("destination.transport", "Transport protocol does not match"))
		wantFailure(t, f.run("system", "logging", "destination", "update", "--uuid", sysDestUuid, "--transport", "udp6"),
			"destination.transport", "does not match")
	})
}

func TestSysLoggingDestinationRmEnableDisable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args   []string
		path   string
		answer string
	}{
		{[]string{"rm", "--uuid", sysDestUuid}, sysSyslogDelDestPath + sysDestUuid, answerDeleted},
		{[]string{"rm", "--description", "siem"}, sysSyslogDelDestPath + sysDestUuid, answerDeleted},
		{[]string{"enable", "--description", "siem"}, sysSyslogToggleDestPath + sysDestUuid + "/1", `{"result":"Enabled","changed":true}`},
		{[]string{"disable", "--uuid", sysDestUuid}, sysSyslogToggleDestPath + sysDestUuid + "/0", `{"result":"Disabled","changed":false}`},
	} {
		t.Run(sysName(tc.args), func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t)
			f.on("POST", tc.path, 200, tc.answer)
			var r = f.run(append([]string{"system", "logging", "destination"}, tc.args...)...)
			wantExit(t, r, 0)
			wantContains(t, "stdout", r.stdout, sysDestUuid)
			wantOneMutation(t, f, "POST", tc.path)
		})
	}

	for _, command := range []string{"rm", "enable", "disable"} {
		t.Run(command+" ambiguous / unknown / no selector make no change", func(t *testing.T) {
			t.Parallel()
			var f = sysLoggingFake(t, sysDestinationRow(map[string]any{"uuid": "d-dup", "description": "siem"}))
			wantFailure(t, f.run("system", "logging", "destination", command, "--description", "siem"), sysDestUuid, "d-dup")
			wantFailure(t, f.run("system", "logging", "destination", command, "--description", "nope"), "not found")
			wantFailure(t, f.run("system", "logging", "destination", command, "--uuid", "d-unknown"), "not found")
			wantFailure(t, f.run("system", "logging", "destination", command), "uuid")
			wantNoMutations(t, f)
		})
	}

	t.Run("rm of a destination deleted meanwhile", func(t *testing.T) {
		t.Parallel()
		var f = sysLoggingFake(t)
		f.on("POST", sysSyslogDelDestPath+sysDestUuid, 200, answerNotFound)
		wantFailure(t, f.run("system", "logging", "destination", "rm", "--uuid", sysDestUuid), "not found")
	})
}

func TestSysLoggingService(t *testing.T) {
	t.Parallel()

	t.Run("status", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysSyslogStatusPath, 200, `{"status":"running","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`)
		var r = f.run("system", "logging", "service", "status")
		wantExit(t, r, 0)
		wantContains(t, "output", r.stdout+r.stderr, "running")
		wantNoMutations(t, f)
	})
	for _, tc := range []struct {
		command string
		path    string
		answer  string
	}{
		{"restart", sysSyslogRestartPath, `{"response":"OK"}`},
		{"reconfigure", sysSyslogReconfigurePath, sysAnswerStatusOk},
	} {
		t.Run(tc.command+" is a POST", func(t *testing.T) {
			t.Parallel()
			var f = newFakeOPN(t)
			f.on("POST", tc.path, 200, tc.answer)
			wantExit(t, f.run("system", "logging", "service", tc.command), 0)
			wantOneMutation(t, f, "POST", tc.path)
			if calls := f.calls(); len(calls) != 1 {
				t.Errorf("want a single call, got %v", calls)
			}
		})
	}
	t.Run("reconfigure failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", sysSyslogReconfigurePath, 200, `{"status":"failed","status_msg":"syslog-ng config invalid"}`)
		wantFailure(t, f.run("system", "logging", "service", "reconfigure"), "syslog-ng config invalid")
	})
	t.Run("restart failure", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("POST", sysSyslogRestartPath, 200, `{"response":"FAILED"}`)
		wantFailure(t, f.run("system", "logging", "service", "restart"), "FAILED")
	})
}

func TestSysLoggingStats(t *testing.T) {
	t.Parallel()
	var header = []string{"SOURCE", "ID", "INSTANCE", "STATE", "TYPE", "NUMBER"}

	var f = newFakeOPN(t)
	f.on("GET", sysSyslogStatsPath, 200, sysSyslogStats)
	var r = f.run("system", "logging", "stats")
	wantExit(t, r, 0)
	// sorted by source
	sysWantTable(t, r.stdout, header, "destination", "dst.program", "global")
	wantNoMutations(t, f)

	t.Run("--search filters case-insensitive", func(t *testing.T) {
		t.Parallel()
		var f = newFakeOPN(t)
		f.on("GET", sysSyslogStatsPath, 200, sysSyslogStats)
		var r = f.run("system", "logging", "stats", "--search", "PORTALAUTH")
		wantExit(t, r, 0)
		sysWantTable(t, r.stdout, header, "destination")
	})
}
