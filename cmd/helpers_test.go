package cmd

// In-process tests of pure helpers. Not parallel: captureStdout swaps os.Stdout

import (
	"encoding/json"
	"io"
	"opnsense-cli/opnsense/api/dnsmasq"
	"os"
	"testing"
	"time"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	var reader, writer, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var original = os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	var output = make(chan string)
	go func() {
		var data, _ = io.ReadAll(reader)
		output <- string(data)
	}()
	fn()
	_ = writer.Close()
	return <-output
}

func TestPrintTable(t *testing.T) {
	var got = captureStdout(t, func() {
		printTable([]string{"UUID", "NAME", "DESCRIPTION"}, [][]string{
			{"u-1", "a-long-name", "with spaces"},
			{"u-22", "", ""},
			{"", "b", "x"},
		})
	})
	var want = "" +
		"UUID  NAME         DESCRIPTION\n" +
		"u-1   a-long-name  with spaces\n" +
		"u-22  -            -\n" +
		"-     b            x\n"
	if got != want {
		t.Errorf("printTable:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestPrintTableOnlyHeader(t *testing.T) {
	var got = captureStdout(t, func() { printTable([]string{"A", "B"}, nil) })
	if got != "A  B\n" {
		t.Errorf("printTable without rows: %q", got)
	}
}

func TestPrintFields(t *testing.T) {
	var got = captureStdout(t, func() {
		printFields([][2]string{{"uuid", "u-1"}, {"description", ""}, {"ip", "10.0.0.1"}})
	})
	var want = "" +
		"uuid:         u-1\n" +
		"description:  \n" +
		"ip:           10.0.0.1\n"
	if got != want {
		t.Errorf("printFields:\n got %q\nwant %q", got, want)
	}
}

func TestBoolToInt(t *testing.T) {
	if BoolToInt(true) != 1 || BoolToInt(false) != 0 {
		t.Error("BoolToInt")
	}
}

func TestDnsmasqHostValidators(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"10.0.0.1", "10.0.0.1", true},
		{"fd00:0:0::1", "fd00::1", true},
		{"FD00::A", "fd00::a", true},
		{"10.0.0.256", "", false},
		{"10.0.0.0/24", "", false},
		{"host.lan", "", false},
	} {
		var got, err = dnsmasqHostValidateIp(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("dnsmasqHostValidateIp(%q) = %q, %v", tc.in, got, err)
		}
	}

	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", true},
		{"aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", true},
		{"aa:bb:cc:dd:ee", "", false},
		{"zz:bb:cc:dd:ee:ff", "", false},
	} {
		var got, err = dnsmasqHostValidateMac(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("dnsmasqHostValidateMac(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestDnsmasqHostJoinList(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{""}, ""},
		{[]string{" 10.0.0.1 ", "", "fd00:0::1"}, "10.0.0.1,fd00::1"},
	} {
		if got := dnsmasqHostJoinList("--ip", tc.in, dnsmasqHostValidateIp); got != tc.want {
			t.Errorf("dnsmasqHostJoinList(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := dnsmasqHostJoinList("--cname", []string{"a.lan", " b.lan"}, nil); got != "a.lan,b.lan" {
		t.Errorf("without normalize: %q", got)
	}
}

func TestDnsmasqHostYesNo(t *testing.T) {
	for in, want := range map[string]string{"1": "yes", "0": "no", "": "no"} {
		if got := dnsmasqHostYesNo(in); got != want {
			t.Errorf("dnsmasqHostYesNo(%q) = %q", in, got)
		}
	}
}

func TestDnsmasqLeaseHelpers(t *testing.T) {
	if dnsmasqLeaseOrEmpty("*") != "" || dnsmasqLeaseOrEmpty("laptop") != "laptop" {
		t.Error("dnsmasqLeaseOrEmpty")
	}

	for _, tc := range []struct {
		expire string
		want   string
	}{
		{"1761350400", time.Unix(1761350400, 0).Local().Format(time.DateTime)},
		{"0", "never"},
		{"", ""},
	} {
		var got = dnsmasqLeaseExpiry(dnsmasq.Lease{Expire: json.Number(tc.expire)})
		if got != tc.want {
			t.Errorf("dnsmasqLeaseExpiry(%q) = %q, want %q", tc.expire, got, tc.want)
		}
	}

	if got := dnsmasqLeaseInterface(dnsmasq.Lease{Interface: "igc1", InterfaceDescr: "LAN"}); got != "LAN" {
		t.Errorf("dnsmasqLeaseInterface prefers the description: %q", got)
	}
	if got := dnsmasqLeaseInterface(dnsmasq.Lease{Interface: "igc1"}); got != "igc1" {
		t.Errorf("dnsmasqLeaseInterface falls back to the device: %q", got)
	}
}
