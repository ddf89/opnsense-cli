//go:build integration

package integrationvpn

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// opn /vpn/openvpn/export against the live box. Like export_test.go the fixture is a disabled server instance
// (OPNsense exports enabled ones only), so these tests check what the CLI does with a server that is not
// exportable; the download of an exportable server is covered by the unit tests (cli/vpn_openvpn_export_test.go)

func TestCliExportTemplates(t *testing.T) {
	var result = mustOpn(t, "/vpn/openvpn/export", "templates")
	requireContains(t, result, result.stdout, "NAME", "PlainOpenVPN", "File Only", "ArchiveOpenVPN", "p12-password")

	result = mustOpn(t, "/vpn/openvpn/export", "templates", "json")
	var lines = strings.Split(strings.TrimSpace(result.stdout), "\n")
	var template map[string]any
	if len(lines) < 3 || json.Unmarshal([]byte(lines[0]), &template) != nil || template["name"] == "" {
		t.Errorf("want one JSON object per template:\n%s", result)
	}
}

func TestCliExportDisabledServer(t *testing.T) {
	var fixture = newExportFixture(t, "cli-export")

	t.Run("print does not list it", func(t *testing.T) {
		var result = mustOpn(t, "/vpn/openvpn/export", "print")
		requireContains(t, result, result.stdout, "DESCRIPTION", "UUID")
		if strings.Contains(result.stdout, fixture.instanceUuid) || strings.Contains(result.stdout, runPrefix) {
			t.Errorf("the disabled instance is listed:\n%s", result)
		}
		result = mustOpn(t, "/vpn/openvpn/export", "print", "json")
		if strings.Contains(result.stdout, fixture.instanceUuid) {
			t.Errorf("the disabled instance is listed:\n%s", result)
		}
	})
	t.Run("accounts, show and set refuse it", func(t *testing.T) {
		for _, args := range [][]string{
			{"accounts", fixture.instanceUuid},
			{"show", fixture.instanceUuid},
			{"set", fixture.instanceUuid, "hostname=vpn.example.com"},
			{"set", testDescription("cli-export"), "template=PlainOpenVPN"},
		} {
			var result = mustFailOpn(t, append([]string{"/vpn/openvpn/export"}, args...)...)
			requireContains(t, result, result.stderr, "not found", "only enabled")
			requireNoStdout(t, result)
		}
	})
	t.Run("download writes nothing", func(t *testing.T) {
		var dir = t.TempDir()
		for _, args := range [][]string{
			{"download", fixture.instanceUuid, "account=" + fixture.clientRef, "hostname=vpn.example.com"},
			{"download", fixture.instanceUuid, "account=none", "file=-"},
		} {
			var result = runOpnIn(t, dir, append([]string{"/vpn/openvpn/export"}, args...)...)
			if result.exitCode != 1 || !strings.Contains(result.stderr, "only enabled") {
				t.Errorf("want a not found error:\n%s", result)
			}
			requireNoStdout(t, result)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("files written: %v", entries)
		}
	})
	t.Run("invalid arguments are refused before any call", func(t *testing.T) {
		var result = mustFailOpn(t, "/vpn/openvpn/export", "set", fixture.instanceUuid, "port=70000")
		requireContains(t, result, result.stderr, "port")
		result = mustFailOpn(t, "/vpn/openvpn/export", "download", fixture.instanceUuid, "account=none", "file=-", "overwrite")
		requireContains(t, result, result.stderr, "overwrite has no effect")
	})
}
