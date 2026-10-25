//go:build integration

package integrationcaptiveportal

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

const (
	zoneMenu     = "/captive-portal/zone"
	templateMenu = "/captive-portal/template"
)

func testZip(t *testing.T, marker string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var writer = zip.NewWriter(&buffer)
	var file, _ = writer.Create("index.html")
	_, _ = file.Write([]byte("<html><body>" + marker + "</body></html>"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// requireZoneDisabled fails when the zone of this run is enabled (it never may be)
func requireZoneDisabled(t *testing.T, cp *captiveportal.CaptivePortalApi, uuid string) {
	t.Helper()
	if zone, err := cp.ZoneGet(uuid); err != nil || zone.Enabled != "0" {
		t.Fatalf("the test zone %s must be disabled: %q %v", uuid, zone.Enabled, err)
	}
}

func cleanupZone(t *testing.T, cp *captiveportal.CaptivePortalApi, uuid string) {
	t.Cleanup(func() {
		if err := cp.ZoneRemove(uuid); err != nil && !api.IsNotFound(err) {
			t.Errorf("cleanup of zone %s: %v", uuid, err)
		}
	})
}

func cleanupTemplate(t *testing.T, cp *captiveportal.CaptivePortalApi, name string) {
	t.Cleanup(func() {
		if template, err := cp.TemplateGetByName(name); err == nil {
			if err := cp.TemplateRemove(template.Uuid); err != nil {
				t.Errorf("cleanup of template %s: %v", template.Uuid, err)
			}
		}
	})
}

func TestLibraryZoneAndTemplate(t *testing.T) {
	var cp = testApi(t)
	var options, err = cp.ZoneOptions()
	if err != nil || len(options["interfaces"]) == 0 {
		t.Fatalf("zone options: %v %v", options["interfaces"], err)
	}
	var iface = options["interfaces"][0].Key

	var description = testDescription("lib")
	uuid, err := cp.ZoneCreate(captiveportal.ZoneFields{"enabled": "0", "interfaces": iface, "description": description,
		"idletimeout": "5", "allowedAddresses": "192.0.2.10,198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupZone(t, cp, uuid)
	requireZoneDisabled(t, cp, uuid)
	zone, err := cp.ZoneGetByDescription(description)
	if err != nil || zone.Uuid != uuid || zone.IdleTimeout != "5" || zone.AllowedAddresses != "192.0.2.10,198.51.100.0/24" {
		t.Fatalf("zone %+v %v", zone, err)
	}
	if changed, err := cp.ZoneSetEnabled(uuid, false); err != nil || changed {
		t.Errorf("disable a disabled zone: %v %v", changed, err)
	}
	requireZoneDisabled(t, cp, uuid)
	if err := cp.ZoneUpdate(uuid, captiveportal.ZoneFields{"idletimeout": "99999"}); err == nil {
		t.Error("an idle timeout over a week must be refused")
	}
	if err := cp.ZoneUpdate("00000000-0000-4000-8000-0000000000a9", captiveportal.ZoneFields{"idletimeout": "5"}); !api.IsNotFound(err) {
		t.Errorf("update of an unknown zone: %v", err)
	}
	if descriptions, err := cp.ZoneDescriptions(); err != nil || descriptions[zone.ZoneId] != description {
		t.Errorf("zone descriptions %v %v", descriptions, err)
	}

	var name = testTemplateName("lib")
	cleanupTemplate(t, cp, name)
	if err := cp.TemplateSave("", name, testZip(t, name)); err != nil {
		t.Fatal(err)
	}
	template, err := cp.TemplateGetByName(name)
	if err != nil || template.FileId == "" {
		t.Fatalf("template %+v %v", template, err)
	}
	content, err := cp.TemplateDownload(template.FileId)
	if err != nil || !bytes.HasPrefix(content, []byte("PK")) {
		t.Fatalf("download: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, file := range reader.File {
		if file.Name == "index.html" {
			var opened, _ = file.Open()
			var buffer bytes.Buffer
			_, _ = buffer.ReadFrom(opened)
			found = strings.Contains(buffer.String(), name)
		}
	}
	if !found || len(reader.File) < 5 {
		t.Errorf("the download must be the template over the default (%d files, own index %v)", len(reader.File), found)
	}
	if err := cp.TemplateSave("00000000-0000-4000-8000-0000000000a9", name, nil); !api.IsNotFound(err) {
		t.Errorf("save to an unknown uuid: %v", err)
	}
	if err := cp.TemplateSave("", testTemplateName("bad"), []byte("PK not really a zip")); err == nil {
		t.Error("an invalid zip must be refused")
	}
	if err := cp.ZoneUpdate(uuid, captiveportal.ZoneFields{"template": template.Uuid}); err != nil {
		t.Fatal(err)
	}
	if err := cp.ZoneRemove(uuid); err != nil {
		t.Fatal(err)
	}
	if err := cp.TemplateRemove(template.Uuid); err != nil {
		t.Fatal(err)
	}
	if err := cp.TemplateRemove(template.Uuid); !api.IsNotFound(err) {
		t.Errorf("second remove: %v", err)
	}
}

func TestCliZoneAndTemplate(t *testing.T) {
	var cp = testApi(t)
	var description = testDescription("cli")
	var result = mustOpn(t, zoneMenu, "add", "description="+description, "interfaces=LAN", "idle-timeout=10",
		"allowed-macs=02:00:00:00:a9:01", "auth-servers=Local Database")
	var uuid = uuidFrom(t, result)
	cleanupZone(t, cp, uuid)
	requireZoneDisabled(t, cp, uuid)

	result = mustOpn(t, zoneMenu, "print", "search="+runPrefix)
	requireContains(t, result, result.stdout, description, "yes")
	result = mustOpn(t, zoneMenu, "show", description)
	requireContains(t, result, result.stdout, "disabled:                yes", "idle-timeout:            10", "auth-servers:            Local Database")
	mustFailOpn(t, zoneMenu, "add", "description="+description, "interfaces=LAN")
	result = mustFailOpn(t, zoneMenu, "set", description, "interfaces=a9-no-such-interface")
	requireContains(t, result, result.stderr, "valid are")
	// enable needs a confirmation and is refused here without it
	mustFailOpn(t, zoneMenu, "enable", description)
	result = mustOpn(t, zoneMenu, "disable", description)
	requireContains(t, result, result.stderr, "already disabled")
	requireZoneDisabled(t, cp, uuid)

	var dir = t.TempDir()
	var name = testTemplateName("cli")
	cleanupTemplate(t, cp, name)
	if err := os.WriteFile(filepath.Join(dir, "page.zip"), testZip(t, name), 0o600); err != nil {
		t.Fatal(err)
	}
	result = runOpnIn(t, dir, templateMenu, "upload", "name="+name, "file=page.zip")
	if result.exitCode != 0 {
		t.Fatalf("upload:\n%s", result)
	}
	var templateUuid = uuidFrom(t, result)
	if result = runOpnIn(t, dir, templateMenu, "upload", "name="+name, "file=page.zip"); result.exitCode == 0 {
		t.Errorf("a second upload must fail without replace:\n%s", result)
	}
	if result = runOpnIn(t, dir, templateMenu, "upload", "name="+name, "file=page.zip", "replace"); uuidFrom(t, result) != templateUuid {
		t.Errorf("replace returned another uuid:\n%s", result)
	}
	requireNoStdout(t, mustOpn(t, zoneMenu, "set", description, "template="+name))
	result = mustOpn(t, templateMenu, "print", "search="+templatePrefix())
	requireContains(t, result, result.stdout, name, description)
	mustFailOpn(t, templateMenu, "remove", name)
	result = runOpnIn(t, dir, templateMenu, "download", name, "file=out.zip")
	if content, err := os.ReadFile(filepath.Join(dir, "out.zip")); result.exitCode != 0 || err != nil || !bytes.HasPrefix(content, []byte("PK")) {
		t.Errorf("download:\n%s", result)
	}
	result = runOpnIn(t, dir, templateMenu, "download-default")
	if info, err := os.Stat(filepath.Join(dir, "template_default.zip")); result.exitCode != 0 || err != nil || info.Size() < 1000 {
		t.Errorf("download-default:\n%s", result)
	}
	var renamed = testTemplateName("cli renamed")
	cleanupTemplate(t, cp, renamed)
	requireNoStdout(t, mustOpn(t, templateMenu, "set", name, "name="+renamed))

	requireNoStdout(t, mustOpn(t, zoneMenu, "set", description, "template="))
	requireNoStdout(t, mustOpn(t, templateMenu, "remove", renamed))
	requireNoStdout(t, mustOpn(t, zoneMenu, "remove", description))
	if _, err := cp.ZoneGet(uuid); !api.IsNotFound(err) {
		t.Errorf("the removed zone still exists: %v", err)
	}
}

func TestSessionsServiceVouchers(t *testing.T) {
	var cp = testApi(t)
	if _, err := cp.SessionList(""); err != nil {
		t.Error(err)
	}
	mustOpn(t, "/captive-portal/session", "print")
	mustFailOpn(t, "/captive-portal/session", "disconnect", "a9-no-such-session")
	if status, err := cp.ServiceStatus(); err != nil || status == "" {
		t.Errorf("status %q %v", status, err)
	}
	mustOpn(t, "/captive-portal/service", "status")
	mustFailOpn(t, "/captive-portal/service", "stop")
	mustOpn(t, "/captive-portal/voucher", "providers")

	providers, err := cp.VoucherProviders()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.VoucherGenerate("a9-no-such-provider", runPrefix, 1, 60, 0); err == nil {
		t.Error("generate for an unknown provider must fail")
	}
	if len(providers) == 0 {
		t.Log("no voucher provider (auth server of type Voucher, legacy page without API): generate / drop only tested for errors")
		mustFailOpn(t, "/captive-portal/voucher", "groups")
		return
	}
	// a group of this run in the first provider, dropped afterwards
	var provider, group = providers[0], runPrefix
	t.Cleanup(func() {
		if err := cp.VoucherDropGroup(provider, group); err != nil {
			t.Errorf("drop of the test group: %v", err)
		}
	})
	var dir = t.TempDir()
	var result = runOpnIn(t, dir, "/captive-portal/voucher", "generate", "provider="+provider, "group="+group, "count=2", "validity=1h")
	if result.exitCode != 0 {
		t.Fatalf("generate:\n%s", result)
	}
	if content, err := os.ReadFile(filepath.Join(dir, group+".csv")); err != nil || strings.Count(string(content), "\n") != 3 {
		t.Errorf("csv %q %v", content, err)
	}
	vouchers, err := cp.VoucherList(provider, group)
	if err != nil || len(vouchers) != 2 || vouchers[0].State != "unused" {
		t.Errorf("vouchers %+v %v", vouchers, err)
	}
	mustOpn(t, "/captive-portal/voucher", "expire", string(vouchers[0].Username), "provider="+provider, "confirm=yes")
	requireNoStdout(t, mustOpn(t, "/captive-portal/voucher", "drop-group", "provider="+provider, "group="+group, "confirm=yes"))
	if vouchers, _ := cp.VoucherList(provider, group); len(vouchers) != 0 {
		t.Errorf("the dropped group still has vouchers: %d", len(vouchers))
	}
}
