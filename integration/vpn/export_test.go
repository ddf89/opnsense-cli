//go:build integration

package integrationvpn

import (
	"errors"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/openvpn"
)

// OpenVPN client export (opnsense/api/openvpn/export.go) against the live box.
//
// OPNsense only exports ENABLED server instances (ExportController::openvpnServers and
// OpenVPN::getInstanceById skip disabled ones), and the tests never create enabled instances on the shared box.
// So the fixture is a disabled server instance with a test CA, server and client certificate: the tests check
// that it is not exportable (not listed, no accounts, download refused, presets not stored) and run what works
// without an exportable server (templates, preset validation). The download itself is covered by the unit tests.

// exportFixture is a disabled server instance with a CA, its server certificate and a client certificate
type exportFixture struct {
	caRef        string
	clientRef    string
	clientCN     string
	instanceUuid string
	vpnid        string
}

// newExportFixture creates the fixture via the raw API, all descriptions carry testDescription(label); the
// cleanup deletes instance, certificates and CA (in this order) and checks they are gone
func newExportFixture(t *testing.T, label string) exportFixture {
	t.Helper()
	var core = coreApi(t)
	var description = testDescription(label)
	var fixture = exportFixture{clientCN: runPrefix + "-" + label + "-client"}

	var add = func(endpoint string, body any) string {
		t.Helper()
		var uuid, err = core.Mutate(core.EndpointForModule(endpoint), body)
		if err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
		return uuid
	}
	var remove = func(what string, search string, del string, uuid string) {
		t.Cleanup(func() {
			if _, err := core.Mutate(core.EndpointForModule(del+"/"+uuid), nil); err != nil {
				t.Errorf("deleting %s %s: %v", what, uuid, err)
			}
			var rows, err = rawSearch(core, search, description)
			if err != nil {
				t.Errorf("searching %s: %v", what, err)
			}
			for _, row := range rows {
				if row.Uuid == uuid {
					t.Errorf("%s %s still exists after delete", what, uuid)
				}
			}
		})
	}
	var refid = func(search string, uuid string) string {
		t.Helper()
		var rows, err = api.Search[struct {
			Uuid  string `json:"uuid"`
			Refid string `json:"refid"`
		}](core, core.EndpointForModule(search), description)
		if err != nil {
			t.Fatalf("%s: %v", search, err)
		}
		for _, row := range rows {
			if row.Uuid == uuid && row.Refid != "" {
				return row.Refid
			}
		}
		t.Fatalf("%s: no refid for %s", search, uuid)
		return ""
	}

	// registered first, removed last
	var caUuid = add("trust/ca/add", map[string]any{"ca": map[string]string{
		"action": "internal", "descr": description + " ca", "commonname": runPrefix + "-" + label + "-ca",
		"key_type": "2048", "digest": "sha256", "lifetime": "30", "country": "NL",
	}})
	remove("ca", "trust/ca/search", "trust/ca/del", caUuid)
	fixture.caRef = refid("trust/ca/search", caUuid)

	var certificate = func(kind string, commonName string) string {
		var uuid = add("trust/cert/add", map[string]any{"cert": map[string]string{
			"action": "internal", "caref": fixture.caRef, "cert_type": kind, "descr": description + " " + kind,
			"commonname": commonName, "key_type": "2048", "digest": "sha256", "lifetime": "30",
		}})
		remove("certificate", "trust/cert/search", "trust/cert/del", uuid)
		return uuid
	}
	var serverRef = refid("trust/cert/search", certificate("server_cert", runPrefix+"-"+label+"-server"))
	fixture.clientRef = refid("trust/cert/search", certificate("usr_cert", fixture.clientCN))

	// DISABLED: nothing listens and OPNsense does not export it. vpnid "" makes OPNsense pick a free one
	fixture.instanceUuid = add("openvpn/instances/add", map[string]any{"instance": map[string]string{
		"vpnid": "", "enabled": "0", "role": "server", "dev_type": "tun", "proto": "udp", "port": "11940",
		"server": "10.253.77.0/24", "ca": fixture.caRef, "cert": serverRef, "description": description,
	}})
	remove("openvpn instance", "openvpn/instances/search", "openvpn/instances/del", fixture.instanceUuid)

	var instance struct {
		Instance struct {
			Vpnid   string `json:"vpnid"`
			Enabled string `json:"enabled"`
		} `json:"instance"`
	}
	if err := core.DoJSON("GET", core.EndpointForModule("openvpn/instances/get/"+fixture.instanceUuid), nil, &instance); err != nil {
		t.Fatalf("openvpn/instances/get: %v", err)
	}
	if instance.Instance.Enabled != "0" || instance.Instance.Vpnid == "" {
		t.Fatalf("want a disabled instance with a vpnid, got %+v", instance.Instance)
	}
	fixture.vpnid = instance.Instance.Vpnid
	return fixture
}

func exportApi(t *testing.T) *openvpn.OpenVPNApi {
	t.Helper()
	return &openvpn.OpenVPNApi{OPNsense: coreApi(t)}
}

func TestExportTemplates(t *testing.T) {
	var templates, err = exportApi(t).ExportTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var byName = map[string]openvpn.ExportTemplate{}
	for _, template := range templates {
		byName[template.Name] = template
	}
	var plain, archive = byName["PlainOpenVPN"], byName["ArchiveOpenVPN"]
	if plain.Description != "File Only" || archive.Description != "Archive" || byName[openvpn.ExportDefaultTemplate].Name == "" {
		t.Fatalf("templates: %+v", templates)
	}
	if plain.Supports(openvpn.ExportOptionP12Password) || !archive.Supports(openvpn.ExportOptionP12Password) ||
		!plain.Supports(openvpn.ExportOptionPlainConfig) {
		t.Errorf("supported options: %+v", templates)
	}
}

// TestExportServersListsOnlyEnabled checks the listed servers are well formed and the disabled fixture is not one of them
func TestExportServersListsOnlyEnabled(t *testing.T) {
	var fixture = newExportFixture(t, "export-list")
	var vpn = exportApi(t)

	var servers, err = vpn.ExportServers()
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range servers {
		if server.Vpnid == fixture.instanceUuid || server.Vpnid == fixture.vpnid {
			t.Errorf("the disabled instance is listed: %+v", server)
		}
		if server.Vpnid == "" || server.Name == "" || len(server.Presets) != len(openvpn.ExportPresetNames) {
			t.Errorf("malformed server: %+v", server)
		}
	}
	for _, vpnid := range []string{fixture.instanceUuid, fixture.vpnid} {
		if _, err := vpn.ExportServerGet(vpnid); !api.IsNotFound(err) {
			t.Errorf("ExportServerGet(%s): want not found, got %v", vpnid, err)
		}
	}
}

// TestExportDisabledServer checks a disabled server can not be exported and its presets are not stored
func TestExportDisabledServer(t *testing.T) {
	var fixture = newExportFixture(t, "export-disabled")
	var vpn = exportApi(t)

	t.Run("no accounts", func(t *testing.T) {
		// OPNsense answers the "(none)" entry only, although the client certificate belongs to the server's CA
		var raw map[string]any
		if err := vpn.DoJSON("GET", vpn.EndpointForModule("openvpn/export/accounts/"+fixture.instanceUuid), nil, &raw); err != nil {
			t.Fatal(err)
		}
		if _, hasClient := raw[fixture.clientRef]; hasClient || len(raw) != 1 {
			t.Errorf("OPNsense lists accounts of a disabled server now: %v", raw)
		}
		var accounts, err = vpn.ExportAccounts(fixture.instanceUuid)
		if !api.IsNotFound(err) {
			t.Errorf("want not found, got %v %+v", err, accounts)
		}
	})
	t.Run("download is refused", func(t *testing.T) {
		// OPNsense answers a plain failure before it looks at (and stores) the options
		var raw map[string]any
		var body = map[string]any{"openvpn_export": map[string]string{openvpn.ExportOptionHostname: "vpn.example.com", openvpn.ExportOptionTemplate: "PlainOpenVPN"}}
		if err := vpn.DoJSON("POST", vpn.EndpointForModule("openvpn/export/download/"+fixture.instanceUuid+"/"+fixture.clientRef), body, &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw) != 1 || raw["result"] != "failed" {
			t.Errorf("OPNsense exports a disabled server now: %v", raw)
		}
		var _, err = vpn.ExportDownload(fixture.instanceUuid, fixture.clientRef, openvpn.ExportOptions{openvpn.ExportOptionHostname: "vpn.example.com"})
		if !api.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
	})
	t.Run("presets are not stored", func(t *testing.T) {
		var _, err = vpn.ExportStorePresets(fixture.instanceUuid, openvpn.ExportOptions{openvpn.ExportOptionHostname: "vpn.example.com"})
		if !api.IsNotFound(err) {
			t.Errorf("want not found, got %v", err)
		}
	})
}

// TestExportValidatePresets runs the (never saving) preset validation for the disabled fixture
func TestExportValidatePresets(t *testing.T) {
	var fixture = newExportFixture(t, "export-validate")
	var vpn = exportApi(t)

	var changed, err = vpn.ExportValidatePresets(fixture.instanceUuid, openvpn.ExportOptions{
		openvpn.ExportOptionHostname: "vpn.example.com,198.51.100.7", openvpn.ExportOptionTemplate: "PlainOpenVPN",
		openvpn.ExportOptionLocalPort: "11940", openvpn.ExportOptionAuthNocache: "1", openvpn.ExportOptionPlainConfig: "verb 4\nmute 10",
	})
	if err != nil || !changed {
		t.Errorf("valid presets: changed %v, err %v", changed, err)
	}

	_, err = vpn.ExportValidatePresets(fixture.instanceUuid, openvpn.ExportOptions{
		openvpn.ExportOptionLocalPort: "70000", openvpn.ExportOptionRandomLocalPort: "maybe",
	})
	var validation *api.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("want a validation error, got %v", err)
	}
	for _, option := range []string{openvpn.ExportOptionHostname, openvpn.ExportOptionLocalPort, openvpn.ExportOptionRandomLocalPort} {
		if validation.Validations[option] == "" {
			t.Errorf("no validation message for %s: %v", option, validation.Validations)
		}
	}
}
