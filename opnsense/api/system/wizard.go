package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Wizard is the current configuration as shown by the setup wizard (System > Wizard, api/core/initial_setup).
// Option fields hold the selected key(s), comma separated. Password fields of the wizard
// (root password, PPPoE password) are deliberately not decoded.
//
// There is no setter: core/initial_setup/configure always re-applies the whole wizard (WAN, LAN incl. its DHCP
// range, root password, deployment type) and reloads all services, it can not be scoped to single fields.
type Wizard struct {
	Hostname         string
	Domain           string
	Language         string
	DnsServers       string // comma separated
	DnsAllowOverride string // "1": allow DNS servers to be overridden by DHCP/PPP on WAN
	Timezone         string
	Unbound          WizardUnbound
	Wan              WizardWan
	Lan              WizardLan
	DeploymentType   WizardDeploymentType
}

type WizardUnbound struct {
	Enabled        string `json:"enabled"`
	Dnssec         string `json:"dnssec"`
	DnssecStripped string `json:"dnssecstripped"`
}

type WizardWan struct {
	Disable       string
	Ipv4Type      string // dhcp, static or pppoe
	SpoofMac      string
	Mtu           string
	Mss           string
	Ipaddr        string // CIDR, only for static
	Gateway       string
	DhcpHostname  string
	PppoeUsername string
	PppoeProvider string
	BlockPriv     string
	BlockBogons   string
}

type WizardLan struct {
	Ipaddr        string `json:"ipaddr"` // CIDR
	Disable       string `json:"disable"`
	ConfigureDhcp string `json:"configure_dhcp"`
}

type WizardDeploymentType struct {
	Multiwan            string `json:"multiwan"`
	DhcpDnsRegistration string `json:"dhcp_dns_registration"`
	Maxthreads          string `json:"maxthreads"`
}

// wizardOption decodes a plain string or an OPNsense option map {"<key>":{"value":"..","selected":1},...}
// into the selected key(s), comma separated in the order OPNsense sent them. Empty keys are skipped
type wizardOption string

func (o *wizardOption) UnmarshalJSON(data []byte) error {
	var plain string
	if err := json.Unmarshal(data, &plain); err == nil {
		*o = wizardOption(plain)
		return nil
	}

	// decode token by token, json.Unmarshal into a map would lose the order (relevant for dns servers)
	var decoder = json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("unexpected option value: %s", data)
	}
	var selected = make([]string, 0)
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return err
		}
		var option struct {
			Selected any `json:"selected"`
		}
		if err := decoder.Decode(&option); err != nil {
			return err
		}
		var key = keyToken.(string)
		if key != "" && fmt.Sprint(option.Selected) == "1" {
			selected = append(selected, key)
		}
	}
	*o = wizardOption(strings.Join(selected, ","))
	return nil
}

// wizardResponse mirrors the answer of core/initial_setup/get, without any password field
type wizardResponse struct {
	Wizard *struct {
		Hostname         string        `json:"hostname"`
		Domain           string        `json:"domain"`
		Language         wizardOption  `json:"language"`
		DnsServers       wizardOption  `json:"dns_servers"`
		DnsAllowOverride string        `json:"dnsallowoverride"`
		Timezone         wizardOption  `json:"timezone"`
		Unbound          WizardUnbound `json:"unbound"`
		Interfaces       struct {
			Wan struct {
				Disable       string       `json:"disable"`
				Ipv4Type      wizardOption `json:"ipv4_type"`
				SpoofMac      string       `json:"spoofmac"`
				Mtu           string       `json:"mtu"`
				Mss           string       `json:"mss"`
				Ipaddr        string       `json:"ipaddr"`
				Gateway       string       `json:"gateway"`
				DhcpHostname  string       `json:"dhcphostname"`
				PppoeUsername string       `json:"pppoe_username"`
				PppoeProvider string       `json:"pppoe_provider"`
				BlockPriv     string       `json:"blockpriv"`
				BlockBogons   string       `json:"blockbogons"`
			} `json:"wan"`
			Lan WizardLan `json:"lan"`
		} `json:"interfaces"`
		DeploymentType WizardDeploymentType `json:"deployment_type"`
	} `json:"wizard"`
}

// WizardGet returns the current settings as shown by the setup wizard (read-only)
func (opn *SystemApi) WizardGet() (Wizard, error) {
	var response wizardResponse
	if err := opn.DoJSON("GET", opn.EndpointForPluginControllerMethod("core", "initial_setup", "get"), nil, &response); err != nil {
		return Wizard{}, err
	}
	if response.Wizard == nil {
		return Wizard{}, fmt.Errorf("unexpected answer from core initial_setup: no wizard given")
	}

	var w = response.Wizard
	var wan = w.Interfaces.Wan
	return Wizard{
		Hostname:         w.Hostname,
		Domain:           w.Domain,
		Language:         string(w.Language),
		DnsServers:       string(w.DnsServers),
		DnsAllowOverride: w.DnsAllowOverride,
		Timezone:         string(w.Timezone),
		Unbound:          w.Unbound,
		Wan: WizardWan{
			Disable:       wan.Disable,
			Ipv4Type:      string(wan.Ipv4Type),
			SpoofMac:      wan.SpoofMac,
			Mtu:           wan.Mtu,
			Mss:           wan.Mss,
			Ipaddr:        wan.Ipaddr,
			Gateway:       wan.Gateway,
			DhcpHostname:  wan.DhcpHostname,
			PppoeUsername: wan.PppoeUsername,
			PppoeProvider: wan.PppoeProvider,
			BlockPriv:     wan.BlockPriv,
			BlockBogons:   wan.BlockBogons,
		},
		Lan:            w.Interfaces.Lan,
		DeploymentType: w.DeploymentType,
	}, nil
}
