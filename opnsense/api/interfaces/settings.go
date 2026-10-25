package interfaces

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Settings are the global interface settings of Interfaces > Settings (api/interfaces/settings). Booleans are
// "0" / "1", the JSON names are the API's
type Settings struct {
	// DisableChecksumOffloading turns hardware checksum offloading off (default 1)
	DisableChecksumOffloading string `json:"disablechecksumoffloading"`
	// DisableSegmentationOffloading turns hardware TCP segmentation offloading (TSO) off (default 1)
	DisableSegmentationOffloading string `json:"disablesegmentationoffloading"`
	// DisableLargeReceiveOffloading turns hardware large receive offloading (LRO) off (default 1)
	DisableLargeReceiveOffloading string `json:"disablelargereceiveoffloading"`
	// DisableVlanHwFilter is the VLAN hardware filtering: "0" enable, "1" disable, "2" leave the driver default
	DisableVlanHwFilter string `json:"disablevlanhwfilter"`
	// DisableIpv6 ignores the IPv6 interface configuration and blocks all forwarded IPv6 traffic
	DisableIpv6 string `json:"disableipv6"`
	// Dhcp6NoRelease stops the DHCPv6 client from sending a release on exit
	Dhcp6NoRelease string `json:"dhcp6_norelease"`
	// Dhcp6Debug enables debug logging of the IPv6 clients
	Dhcp6Debug string `json:"dhcp6_debug"`
	// Dhcp6Duid is the DHCP unique identifier of the system (colon separated hex bytes), "" for the generated one
	Dhcp6Duid string `json:"dhcp6_duid"`
	// Dhcp6RaTimeout is the router advertisement timeout in seconds, 0 disables it (default 10)
	Dhcp6RaTimeout string `json:"dhcp6_ratimeout"`

	// Duids are DUIDs OPNsense offers to use (keys llt, ll, uuid, en, current), not part of the settings
	Duids map[string]string `json:"-"`
}

// SettingsFields are the settings to change with SettingsSet, only non nil fields are sent and OPNsense keeps
// the others
type SettingsFields struct {
	DisableChecksumOffloading     *string `json:"disablechecksumoffloading,omitempty"`
	DisableSegmentationOffloading *string `json:"disablesegmentationoffloading,omitempty"`
	DisableLargeReceiveOffloading *string `json:"disablelargereceiveoffloading,omitempty"`
	DisableVlanHwFilter           *string `json:"disablevlanhwfilter,omitempty"`
	DisableIpv6                   *string `json:"disableipv6,omitempty"`
	Dhcp6NoRelease                *string `json:"dhcp6_norelease,omitempty"`
	Dhcp6Debug                    *string `json:"dhcp6_debug,omitempty"`
	Dhcp6Duid                     *string `json:"dhcp6_duid,omitempty"`
	Dhcp6RaTimeout                *string `json:"dhcp6_ratimeout,omitempty"`
}

var duidPattern = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5,253}$`)

// SettingsValidateDuid checks a DUID like OPNsense does: 6-254 colon separated hex bytes of type 1-4 ("" for
// the generated DUID)
func SettingsValidateDuid(duid string) error {
	if duid == "" {
		return nil
	}
	if !duidPattern.MatchString(duid) {
		return fmt.Errorf("invalid DUID %q: 6 or more colon separated hex bytes like 00:01:00:01:32:70", duid)
	}
	var bytes = strings.Split(duid, ":")
	var kind, _ = strconv.ParseUint(bytes[1], 16, 8)
	var hardware, _ = strconv.ParseUint(bytes[3], 16, 8)
	var valid = (kind == 1 || kind == 3) && hardware == 1 || kind == 2 || kind == 4 || kind == 0 && hardware == 4
	if !valid {
		return fmt.Errorf("invalid DUID %q: unknown DUID type", duid)
	}
	return nil
}

// SettingsGet returns the interface settings and the DUIDs OPNsense offers
func (opn *InterfacesApi) SettingsGet() (Settings, error) {
	var container struct {
		Settings map[string]json.RawMessage `json:"settings"`
		Duids    map[string]string          `json:"duids"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("settings", "get"), nil, &container); err != nil {
		return Settings{}, err
	}
	if container.Settings == nil {
		return Settings{}, fmt.Errorf("unexpected answer from interface settings: no settings section")
	}
	var values = map[string]string{}
	for field, value := range container.Settings {
		if options, err := parseOptions(value); err == nil {
			var selected []string
			for _, option := range options {
				if option.Selected {
					selected = append(selected, option.Key)
				}
			}
			values[field] = strings.Join(selected, ",")
			continue
		}
		values[field] = valueText(value)
	}
	var encoded, _ = json.Marshal(values)
	var settings Settings
	if err := json.Unmarshal(encoded, &settings); err != nil {
		return Settings{}, err
	}
	settings.Duids = container.Duids
	if settings.Duids == nil {
		settings.Duids = map[string]string{}
	}
	return settings, nil
}

// SettingsSet changes only the non nil settings (a partial merge), it only saves them: they take effect with
// SettingsReconfigure
func (opn *InterfacesApi) SettingsSet(fields SettingsFields) error {
	if fields.Dhcp6Duid != nil {
		if err := SettingsValidateDuid(*fields.Dhcp6Duid); err != nil {
			return err
		}
	}
	var _, err = opn.Mutate(opn.endpoint("settings", "set"), map[string]any{"settings": fields})
	return err
}

// SettingsReconfigure applies the saved settings to all interfaces (pluginctl networking_reload): offloading and
// VLAN filtering changes reset the hardware settings of every interface, which may interrupt traffic
func (opn *InterfacesApi) SettingsReconfigure() error {
	return opn.reconfigure("settings", "interface settings")
}
