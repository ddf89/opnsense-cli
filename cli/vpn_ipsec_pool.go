package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"opnsense-cli/opnsense/api/ipsec"
)

// /vpn/ipsec/pool, /vpn/ipsec/vti and /vpn/ipsec/manual-spd: the address pools for mobile clients (selected by
// name), the virtual tunnel interfaces for route based IPsec (natural key reqid, also selected by the device name
// ipsec<reqid> or the description) and the manual SPD entries (selected by description)

var vpnIpsecPoolNamePattern = regexp.MustCompile(`^[0-9a-zA-Z,_\-:]+$`)

func vpnIpsecValidatePoolName(value string) error {
	if len(value) > 1024 || !vpnIpsecPoolNamePattern.MatchString(value) {
		return errors.New("must be letters, digits and , _ - : (no spaces)")
	}
	return nil
}

func vpnIpsecPoolFields(add bool) []vpnIpsecField {
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "name", Help: "unique name, connections refer to it with pools=", Validate: vpnIpsecValidatePoolName}), field: "name"},
		{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the pool, but don't load it"}, field: "enabled", kind: vpnIpsecDisabled},
		{Arg: vpnIpsecRequired(add, Arg{Name: "network", Help: "the subnet the addresses are taken from, e.g. 198.51.100.0/24", Validate: vpnIpsecValidateCIDR}), field: "addrs"},
		{Arg: Arg{Name: "dns", Type: List, Help: "DNS servers pushed to the clients", Validate: ValidateIPList}, field: "dns", kind: vpnIpsecList},
	}
}

func vpnIpsecVtiFields(add bool) []vpnIpsecField {
	var address = func(name string, help string, required bool) vpnIpsecField {
		return vpnIpsecField{Arg: vpnIpsecRequired(add && required, Arg{Name: name, Help: help, Validate: ValidateIP}),
			field: strings.ReplaceAll(name, "-", "_")}
	}
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "reqid", Type: Int, Help: "unique reqid, also the device number (ipsec<reqid>), children use it with reqid=",
			Validate: vpnIpsecValidateReqid}), field: "reqid"},
		{Arg: Arg{Name: "description", Help: "description", Validate: vpnIpsecValidateText}, field: "description"},
		{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the interface, but don't create it"}, field: "enabled", kind: vpnIpsecDisabled},
		address("local", "local outer address of the ESP packets (with remote, or neither)", false),
		address("remote", "remote outer address of the ESP packets", false),
		address("tunnel-local", "inner local address for routing", true),
		address("tunnel-remote", "inner remote address for routing (same family as tunnel-local)", true),
		address("tunnel-local2", "secondary inner local address", false),
		address("tunnel-remote2", "secondary inner remote address", false),
		{Arg: Arg{Name: "skip-firewall", Type: Bool, Help: "skip the firewall rules of the enc0 interface for outbound traffic (allows source NAT)"},
			field: "skip_fw", kind: vpnIpsecFlag},
	}
}

func vpnIpsecValidateReqid(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	return ValidateRange(1, 65535)(value)
}

func vpnIpsecManualSpdFields(add bool) []vpnIpsecField {
	return []vpnIpsecField{
		{Arg: Arg{Name: "description", Help: "description", Validate: vpnIpsecValidateText}, field: "description"},
		{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the entry, but don't install it"}, field: "enabled", kind: vpnIpsecDisabled},
		{Arg: Arg{Name: "protocol", Values: []string{"esp", "ah"}, Validate: vpnIpsecNotEmpty, Help: "esp (default) or ah"}, field: "protocol"},
		{Arg: Arg{Name: "reqid", Type: Int, Help: "register the entry on this reqid (either reqid or child)", Validate: ValidateRange(1, 65535)}, field: "reqid"},
		{Arg: Arg{Name: "child", Help: `register the entry on this child: its uuid or "<connection> - <child>" (either reqid or child)`,
			Complete: vpnIpsecCompleteRef((*ipsec.IPsecApi).ManualSpdForm, "connection_child", false)}, field: "connection_child", kind: vpnIpsecRef},
		{Arg: vpnIpsecRequired(add, Arg{Name: "source", Help: "source network, e.g. the network translated by NAT", Validate: vpnIpsecValidateNetwork}), field: "source"},
		{Arg: Arg{Name: "destination", Help: "destination network, empty for the networks of the child SA", Validate: vpnIpsecValidateNetwork}, field: "destination"},
	}
}

// vpnIpsecPoolInUse refuses to remove a pool connections use (OPNsense would keep the dangling uuid)
func vpnIpsecPoolInUse(api *ipsec.IPsecApi, pool ipsec.Record) error {
	var connections, err = api.ConnectionList("")
	if err != nil {
		return err
	}
	if users := vpnIpsecUsers(connections, "pools", pool.Uuid(), vpnIpsecQuoted("description")); len(users) > 0 {
		return fmt.Errorf("the pool %q is used by the connections %s, change their pools= first", pool.Value("name"), strings.Join(users, ", "))
	}
	return nil
}

// vpnIpsecReadOnlyVti refuses changes of interfaces OPNsense generates from legacy tunnels
func vpnIpsecReadOnlyVti(update func(api *ipsec.IPsecApi, uuid string, fields ipsec.Fields) error) func(api *ipsec.IPsecApi, uuid string, fields ipsec.Fields) error {
	return func(api *ipsec.IPsecApi, uuid string, fields ipsec.Fields) error {
		var vti, err = api.VtiGet(uuid)
		if err != nil {
			return err
		}
		if vti.Value("origin") == "legacy" {
			return fmt.Errorf("the interface ipsec%s is generated from a legacy tunnel and read-only", vti.Value("reqid"))
		}
		return update(api, uuid, fields)
	}
}

func init() {
	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/pool", help: "address pools for the virtual IPs of mobile clients (VPN > IPsec > Connections > Pools)",
		noun: "pool", itemHelp: "the #, uuid or name of the pool", prefix: "pool.",
		addLong: `Connections hand out addresses from a pool with pools=<name>. The name names the pool: if it exists
already, add fails unless replace is given, then that pool is replaced completely.`,
		setLong:    `name= renames the pool, the connections keep using it.`,
		fields:     vpnIpsecPoolFields,
		fieldNames: ipsec.PoolFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.PoolList("") },
		form:       (*ipsec.IPsecApi).PoolForm,
		create:     (*ipsec.IPsecApi).PoolCreate,
		update:     (*ipsec.IPsecApi).PoolUpdate,
		remove:     (*ipsec.IPsecApi).PoolRemove,
		setEnabled: (*ipsec.IPsecApi).PoolSetEnabled,
		names:      func(r ipsec.Record) []string { return []string{r.Value("name")} },
		label:      vpnIpsecQuoted("name"),
		key: func(r ipsec.Record, values map[string]string) bool {
			return strings.EqualFold(r.Value("name"), values["name"])
		},
		keyText: "name",
		columns: []vpnIpsecColumn{
			{"DISABLED", vpnIpsecDisabledText},
			{"NAME", func(r ipsec.Record) string { return r.Value("name") }},
			{"NETWORK", func(r ipsec.Record) string { return r.Value("addrs") }},
			{"DNS", func(r ipsec.Record) string { return r.Value("dns") }},
		},
		removeLong:   "A pool used by connections can not be removed.",
		beforeRemove: vpnIpsecPoolInUse,
	})

	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/vti", help: "virtual tunnel interfaces (ipsec<reqid>) for route based IPsec (VPN > IPsec > Virtual Tunnel Interfaces)",
		noun: "virtual tunnel interface", itemHelp: "the #, uuid, device name (ipsec<reqid>) or description of the interface", prefix: "vti.",
		addLong: `The interface ipsec<reqid> carries the traffic of the children with the same reqid (child reqid= and
policies=no). The reqid names the interface: if it exists already, add fails unless replace is given, then that
interface is replaced completely. Interfaces generated from legacy tunnels are read-only.`,
		fields:     vpnIpsecVtiFields,
		fieldNames: ipsec.VtiFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.VtiList("") },
		form:       (*ipsec.IPsecApi).VtiForm,
		create:     (*ipsec.IPsecApi).VtiCreate,
		update:     vpnIpsecReadOnlyVti((*ipsec.IPsecApi).VtiUpdate),
		remove:     (*ipsec.IPsecApi).VtiRemove,
		setEnabled: (*ipsec.IPsecApi).VtiSetEnabled,
		names: func(r ipsec.Record) []string {
			return []string{"ipsec" + r.Value("reqid"), r.Value("description")}
		},
		label: func(r ipsec.Record) string { return "ipsec" + r.Value("reqid") },
		key: func(r ipsec.Record, values map[string]string) bool {
			return r.Value("reqid") == values["reqid"]
		},
		keyText: "reqid",
		columns: []vpnIpsecColumn{
			{"DISABLED", vpnIpsecDisabledText},
			{"DEVICE", func(r ipsec.Record) string { return "ipsec" + r.Value("reqid") }},
			{"LOCAL", func(r ipsec.Record) string { return r.Value("local") }},
			{"REMOTE", func(r ipsec.Record) string { return r.Value("remote") }},
			{"TUNNEL", func(r ipsec.Record) string {
				return strings.Trim(r.Value("tunnel_local")+" - "+r.Value("tunnel_remote"), " -")
			}},
			{"ORIGIN", func(r ipsec.Record) string { return r.Value("origin") }},
			{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
		},
		removeLong: "The device is removed by the next reconfigure.",
	})

	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/manual-spd", help: "manual security policies, e.g. for NAT before IPsec (VPN > IPsec > Connections > Manual SPD)",
		noun: "manual SPD entry", plural: "manual SPD entries", itemHelp: "the #, uuid or description of the entry", prefix: "spd.",
		addLong: `The entry is installed when a CHILD SA with the reqid (or of the child) comes up, established tunnels
need to reconnect. Give either reqid= or child=.`,
		fields:     vpnIpsecManualSpdFields,
		fieldNames: ipsec.ManualSpdFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.ManualSpdList("") },
		form:       (*ipsec.IPsecApi).ManualSpdForm,
		create:     (*ipsec.IPsecApi).ManualSpdCreate,
		update:     (*ipsec.IPsecApi).ManualSpdUpdate,
		remove:     (*ipsec.IPsecApi).ManualSpdRemove,
		setEnabled: (*ipsec.IPsecApi).ManualSpdSetEnabled,
		names:      vpnIpsecDescriptionName,
		label:      vpnIpsecQuoted("description"),
		check: func(args *Args) error {
			if args.Has("reqid") && args.Has("child") && args.String("reqid") != "" && args.String("child") != "" {
				return errors.New("give either reqid or child, not both")
			}
			return nil
		},
		columns: []vpnIpsecColumn{
			{"DISABLED", vpnIpsecDisabledText},
			{"PROTOCOL", func(r ipsec.Record) string { return r.Value("protocol") }},
			{"REQID", func(r ipsec.Record) string { return r.Value("reqid") }},
			{"CHILD", func(r ipsec.Record) string { return r.Display("connection_child") }},
			{"SOURCE", func(r ipsec.Record) string { return r.Value("source") }},
			{"DESTINATION", func(r ipsec.Record) string { return r.Value("destination") }},
			{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
		},
	})
}
