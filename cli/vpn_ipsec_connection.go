package cli

import (
	"fmt"
	"strings"

	"opnsense-cli/opnsense/api/ipsec"
)

// /vpn/ipsec/connection, local, remote and child: the swanctl connections of VPN > IPsec > Connections with
// their local and remote authentication rounds and children (CHILD SAs). Connections are selected by the #
// of print, the uuid or the description (their natural key). Locals, remotes and children belong to a connection
// (connection= by uuid or description): a round's natural key is its connection and round number, a child's its
// connection and description

const vpnIpsecTimeHelp = " in seconds, empty for the strongSwan default"

func vpnIpsecConnectionFields(add bool) []vpnIpsecField {
	var timeArg = func(name string, help string) Arg {
		return Arg{Name: name, Type: Int, Help: help + vpnIpsecTimeHelp, Validate: ValidateRange(0, 500000)}
	}
	var ports = [][2]string{{"500", ""}, {"4500", "4500"}}
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "description", Help: "description, also the name of the connection", Validate: vpnIpsecNotEmpty}), field: "description"},
		{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the connection, but don't load it"}, field: "enabled", kind: vpnIpsecDisabled},
		vpnIpsecMap(Arg{Name: "version", Help: "IKE version: ike (IKEv1+IKEv2, the default), ikev1 (deprecated) or ikev2"}, "version",
			[2]string{"ike", "0"}, [2]string{"ikev1", "1"}, [2]string{"ikev2", "2"}),
		{Arg: Arg{Name: "proposals", Type: List, Validate: vpnIpsecNotEmpty, Help: "IKE proposals like aes256gcm16-sha256-x25519, default for the strongSwan defaults",
			Complete: vpnIpsecCompleteRef((*ipsec.IPsecApi).ConnectionForm, "proposals", true)}, field: "proposals", kind: vpnIpsecRefList, keys: true},
		{Arg: Arg{Name: "local-addresses", Type: List, Help: "local addresses, DNS names, subnets or ranges for IKE, empty for any"}, field: "local_addrs", kind: vpnIpsecList},
		{Arg: Arg{Name: "remote-addresses", Type: List, Help: "remote addresses, DNS names, subnets or ranges for IKE, empty for any"}, field: "remote_addrs", kind: vpnIpsecList},
		vpnIpsecMap(Arg{Name: "local-port", Help: "local IKE port: 500 (default, floats to 4500 behind NAT) or 4500"}, "local_port", ports...),
		vpnIpsecMap(Arg{Name: "remote-port", Help: "remote IKE port: 500 (default) or 4500"}, "remote_port", ports...),
		{Arg: Arg{Name: "unique", Values: []string{"no", "never", "keep", "replace"}, Validate: vpnIpsecNotEmpty,
			Help: "uniqueness policy for connections of the same peer, default no"}, field: "unique"},
		{Arg: Arg{Name: "aggressive", Type: Bool, Help: "IKEv1 aggressive mode (deprecated, less secure)"}, field: "aggressive", kind: vpnIpsecFlag},
		{Arg: Arg{Name: "mobike", Type: Bool, Help: "MOBIKE for IKEv2 (default yes)"}, field: "mobike", kind: vpnIpsecFlag},
		{Arg: Arg{Name: "udp-encapsulation", Type: Bool, Help: "force UDP encapsulation of ESP by faking NAT detection"}, field: "encap", kind: vpnIpsecFlag},
		{Arg: timeArg("reauth-time", "time until the IKE SA is reauthenticated"), field: "reauth_time"},
		{Arg: timeArg("rekey-time", "time until the IKE SA is rekeyed"), field: "rekey_time"},
		{Arg: timeArg("over-time", "hard IKE SA lifetime when rekeying or reauthentication fails"), field: "over_time"},
		{Arg: timeArg("dpd-delay", "interval of dead peer detection checks"), field: "dpd_delay"},
		{Arg: timeArg("dpd-timeout", "IKEv1 dead peer detection timeout (deprecated)"), field: "dpd_timeout"},
		{Arg: Arg{Name: "pools", Type: List, Help: "address pools (names) for the virtual IPs of clients, or radius",
			Complete: vpnIpsecCompleteRef((*ipsec.IPsecApi).ConnectionForm, "pools", false)}, field: "pools", kind: vpnIpsecRefList},
		{Arg: Arg{Name: "send-cert-req", Type: Bool, Help: "send certificate requests (default yes)"}, field: "send_certreq", kind: vpnIpsecFlag},
		vpnIpsecMap(Arg{Name: "send-cert", Help: "when to send the certificate: default (if asked), if-asked, never or always"}, "send_cert",
			[2]string{"default", ""}, [2]string{"if-asked", "ifasked"}, [2]string{"never", "never"}, [2]string{"always", "always"}),
		{Arg: Arg{Name: "keying-tries", Type: Int, Help: "retransmission sequences on the initial connect, 0 for forever, empty for 1",
			Validate: ValidateRange(0, 1000)}, field: "keyingtries"},
	}
}

// vpnIpsecRoundFields are the fields of local (remote=false) and remote authentication rounds
func vpnIpsecRoundFields(remote bool) func(add bool) []vpnIpsecField {
	var form = (*ipsec.IPsecApi).LocalForm
	if remote {
		form = (*ipsec.IPsecApi).RemoteForm
	}
	return func(add bool) []vpnIpsecField {
		var fields = []vpnIpsecField{
			{Arg: vpnIpsecRequired(add, Arg{Name: "connection", Help: "the connection (uuid or description)", Validate: vpnIpsecNotEmpty,
				Complete: vpnIpsecConnectionNames}), field: "connection", kind: vpnIpsecConnection},
			{Arg: Arg{Name: "round", Type: Int, Validate: ValidateRange(0, 10), Help: "number by which the rounds are sorted, default 0"}, field: "round"},
			{Arg: Arg{Name: "description", Help: "description", Validate: vpnIpsecValidateText}, field: "description"},
			{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the round, but don't use it"}, field: "enabled", kind: vpnIpsecDisabled},
			{Arg: Arg{Name: "auth", Values: []string{"psk", "pubkey", "eap-tls", "eap-mschapv2", "xauth-pam", "eap-radius"},
				Validate: vpnIpsecNotEmpty, Help: "authentication method, default psk (define the key in /vpn/ipsec/pre-shared-key)"}, field: "auth"},
			{Arg: Arg{Name: "id", Help: "IKE identity, e.g. an address, FQDN, email or distinguished name", Validate: vpnIpsecValidateText}, field: "id"},
			{Arg: Arg{Name: "eap-id", Help: "EAP identity (EAP methods only), %any to ask the client", Validate: vpnIpsecValidateText}, field: "eap_id"},
		}
		if remote {
			fields = append(fields, vpnIpsecField{Arg: Arg{Name: "groups", Type: List, Help: "the peer must be member of one of these groups",
				Complete: vpnIpsecCompleteRef(form, "groups", false)}, field: "groups", kind: vpnIpsecRefList})
		}
		fields = append(fields, vpnIpsecField{Arg: Arg{Name: "certs", Type: List, Help: "certificates (descriptions) for certificate authentication",
			Complete: vpnIpsecCompleteRef(form, "certs", false)}, field: "certs", kind: vpnIpsecRefList})
		if remote {
			fields = append(fields, vpnIpsecField{Arg: Arg{Name: "cacerts", Type: List, Help: "certificate authorities to accept, not together with certs",
				Complete: vpnIpsecCompleteRef(form, "cacerts", false)}, field: "cacerts", kind: vpnIpsecRefList})
		}
		return append(fields, vpnIpsecField{Arg: Arg{Name: "pubkeys", Type: List, Help: "key pairs (names) for auth=pubkey",
			Complete: vpnIpsecCompleteRef(form, "pubkeys", false)}, field: "pubkeys", kind: vpnIpsecRefList})
	}
}

func vpnIpsecChildFields(add bool) []vpnIpsecField {
	var actions = func(values ...string) [][2]string {
		var mapping [][2]string
		for _, value := range values {
			mapping = append(mapping, [2]string{strings.ReplaceAll(value, "|", "+"), value})
		}
		return mapping
	}
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "connection", Help: "the connection (uuid or description)", Validate: vpnIpsecNotEmpty,
			Complete: vpnIpsecConnectionNames}), field: "connection", kind: vpnIpsecConnection},
		{Arg: Arg{Name: "description", Help: "description, also the name of the child within its connection", Validate: vpnIpsecValidateText}, field: "description"},
		{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the child, but don't use it"}, field: "enabled", kind: vpnIpsecDisabled},
		{Arg: Arg{Name: "mode", Values: []string{"tunnel", "transport", "pass", "drop"}, Validate: vpnIpsecNotEmpty,
			Help: "IPsec mode, default tunnel; pass and drop install bypass / drop policies"}, field: "mode"},
		{Arg: Arg{Name: "local-ts", Type: List, Help: "local traffic selectors (networks), empty for the tunnel address", Validate: vpnIpsecValidateNetworks}, field: "local_ts", kind: vpnIpsecList},
		{Arg: Arg{Name: "remote-ts", Type: List, Help: "remote traffic selectors (networks), empty for the tunnel address", Validate: vpnIpsecValidateNetworks}, field: "remote_ts", kind: vpnIpsecList},
		{Arg: Arg{Name: "esp-proposals", Type: List, Validate: vpnIpsecNotEmpty, Help: "ESP proposals like aes256gcm16-modp2048, default for the strongSwan defaults",
			Complete: vpnIpsecCompleteRef((*ipsec.IPsecApi).ChildForm, "esp_proposals", true)}, field: "esp_proposals", kind: vpnIpsecRefList, keys: true},
		{Arg: Arg{Name: "sha256-96", Type: Bool, Help: "use the incorrect 96 bit truncation of HMAC-SHA-256 for old peers"}, field: "sha256_96", kind: vpnIpsecFlag},
		vpnIpsecMap(Arg{Name: "start-action", Help: "action after loading: start (default), none, trap, trap+start or route"}, "start_action",
			actions("start", "none", "trap", "trap|start", "route")...),
		vpnIpsecMap(Arg{Name: "close-action", Help: "action when the peer closes the CHILD SA: none (default), trap or start"}, "close_action",
			actions("none", "trap", "start")...),
		vpnIpsecMap(Arg{Name: "dpd-action", Help: "action on a dead peer detection timeout: clear (default), trap or start"}, "dpd_action",
			actions("clear", "trap", "start")...),
		{Arg: Arg{Name: "policies", Type: Bool, Help: "install IPsec policies (default yes, no for route based VTI setups)"}, field: "policies", kind: vpnIpsecFlag},
		{Arg: Arg{Name: "reqid", Type: Int, Help: "fixed reqid (e.g. for a VTI), empty for a dynamic one", Validate: ValidateRange(1, 65535)}, field: "reqid"},
		{Arg: Arg{Name: "rekey-time", Type: Int, Help: "seconds until the CHILD SA is rekeyed, default 3600", Validate: vpnIpsecRekeyTime}, field: "rekey_time"},
		{Arg: Arg{Name: "replay-window", Type: Int, Help: "replay window size, 0 disables replay protection, empty for the default 32",
			Validate: ValidateRange(0, 32)}, field: "replay_window"},
	}
}

func vpnIpsecRekeyTime(value string) error {
	if value == "" {
		return fmt.Errorf("must not be empty, the default is 3600")
	}
	return ValidateRange(0, 500000)(value)
}

// vpnIpsecParentFilter applies the connection= argument of print
func vpnIpsecParentFilter(api *ipsec.IPsecApi, args *Args, records []ipsec.Record) ([]ipsec.Record, error) {
	if !args.Has("connection") {
		return records, nil
	}
	var uuid, err = vpnIpsecConnectionResolve(api, args.String("connection"))
	if err != nil {
		return nil, err
	}
	var filtered []ipsec.Record
	for _, record := range records {
		if record.Value("connection") == uuid {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

var vpnIpsecParentPrintArg = Arg{Name: "connection", Help: "only those of this connection (uuid or description)", Validate: vpnIpsecNotEmpty,
	Complete: vpnIpsecConnectionNames}

// vpnIpsecRoundLabel names a round in messages: round 0 of "conn"
func vpnIpsecRoundLabel(r ipsec.Record) string {
	return fmt.Sprintf("round %s of %q", r.Value("round"), r.Display("connection"))
}

func vpnIpsecSameRound(r ipsec.Record, values map[string]string) bool {
	return r.Value("connection") == values["connection"] && r.Value("round") == values["round"]
}

func vpnIpsecSameChild(r ipsec.Record, values map[string]string) bool {
	return values["description"] != "" && r.Value("connection") == values["connection"] &&
		strings.EqualFold(r.Value("description"), values["description"])
}

func vpnIpsecDescriptionName(r ipsec.Record) []string {
	return []string{r.Value("description")}
}

// vpnIpsecConnectionInUse refuses to remove a connection whose children are used by manual SPD entries
func vpnIpsecConnectionInUse(api *ipsec.IPsecApi, connection ipsec.Record) error {
	var children, err = api.ChildList(connection.Uuid())
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := vpnIpsecChildInUse(api, child); err != nil {
			return err
		}
	}
	return nil
}

// vpnIpsecChildInUse refuses to remove a child manual SPD entries use (OPNsense would keep the dangling uuid)
func vpnIpsecChildInUse(api *ipsec.IPsecApi, child ipsec.Record) error {
	var entries, err = api.ManualSpdList("")
	if err != nil {
		return err
	}
	if users := vpnIpsecUsers(entries, "connection_child", child.Uuid(), vpnIpsecQuoted("description")); len(users) > 0 {
		return fmt.Errorf("the child %s of %q is used by the manual SPD entries %s, change their child= or remove them first",
			vpnIpsecQuoted("description")(child), child.Display("connection"), strings.Join(users, ", "))
	}
	return nil
}

func init() {
	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/connection", help: "IPsec connections: IKE settings of a tunnel or mobile setup (VPN > IPsec > Connections)",
		noun: "connection", itemHelp: "the #, uuid or description of the connection", prefix: "connection.",
		addLong: `Fields not given get the OPNsense defaults (enabled, version=ike, proposals=default). A connection
also needs a local and a remote authentication round (/vpn/ipsec/local, /vpn/ipsec/remote) and children
(/vpn/ipsec/child). The description names the connection: if it exists already, add fails unless replace is
given, then that connection is replaced completely (fields not given are reset to the defaults, its rounds
and children are kept). IPsec itself is switched on with "/vpn/ipsec/service enable".`,
		setLong:    `description= renames the connection.`,
		fields:     vpnIpsecConnectionFields,
		fieldNames: ipsec.ConnectionFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.ConnectionList("") },
		form:       (*ipsec.IPsecApi).ConnectionForm,
		create:     (*ipsec.IPsecApi).ConnectionCreate,
		update:     (*ipsec.IPsecApi).ConnectionUpdate,
		remove:     (*ipsec.IPsecApi).ConnectionRemove,
		setEnabled: (*ipsec.IPsecApi).ConnectionSetEnabled,
		names:      vpnIpsecDescriptionName,
		label:      vpnIpsecQuoted("description"),
		key: func(r ipsec.Record, values map[string]string) bool {
			return strings.EqualFold(r.Value("description"), values["description"])
		},
		keyText: "description",
		columns: []vpnIpsecColumn{
			{"DISABLED", vpnIpsecDisabledText},
			{"VERSION", func(r ipsec.Record) string { return r.Display("version") }},
			{"LOCAL", func(r ipsec.Record) string { return r.Value("local_addrs") }},
			{"REMOTE", func(r ipsec.Record) string { return r.Value("remote_addrs") }},
			{"PROPOSALS", func(r ipsec.Record) string { return r.Value("proposals") }},
			{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
		},
		beforeRemove: vpnIpsecConnectionInUse,
		removeLong:   `Removing a connection also removes its local and remote authentication rounds and its children.`,
	})

	for _, remote := range []bool{false, true} {
		var name, noun, help = "local", "local authentication round", "local authentication rounds of the connections: how this side authenticates"
		var list, form = (*ipsec.IPsecApi).LocalList, (*ipsec.IPsecApi).LocalForm
		var create, update = (*ipsec.IPsecApi).LocalCreate, (*ipsec.IPsecApi).LocalUpdate
		var remove, setEnabled = (*ipsec.IPsecApi).LocalRemove, (*ipsec.IPsecApi).LocalSetEnabled
		var fieldNames = ipsec.LocalFieldNames
		if remote {
			name, noun, help = "remote", "remote authentication round", "remote authentication rounds of the connections: how the peer must authenticate"
			list, form = (*ipsec.IPsecApi).RemoteList, (*ipsec.IPsecApi).RemoteForm
			create, update = (*ipsec.IPsecApi).RemoteCreate, (*ipsec.IPsecApi).RemoteUpdate
			remove, setEnabled = (*ipsec.IPsecApi).RemoteRemove, (*ipsec.IPsecApi).RemoteSetEnabled
			fieldNames = ipsec.RemoteFieldNames
		}
		var listAll = list
		vpnIpsecRegister(&vpnIpsecItems{
			menu: "vpn/ipsec/" + name, help: help + " (VPN > IPsec > Connections)",
			noun: noun, itemHelp: "the #, uuid or description of the round", prefix: name + ".",
			addLong: `connection= names the connection the round belongs to. Fields not given get the OPNsense defaults
(enabled, round=0, auth=psk). A connection and round number name the round: if it exists already, add fails
unless replace is given, then that round is replaced completely.`,
			setLong:    `connection= moves the round to another connection.`,
			fields:     vpnIpsecRoundFields(remote),
			fieldNames: fieldNames,
			list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return listAll(api, "") },
			form:       form, create: create, update: update, remove: remove, setEnabled: setEnabled,
			names:   vpnIpsecDescriptionName,
			label:   vpnIpsecRoundLabel,
			key:     vpnIpsecSameRound,
			keyText: "connection and round",
			columns: []vpnIpsecColumn{
				{"DISABLED", vpnIpsecDisabledText},
				{"CONNECTION", func(r ipsec.Record) string { return r.Display("connection") }},
				{"ROUND", func(r ipsec.Record) string { return r.Value("round") }},
				{"AUTH", func(r ipsec.Record) string { return r.Value("auth") }},
				{"ID", func(r ipsec.Record) string { return r.Value("id") }},
				{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
			},
			printArgs: []Arg{vpnIpsecParentPrintArg},
			filter:    vpnIpsecParentFilter,
		})
	}

	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/child", help: "children of the connections: the CHILD SAs (phase 2) with their traffic selectors (VPN > IPsec > Connections)",
		noun: "child", plural: "children", itemHelp: "the #, uuid or description of the child", prefix: "child.",
		addLong: `connection= names the connection the child belongs to. Fields not given get the OPNsense defaults
(enabled, mode=tunnel, start-action=start, esp-proposals=default, rekey-time=3600). A connection and description
name the child: if it exists already, add fails unless replace is given, then that child is replaced completely.`,
		setLong:    `connection= moves the child to another connection.`,
		fields:     vpnIpsecChildFields,
		fieldNames: ipsec.ChildFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.ChildList("") },
		form:       (*ipsec.IPsecApi).ChildForm,
		create:     (*ipsec.IPsecApi).ChildCreate,
		update:     (*ipsec.IPsecApi).ChildUpdate,
		remove:     (*ipsec.IPsecApi).ChildRemove,
		setEnabled: (*ipsec.IPsecApi).ChildSetEnabled,
		names:      vpnIpsecDescriptionName,
		label: func(r ipsec.Record) string {
			return fmt.Sprintf("%s of %q", vpnIpsecQuoted("description")(r), r.Display("connection"))
		},
		key:     vpnIpsecSameChild,
		keyText: "connection and description",
		columns: []vpnIpsecColumn{
			{"DISABLED", vpnIpsecDisabledText},
			{"CONNECTION", func(r ipsec.Record) string { return r.Display("connection") }},
			{"MODE", func(r ipsec.Record) string { return r.Value("mode") }},
			{"LOCAL-TS", func(r ipsec.Record) string { return r.Value("local_ts") }},
			{"REMOTE-TS", func(r ipsec.Record) string { return r.Value("remote_ts") }},
			{"REQID", func(r ipsec.Record) string { return r.Value("reqid") }},
			{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
		},
		printArgs:    []Arg{vpnIpsecParentPrintArg},
		filter:       vpnIpsecParentFilter,
		beforeRemove: vpnIpsecChildInUse,
	})
}
