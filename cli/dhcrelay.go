package cli

import (
	"errors"
	"net/netip"

	"opnsense-cli/opnsense/api/dhcp"
)

// /dhcrelay: the DHCP relay (Services > DHCRelay): /dhcrelay/destination (named DHCP server lists),
// /dhcrelay/relay (interface -> destination) and /dhcrelay/service. Changes are only saved until
// "/dhcrelay/service reconfigure"

const dhcrelayApplyHint = `Changes are only saved, run "/dhcrelay/service reconfigure" to apply them.`

func init() {
	Root.Menu("dhcrelay").Help = "DHCP relay: forward DHCP requests of an interface to other DHCP servers (Services > DHCRelay)"

	var destinations = &keaItems{
		path: "dhcrelay/destination", help: "relay destinations: named lists of DHCP servers (Services > DHCRelay > Destinations)",
		noun: "destination", itemHelp: "the #, uuid or name of the destination",
		addLong: `The servers of a destination are all IPv4 or all IPv6 addresses; an IPv4 destination serves DHCPv4
relays, an IPv6 destination DHCPv6 relays.`,
		hint:    dhcrelayApplyHint,
		records: keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.RelayDestinations() }),
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "name", Help: "name of the destination (unique)", Validate: keaValidateText}), api: "name"},
				{Arg: keaRequired(add, Arg{Name: "servers", Type: List, Help: "addresses of the DHCP servers, all IPv4 or all IPv6", Validate: dhcrelayValidateServers}),
					api: "server", kind: keaList},
			}
		},
		columns: []keaColumn{keaColumnOf("NAME", "name"), keaColumnOf("SERVERS", "server")},
		names:   func(row dhcp.Row) []string { return []string{row["name"]} },
		key:     "name",
		same:    func(row dhcp.Row, fields dhcp.Fields) bool { return row["name"] == fields["name"] },
	}
	keaRegisterItems(destinations)

	var destinationRef = keaRefTo(destinations)
	keaRegisterItems(&keaItems{
		path: "dhcrelay/relay", help: "relays: the interfaces whose DHCP requests are forwarded (Services > DHCRelay > Relays)",
		noun: "relay", itemHelp: "the #, uuid or interface of the relay",
		addLong: `An interface can have one relay with an IPv4 and one with an IPv6 destination. Don't relay on an interface
a DHCP server of the firewall serves.`,
		hint:    dhcrelayApplyHint,
		records: keaRecordsOf(func(api *dhcp.DhcpApi) keaRecords { return api.Relays() }),
		fields: func(add bool) []keaField {
			return []keaField{
				{Arg: keaRequired(add, Arg{Name: "interface", Help: "the interface to listen on (key like lan)"}), api: "interface", options: true},
				{Arg: keaRequired(add, Arg{Name: "destination", Help: "the destination (its name or uuid)", Complete: keaRefNames(destinationRef)}),
					api: "destination", kind: keaRef, ref: destinationRef},
				{Arg: Arg{Name: "disabled", Type: Bool, Help: "keep the relay, but don't run it"}, api: "enabled", kind: keaDisabled},
				{Arg: Arg{Name: "agent-info", Type: Bool, Help: "add the relay agent information option (82)"}, api: "agent_info", kind: keaFlag},
				{Arg: Arg{Name: "carp-depend-on", Help: "only run while this CARP virtual IP is master, empty for always"}, api: "carp_depend_on", options: true},
			}
		},
		columns: []keaColumn{keaColumnOf("INTERFACE", "interface"), keaRefColumn("DESTINATION", "destination"),
			{header: "AGENT-INFO", value: func(row dhcp.Row) string { return YesNo(row["agent_info"]) }},
			{header: "STATUS", value: dhcrelayStatusText}},
		names: func(row dhcp.Row) []string { return []string{row["interface"]} },
		key:   "interface and destination",
		same: func(row dhcp.Row, fields dhcp.Fields) bool {
			return row["interface"] == fields["interface"] && row["destination"] == fields["destination"]
		},
	})

	var menu = Root.Menu("dhcrelay/service")
	menu.Help = "the DHCP relay service"
	menu.Add(&Command{Name: "reconfigure", Aliases: []string{"apply"},
		Help: "apply the saved relays: (re)start the enabled ones, stop the others",
		Run: func(c *Context, _ *Args) error {
			var dhcpApi, err = keaApi(c)
			if err != nil {
				return err
			}
			return dhcpApi.RelayReconfigure()
		}})
}

// dhcrelayStatusText names the status color of search_relay
func dhcrelayStatusText(row dhcp.Row) string {
	switch row["status"] {
	case "green":
		return "running"
	case "red":
		return "stopped"
	case "grey", "":
		return "disabled"
	}
	return row["status"]
}

// dhcrelayValidateServers accepts addresses of one family
func dhcrelayValidateServers(value string) error {
	if err := keaValidateAddresses(0)(value); err != nil {
		return err
	}
	var families = map[bool]bool{}
	for _, element := range splitList(value) {
		families[netip.MustParseAddr(element).Is4()] = true
	}
	if len(families) > 1 {
		return errors.New("must be all IPv4 or all IPv6 addresses, not both")
	}
	return nil
}
