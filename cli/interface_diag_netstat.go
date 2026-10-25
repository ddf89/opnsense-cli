package cli

import (
	"opnsense-cli/opnsense/api/diagnostics"
	"strconv"
	"strings"
)

// /interface/netstat: Interfaces > Diagnostics > Netstat (api/diagnostics/interface/get_*_statistics), the
// netstat output of the firewall

func init() {
	var menu = Root.Menu("interface/netstat")
	menu.Help = "network statistics of the firewall (netstat)"
	var jsonArg = Arg{Name: "json", Type: Bool, Help: "print the raw answer as one JSON object"}
	menu.Add(
		&Command{
			Name: "interfaces",
			Help: "packet and byte counters per interface address (netstat -i)",
			Args: []Arg{
				{Name: "interface", Type: List, Help: "only these interfaces (description like LAN, or device like vtnet0)"},
				jsonArg,
			},
			Run: interfaceDiagNetstatInterfaces,
		},
		&Command{
			Name: "sockets",
			Help: "the open internet sockets with their processes (netstat -a, sockstat)",
			Args: []Arg{
				{Name: "protocol", Values: []string{"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"}, Help: "only sockets of this protocol"},
				{Name: "listening", Type: Bool, Help: "only sockets without remote end (listening TCP, unconnected UDP)"},
				{Name: "unix", Type: Bool, Help: "list the unix domain sockets instead"},
				jsonArg,
			},
			Run: interfaceDiagNetstatSockets,
		},
		&Command{
			Name: "protocols",
			Help: "the statistics of every network protocol (netstat -s)",
			Args: []Arg{
				{Name: "protocol", Type: List, Help: "only these protocols (tcp, udp, ip, icmp, ip6, icmp6, arp, carp, pfsync, ...)"},
				{Name: "zero", Type: Bool, Help: "also show the counters that are 0"},
				jsonArg,
			},
			Run: interfaceDiagNetstatProtocols,
		},
		&Command{
			Name: "bpf",
			Help: "the bpf(4) listeners like tcpdump and dhclient (netstat -B)",
			Args: []Arg{jsonArg},
			Run:  interfaceDiagNetstatBpf,
		},
		&Command{
			Name: "memory",
			Help: "the mbuf statistics of the network stack (netstat -m)",
			Args: []Arg{jsonArg},
			Run:  interfaceDiagNetstatMemory,
		},
		&Command{
			Name: "netisr",
			Help: "the netisr(9) protocols and queues (netstat -Q)",
			Args: []Arg{jsonArg},
			Run:  interfaceDiagNetstatNetisr,
		},
	)
}

func interfaceDiagCount(count diagnostics.ToolsCount) string {
	return strconv.FormatInt(int64(count), 10)
}

func interfaceDiagNetstatInterfaces(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	entries, raw, err := api.NetstatInterfaces()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	var rows [][]string
	for _, entry := range entries {
		// labels look like "[LAN] (vtnet0) / 192.168.1.1", or "[vtnet9] / address" without description
		var description = ""
		if strings.HasPrefix(entry.Label, "[") && strings.Contains(entry.Label, "] (") {
			description = entry.Label[1:strings.Index(entry.Label, "]")]
		}
		if !interfaceDiagMatches(args.List("interface"), "", entry.Name, description) {
			continue
		}
		var mtu = ""
		if entry.Mtu != 0 {
			mtu = interfaceDiagCount(entry.Mtu)
		}
		rows = append(rows, []string{
			interfaceDiagInterface(entry.Name, description), entry.Network, entry.Address, mtu,
			interfaceDiagCount(entry.ReceivedPackets), interfaceDiagCount(entry.ReceivedErrors), interfaceDiagCount(entry.DroppedPackets),
			interfaceDiagCount(entry.ReceivedBytes), interfaceDiagCount(entry.SentPackets), interfaceDiagCount(entry.SendErrors),
			interfaceDiagCount(entry.SentBytes), interfaceDiagCount(entry.Collisions),
		})
	}
	c.Table([]string{"INTERFACE", "NETWORK", "ADDRESS", "MTU", "IN-PKTS", "IN-ERRS", "IN-DROPS", "IN-BYTES", "OUT-PKTS", "OUT-ERRS", "OUT-BYTES", "COLLISIONS"}, rows)
	return nil
}

func interfaceDiagNetstatSockets(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	sockets, raw, err := api.NetstatSocketList()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	if args.Bool("unix") {
		var rows [][]string
		for _, socket := range sockets.Unix {
			rows = append(rows, []string{socket.Address, socket.Type, string(socket.Path),
				interfaceDiagCount(socket.ReceiveBytesWaiting), interfaceDiagCount(socket.SendBytesWaiting)})
		}
		c.Table([]string{"ADDRESS", "TYPE", "PATH", "RECV-Q", "SEND-Q"}, rows)
		return nil
	}
	var protocol = strings.ToLower(args.String("protocol"))
	var rows [][]string
	for _, socket := range sockets.Internet {
		if protocol != "" && !strings.HasPrefix(socket.Protocol, protocol) {
			continue
		}
		if args.Bool("listening") && socket.Remote.Address != "*" {
			continue
		}
		rows = append(rows, []string{socket.Protocol, socket.Local.String(), socket.Remote.String(),
			interfaceDiagCount(socket.ReceiveBytesWaiting), interfaceDiagCount(socket.SendBytesWaiting),
			string(socket.User), string(socket.Command), string(socket.Pid)})
	}
	c.Table([]string{"PROTO", "LOCAL", "REMOTE", "RECV-Q", "SEND-Q", "USER", "COMMAND", "PID"}, rows)
	return nil
}

func interfaceDiagNetstatProtocols(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	sections, raw, err := api.NetstatProtocols()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	var wanted = args.List("protocol")
	var printed = 0
	for _, section := range sections {
		if len(wanted) > 0 && !containsFold(wanted, section.Name) {
			continue
		}
		var fields [][2]string
		for _, value := range section.Values {
			if args.Bool("zero") || (value.Value != "0" && value.Value != "[]" && value.Value != "{}") {
				fields = append(fields, [2]string{"  " + value.Name, value.Value})
			}
		}
		if len(fields) == 0 && len(wanted) == 0 {
			continue // nothing counted
		}
		if printed > 0 {
			c.Println()
		}
		printed++
		c.Printf("%s:\n", section.Name)
		c.Fields(fields)
	}
	if len(wanted) > 0 && printed == 0 {
		var names = make([]string, 0, len(sections))
		for _, section := range sections {
			names = append(names, section.Name)
		}
		c.Infof("no statistics for %s, OPNsense has: %s", strings.Join(wanted, ", "), strings.Join(names, ", "))
	}
	return nil
}

func interfaceDiagNetstatBpf(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	peers, raw, err := api.NetstatBpf()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	var rows [][]string
	for _, peer := range peers {
		var flags []string
		for _, flag := range []struct {
			set  bool
			name string
		}{{peer.Promiscuous, "promiscuous"}, {peer.Immediate, "immediate"}, {peer.Locked, "locked"}, {peer.HeaderComplete, "header-complete"}} {
			if flag.set {
				flags = append(flags, flag.name)
			}
		}
		rows = append(rows, []string{string(peer.Pid), peer.Process, peer.Interface, peer.Direction, strings.Join(flags, ","),
			interfaceDiagCount(peer.ReceivedPackets), interfaceDiagCount(peer.DroppedPackets), interfaceDiagCount(peer.FilterPackets)})
	}
	c.Table([]string{"PID", "PROCESS", "INTERFACE", "DIRECTION", "FLAGS", "RECEIVED", "DROPPED", "MATCHED"}, rows)
	return nil
}

func interfaceDiagNetstatMemory(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	section, raw, err := api.NetstatMemory()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	var fields = make([][2]string, 0, len(section.Values))
	for _, value := range section.Values {
		fields = append(fields, [2]string{value.Name, value.Value})
	}
	c.Fields(fields)
	return nil
}

func interfaceDiagNetstatNetisr(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	netisr, raw, err := api.NetstatNetisrGet()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(raw)
	}
	var protocols [][]string
	for _, protocol := range netisr.Protocols {
		protocols = append(protocols, []string{protocol.Name, interfaceDiagCount(protocol.Protocol), interfaceDiagCount(protocol.QueueLimit),
			protocol.PolicyType, protocol.Policy, protocol.Flags})
	}
	c.Table([]string{"PROTOCOL", "ID", "QUEUE-LIMIT", "POLICY-TYPE", "POLICY", "FLAGS"}, protocols)
	c.Println()
	var work [][]string
	for _, w := range netisr.Work {
		work = append(work, []string{interfaceDiagCount(w.Workstream), interfaceDiagCount(w.Cpu), w.Name, interfaceDiagCount(w.Length),
			interfaceDiagCount(w.Watermark), interfaceDiagCount(w.Dispatched), interfaceDiagCount(w.HybridDispatched),
			interfaceDiagCount(w.Queued), interfaceDiagCount(w.Handled), interfaceDiagCount(w.QueueDrops)})
	}
	c.Table([]string{"WORKSTREAM", "CPU", "PROTOCOL", "LENGTH", "WATERMARK", "DISPATCHED", "HYBRID", "QUEUED", "HANDLED", "DROPS"}, work)
	return nil
}
