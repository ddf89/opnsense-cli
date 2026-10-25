package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Interfaces > Diagnostics > Netstat (api/diagnostics/interface/get_*_statistics): netstat --libxo json output of
// the firewall. bpf: netstat -B, interface: netstat -i -b -d (one entry per interface address), protocol: netstat -s,
// socket: netstat -a -x merged with sockstat (process of each socket), memory: netstat -m (mbufs), netisr: netstat -Q

// NetstatValue is one statistic of a nested netstat object, Name the dotted path below the section (e.g.
// "syncache.entries-added"), Value as sent (number or text)
type NetstatValue struct {
	Name  string
	Value string
}

// NetstatSection are the statistics of one protocol (tcp, udp, ip, ...) or of the mbufs, in netstat order
type NetstatSection struct {
	Name   string
	Values []NetstatValue
}

// NetstatInterface are the counters of one interface address (netstat -i), Label the key OPNsense uses, e.g.
// "[LAN] (vtnet0) / 192.168.1.1"
type NetstatInterface struct {
	Label           string     `json:"-"`
	Name            string     `json:"name"` // device
	Flags           string     `json:"flags"`
	Mtu             ToolsCount `json:"mtu"`
	Network         string     `json:"network"` // e.g. 192.168.1.0/24 or <Link#1>
	Address         string     `json:"address"`
	ReceivedPackets ToolsCount `json:"received-packets"`
	ReceivedErrors  ToolsCount `json:"received-errors"`
	DroppedPackets  ToolsCount `json:"dropped-packets"`
	ReceivedBytes   ToolsCount `json:"received-bytes"`
	SentPackets     ToolsCount `json:"sent-packets"`
	SendErrors      ToolsCount `json:"send-errors"`
	SentBytes       ToolsCount `json:"sent-bytes"`
	Collisions      ToolsCount `json:"collisions"`
}

// NetstatEndpoint is the local or remote end of an internet socket, "*" for any
type NetstatEndpoint struct {
	Address string    `json:"address"`
	Port    ToolsText `json:"port"`
}

// String renders the endpoint as address:port, IPv6 addresses in brackets
func (e NetstatEndpoint) String() string {
	if strings.Contains(e.Address, ":") {
		return "[" + e.Address + "]:" + string(e.Port)
	}
	return e.Address + ":" + string(e.Port)
}

// NetstatInternetSocket is a TCP or UDP socket with the process holding it (when sockstat knew it)
type NetstatInternetSocket struct {
	Protocol            string          `json:"protocol"` // tcp4, udp6, ...
	Local               NetstatEndpoint `json:"local"`
	Remote              NetstatEndpoint `json:"remote"`
	ReceiveBytesWaiting ToolsCount      `json:"receive-bytes-waiting"`
	SendBytesWaiting    ToolsCount      `json:"send-bytes-waiting"`
	User                ToolsText       `json:"user"`
	Command             ToolsText       `json:"command"`
	Pid                 ToolsText       `json:"pid"`
	Fd                  ToolsText       `json:"fd"`
}

// NetstatUnixSocket is a unix domain socket
type NetstatUnixSocket struct {
	Address             string     `json:"address"`
	Type                string     `json:"type"` // stream, dgram, seqpac
	Path                ToolsText  `json:"path"`
	ReceiveBytesWaiting ToolsCount `json:"receive-bytes-waiting"`
	SendBytesWaiting    ToolsCount `json:"send-bytes-waiting"`
	Connection          ToolsText  `json:"connection"`
}

// NetstatSockets are the sockets of the firewall, sorted (internet by protocol and local end, unix by path)
type NetstatSockets struct {
	Internet []NetstatInternetSocket
	Unix     []NetstatUnixSocket
}

// NetstatBpfPeer is a bpf(4) listener (tcpdump, dhclient, filterlog, ...)
type NetstatBpfPeer struct {
	Pid               ToolsText  `json:"pid"`
	Process           string     `json:"process"`
	Interface         string     `json:"interface-name"`
	Direction         string     `json:"direction"`
	Promiscuous       bool       `json:"promiscuous"`
	Immediate         bool       `json:"immediate"`
	Locked            bool       `json:"locked"`
	HeaderComplete    bool       `json:"header-complete"`
	ReceivedPackets   ToolsCount `json:"received-packets"`
	DroppedPackets    ToolsCount `json:"dropped-packets"`
	FilterPackets     ToolsCount `json:"filter-packets"`
	StoreBufferLength ToolsCount `json:"store-buffer-length"`
	HoldBufferLength  ToolsCount `json:"hold-buffer-length"`
}

// NetstatNetisrProtocol is a protocol registered with netisr(9)
type NetstatNetisrProtocol struct {
	Name       string     `json:"name"`
	Protocol   ToolsCount `json:"protocol"`
	QueueLimit ToolsCount `json:"queue-limit"`
	PolicyType string     `json:"policy-type"`
	Policy     string     `json:"policy"`
	Flags      string     `json:"flags"`
}

// NetstatNetisrWork are the counters of one protocol on one netisr workstream
type NetstatNetisrWork struct {
	Workstream       ToolsCount `json:"workstream"`
	Cpu              ToolsCount `json:"cpu"`
	Name             string     `json:"name"`
	Length           ToolsCount `json:"length"`
	Watermark        ToolsCount `json:"watermark"`
	Dispatched       ToolsCount `json:"dispatched"`
	HybridDispatched ToolsCount `json:"hybrid-dispatched"`
	QueueDrops       ToolsCount `json:"queue-drops"`
	Queued           ToolsCount `json:"queued"`
	Handled          ToolsCount `json:"handled"`
}

// NetstatNetisr are the netisr(9) protocols and the work of all workstreams
type NetstatNetisr struct {
	Protocols []NetstatNetisrProtocol
	Work      []NetstatNetisrWork
}

func (opn *DiagnosticsApi) netstatGet(method string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("interface", method), nil, &raw); err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(raw); bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]")) {
		return nil, fmt.Errorf("%s: OPNsense returned no statistics", method)
	}
	return raw, nil
}

// NetstatInterfaces returns the counters per interface address, sorted by device and label. Raw is the answer
func (opn *DiagnosticsApi) NetstatInterfaces() ([]NetstatInterface, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_interface_statistics")
	if err != nil {
		return nil, nil, err
	}
	var container struct {
		Statistics json.RawMessage `json:"statistics"`
	}
	var byLabel map[string]NetstatInterface
	err = json.Unmarshal(raw, &container)
	if err == nil {
		err = trafficDecodeObject(container.Statistics, &byLabel)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected interface statistics: %w", err)
	}
	var result = make([]NetstatInterface, 0, len(byLabel))
	for label, entry := range byLabel {
		entry.Label = label
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Label < result[j].Label
	})
	return result, raw, nil
}

// NetstatSocketList returns the internet and unix domain sockets. Raw is the answer
func (opn *DiagnosticsApi) NetstatSocketList() (NetstatSockets, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_socket_statistics")
	if err != nil {
		return NetstatSockets{}, nil, err
	}
	var container struct {
		Statistics struct {
			Internet json.RawMessage `json:"Active Internet connections"`
			Unix     json.RawMessage `json:"Active UNIX domain sockets"`
		} `json:"statistics"`
	}
	var internet map[string]NetstatInternetSocket
	var unix map[string]NetstatUnixSocket
	err = json.Unmarshal(raw, &container)
	if err == nil {
		err = trafficDecodeObject(container.Statistics.Internet, &internet)
	}
	if err == nil {
		err = trafficDecodeObject(container.Statistics.Unix, &unix)
	}
	if err != nil {
		return NetstatSockets{}, nil, fmt.Errorf("unexpected socket statistics: %w", err)
	}

	var result NetstatSockets
	for _, socket := range internet {
		result.Internet = append(result.Internet, socket)
	}
	sort.Slice(result.Internet, func(i, j int) bool {
		var a, b = result.Internet[i], result.Internet[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Local.String() != b.Local.String() {
			return a.Local.String() < b.Local.String()
		}
		return a.Remote.String() < b.Remote.String()
	})
	for _, socket := range unix {
		result.Unix = append(result.Unix, socket)
	}
	sort.Slice(result.Unix, func(i, j int) bool {
		var a, b = result.Unix[i], result.Unix[j]
		if a.Path != b.Path {
			return a.Path > b.Path // sockets with a path first
		}
		return a.Address < b.Address
	})
	return result, raw, nil
}

// NetstatProtocols returns the statistics of every protocol (netstat -s) in netstat order. Raw is the answer
func (opn *DiagnosticsApi) NetstatProtocols() ([]NetstatSection, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_protocol_statistics")
	if err != nil {
		return nil, nil, err
	}
	var container struct {
		Statistics json.RawMessage `json:"statistics"`
	}
	if err := json.Unmarshal(raw, &container); err != nil || container.Statistics == nil {
		return nil, nil, fmt.Errorf("unexpected protocol statistics: %v", err)
	}
	sections, err := netstatSections(container.Statistics)
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected protocol statistics: %w", err)
	}
	return sections, raw, nil
}

// NetstatMemory returns the mbuf statistics (netstat -m) in netstat order. Raw is the answer
func (opn *DiagnosticsApi) NetstatMemory() (NetstatSection, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_memory_statistics")
	if err != nil {
		return NetstatSection{}, nil, err
	}
	sections, err := netstatSections(raw)
	if err != nil || len(sections) == 0 {
		return NetstatSection{}, nil, fmt.Errorf("unexpected memory statistics: %v", err)
	}
	return sections[0], raw, nil
}

// NetstatBpf returns the bpf(4) peers. Raw is the answer
func (opn *DiagnosticsApi) NetstatBpf() ([]NetstatBpfPeer, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_bpf_statistics")
	if err != nil {
		return nil, nil, err
	}
	var container struct {
		Statistics struct {
			Entries []NetstatBpfPeer `json:"bpf-entry"`
		} `json:"bpf-statistics"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return nil, nil, fmt.Errorf("unexpected bpf statistics: %w", err)
	}
	return container.Statistics.Entries, raw, nil
}

// NetstatNetisrGet returns the netisr(9) protocols and workstream counters. Raw is the answer
func (opn *DiagnosticsApi) NetstatNetisrGet() (NetstatNetisr, json.RawMessage, error) {
	var raw, err = opn.netstatGet("get_netisr_statistics")
	if err != nil {
		return NetstatNetisr{}, nil, err
	}
	var container struct {
		Netisr struct {
			Protocols   []NetstatNetisrProtocol `json:"protocol"`
			Workstreams []struct {
				Work []NetstatNetisrWork `json:"work"`
			} `json:"workstream"`
		} `json:"netisr"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return NetstatNetisr{}, nil, fmt.Errorf("unexpected netisr statistics: %w", err)
	}
	var result = NetstatNetisr{Protocols: container.Netisr.Protocols}
	for _, workstream := range container.Netisr.Workstreams {
		result.Work = append(result.Work, workstream.Work...)
	}
	return result, raw, nil
}

// netstatSections flattens a JSON object of objects ({"tcp":{"sent-packets":1,"syncache":{...}}}) into sections
// keeping the key order of the answer. Lists are kept as JSON text
func netstatSections(raw json.RawMessage) ([]NetstatSection, error) {
	var decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := netstatExpectDelim(decoder, '{'); err != nil {
		return nil, err
	}
	var sections []NetstatSection
	for decoder.More() {
		var name, err = netstatKey(decoder)
		if err != nil {
			return nil, err
		}
		var section = NetstatSection{Name: name}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := netstatFlatten(value, "", &section.Values); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		sections = append(sections, section)
	}
	return sections, netstatExpectDelim(decoder, '}')
}

func netstatFlatten(raw json.RawMessage, prefix string, values *[]NetstatValue) error {
	var trimmed = bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		var text = string(trimmed)
		if len(trimmed) > 0 && trimmed[0] == '"' {
			_ = json.Unmarshal(trimmed, &text)
		}
		*values = append(*values, NetstatValue{Name: prefix, Value: text})
		return nil
	}
	var decoder = json.NewDecoder(bytes.NewReader(trimmed))
	if err := netstatExpectDelim(decoder, '{'); err != nil {
		return err
	}
	for decoder.More() {
		var key, err = netstatKey(decoder)
		if err != nil {
			return err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		var name = key
		if prefix != "" {
			name = prefix + "." + key
		}
		if err := netstatFlatten(value, name, values); err != nil {
			return err
		}
	}
	return netstatExpectDelim(decoder, '}')
}

func netstatKey(decoder *json.Decoder) (string, error) {
	var token, err = decoder.Token()
	if err != nil {
		return "", err
	}
	var key, isString = token.(string)
	if !isString {
		return "", fmt.Errorf("expected an object key, got %v", token)
	}
	return key, nil
}

func netstatExpectDelim(decoder *json.Decoder, delim json.Delim) error {
	var token, err = decoder.Token()
	if err == io.EOF {
		return fmt.Errorf("unexpected end of JSON, expected %v", delim)
	}
	if err != nil {
		return err
	}
	if token != delim {
		return fmt.Errorf("expected %v, got %v", delim, token)
	}
	return nil
}
