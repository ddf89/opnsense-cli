package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The one-shot tools of Interfaces > Diagnostics: traceroute, port probe and DNS lookup. Their set endpoint
// validates the settings, runs the tool synchronously on the firewall and answers its output in "response"

// --- traceroute (api/diagnostics/traceroute/set)

// TracerouteOptions configure a traceroute. Empty values use the defaults
type TracerouteOptions struct {
	Hostname      string // host name or address, required
	Family        string // "inet" (IPv4, default) or "inet6"
	Protocol      string // "udp" (default) or "icmp"
	SourceAddress string
}

// TracerouteHop is one line of the traceroute output (one probe per hop, 2s wait). Hops without answer
// ("*") are left out by OPNsense
type TracerouteHop struct {
	TTL     string `json:"ttl"`
	AS      string `json:"AS"` // e.g. AS0
	Host    string `json:"host"`
	Address string `json:"address"`
	Probes  string `json:"probes"` // e.g. "0.153 ms"
}

// TracerouteResult is the traceroute answer: the hops, the first line of traceroute ("traceroute to ...") or
// other stderr output as Notice, and Error "timeout reached" when traceroute did not finish within 20 seconds
type TracerouteResult struct {
	Hops   []TracerouteHop `json:"rows"`
	Notice string          `json:"notice"`
	Error  string          `json:"error"`
	Raw    json.RawMessage `json:"-"`
}

// Traceroute runs a traceroute on the firewall, it takes up to 20 seconds
func (opn *DiagnosticsApi) Traceroute(options TracerouteOptions) (TracerouteResult, error) {
	var family, protocol = options.Family, options.Protocol
	if family == "" {
		family = "inet"
	}
	if protocol == "" {
		protocol = "udp"
	}
	var answer, err = opn.toolsSet("traceroute", "traceroute", map[string]string{
		"hostname": options.Hostname, "ipproto": family, "protocol": protocol, "source_address": options.SourceAddress,
	})
	if err != nil {
		return TracerouteResult{}, err
	}
	var result TracerouteResult
	if err := toolsDecodeResponse("traceroute", answer.Response, &result); err != nil {
		return TracerouteResult{}, err
	}
	result.Raw = answer.Response
	return result, nil
}

// toolsDecodeResponse decodes the "response" of a tool, which is null when the tool printed no JSON
func toolsDecodeResponse(what string, response json.RawMessage, out any) error {
	var trimmed = bytes.TrimSpace(response)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte(`""`)) {
		return fmt.Errorf("%s: OPNsense returned no result", what)
	}
	if bytes.Equal(trimmed, []byte("[]")) {
		return nil
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		return fmt.Errorf("unexpected %s result %s: %w", what, trimmed, err)
	}
	return nil
}

// --- port probe (api/diagnostics/portprobe/set)

// PortProbeOptions configure a TCP connection test (nc -z, 10 seconds timeout). Empty values use the defaults
type PortProbeOptions struct {
	Hostname      string // host name or address, required
	Port          int    // required
	Family        string // "inet" (IPv4, default) or "inet6"
	SourceAddress string
	SourcePort    int
	// ShowText reads what the remote end sends after connecting (Payload) instead of only connecting
	ShowText bool
}

// PortProbeResult is what nc reported: Message is its stderr ("Connection to ... succeeded!" or
// "nc: connect to ... failed: Connection refused"), Payload what the remote end sent (with ShowText)
type PortProbeResult struct {
	Message string          `json:"message"`
	Payload string          `json:"payload"`
	Raw     json.RawMessage `json:"-"`
}

// Succeeded tells whether the connection was established
func (r PortProbeResult) Succeeded() bool {
	return strings.Contains(r.Message, "succeeded")
}

// PortProbe tests whether a TCP connection from the firewall to host and port can be established
func (opn *DiagnosticsApi) PortProbe(options PortProbeOptions) (PortProbeResult, error) {
	var family = options.Family
	if family == "" {
		family = "inet"
	}
	var values = map[string]string{
		"hostname": options.Hostname, "port": "", "ipproto": family, "source_address": options.SourceAddress,
		"source_port": "", "showtext": toolsFlag(options.ShowText),
	}
	if options.Port != 0 {
		values["port"] = strconv.Itoa(options.Port)
	}
	if options.SourcePort != 0 {
		values["source_port"] = strconv.Itoa(options.SourcePort)
	}
	var answer, err = opn.toolsSet("portprobe", "portprobe", values)
	if err != nil {
		return PortProbeResult{}, err
	}
	var result PortProbeResult
	if err := toolsDecodeResponse("port probe", answer.Response, &result); err != nil {
		return PortProbeResult{}, err
	}
	result.Raw = answer.Response
	return result, nil
}

// --- DNS lookup (api/diagnostics/dns_diagnostics/set)

// DnsLookupRecords are the answers of one record type: zone file lines like "localhost.\t10800\tIN\tA\t127.0.0.1"
type DnsLookupRecords struct {
	Answers   []string `json:"answers"`
	QueryTime string   `json:"query_time"` // e.g. "0 msec"
	Server    string   `json:"server"`
}

// DnsLookupAnswer is one parsed answer line
type DnsLookupAnswer struct {
	Type  string
	Name  string
	TTL   string
	Class string
	Data  string
}

// DnsLookupResult is the answer of a DNS lookup: for a host name the A, AAAA, MX and TXT records that exist
// (drill), for an address the PTR records (host -v). Error is the error message of the resolver tool
type DnsLookupResult struct {
	Records map[string]DnsLookupRecords
	Error   string
	Raw     json.RawMessage
}

// DnsLookupTypes is the order record types are shown in
var DnsLookupTypes = []string{"A", "AAAA", "MX", "TXT", "PTR"}

// Types returns the record types of the result, in DnsLookupTypes order, others after them sorted
func (r DnsLookupResult) Types() []string {
	var types []string
	for _, known := range DnsLookupTypes {
		if _, found := r.Records[known]; found {
			types = append(types, known)
		}
	}
	var others []string
	for name := range r.Records {
		if !slices.Contains(DnsLookupTypes, name) {
			others = append(others, name)
		}
	}
	sort.Strings(others)
	return append(types, others...)
}

// Answers returns all answers parsed, in Types order
func (r DnsLookupResult) Answers() []DnsLookupAnswer {
	var answers []DnsLookupAnswer
	for _, recordType := range r.Types() {
		for _, line := range r.Records[recordType].Answers {
			answers = append(answers, DnsLookupParseAnswer(recordType, line))
		}
	}
	return answers
}

// DnsLookupParseAnswer splits a zone file line "name ttl class type data" (data may contain blanks, e.g. TXT
// or MX). Lines that do not have this form are returned as Data
func DnsLookupParseAnswer(recordType string, line string) DnsLookupAnswer {
	var fields = strings.Fields(line)
	if len(fields) < 5 || !strings.EqualFold(fields[2], "IN") {
		return DnsLookupAnswer{Type: recordType, Data: strings.TrimSpace(line)}
	}
	var rest = line
	for i := 0; i < 4; i++ {
		rest = strings.TrimLeft(rest, " \t")
		rest = rest[strings.IndexAny(rest, " \t")+1:]
	}
	return DnsLookupAnswer{Type: fields[3], Name: fields[0], TTL: fields[1], Class: fields[2], Data: strings.TrimSpace(rest)}
}

// DnsLookup resolves hostname (A, AAAA, MX, TXT) or, for an address, its PTR records on the firewall, asking server
// ("" for the resolvers of the firewall)
func (opn *DiagnosticsApi) DnsLookup(hostname string, server string) (DnsLookupResult, error) {
	var answer, err = opn.toolsSet("dns_diagnostics", "dns", map[string]string{"hostname": hostname, "server": server})
	if err != nil {
		return DnsLookupResult{}, err
	}
	var decoded map[string]json.RawMessage
	if err := toolsDecodeResponse("DNS lookup", answer.Response, &decoded); err != nil {
		return DnsLookupResult{}, err
	}
	var result = DnsLookupResult{Records: map[string]DnsLookupRecords{}, Raw: answer.Response}
	for key, value := range decoded {
		if key == "error_message" {
			if err := json.Unmarshal(value, &result.Error); err != nil {
				return DnsLookupResult{}, fmt.Errorf("unexpected DNS lookup error message %s", value)
			}
			continue
		}
		var records DnsLookupRecords
		var fields struct {
			Answers   []string  `json:"answers"`
			QueryTime ToolsText `json:"query_time"`
			Server    ToolsText `json:"server"`
		}
		if err := json.Unmarshal(value, &fields); err != nil {
			return DnsLookupResult{}, fmt.Errorf("unexpected DNS lookup records %s: %w", value, err)
		}
		records.Answers, records.QueryTime, records.Server = fields.Answers, string(fields.QueryTime), string(fields.Server)
		result.Records[key] = records
	}
	return result, nil
}
