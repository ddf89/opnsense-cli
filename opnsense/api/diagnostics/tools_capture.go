package diagnostics

import (
	"encoding/json"
	"fmt"
	"mime"
	coreapi "opnsense-cli/opnsense/api"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Interfaces > Diagnostics > Packet Capture (api/diagnostics/packet_capture, PacketCaptureController). Like ping a
// capture is a job: set stores the settings and answers the job id, start runs one tcpdump per interface (in the
// background, writing /tmp/captures/<id>_<device>.pcap), search_jobs lists the jobs, stop kills the tcpdumps, remove
// kills them and deletes the files, view decodes the packets (tcpdump -r, at most ~500 per interface) and download
// sends a zip of the pcap files and the settings. tcpdump stops by itself after count packets per interface.
// Jobs are shared by all users of the firewall

// PacketCaptureFamilies are the address families a capture can be limited to
var PacketCaptureFamilies = []string{"any", "ip", "ip6", "arp"}

// PacketCaptureDetails are the detail levels of PacketCaptureView (tcpdump -q, -v, -vv)
var PacketCaptureDetails = []string{"normal", "medium", "high"}

// PacketCaptureSettings configure a capture job
type PacketCaptureSettings struct {
	// Interfaces are device names (vtnet0, lo0, ...) of PacketCaptureOptions, at least one
	Interfaces  []string
	Description string
	// Family is any (default), ip, ip6 or arp
	Family string
	// Protocol is a protocol of PacketCaptureOptions (any = no filter, the default), ProtocolInvert captures
	// everything but it
	Protocol       string
	ProtocolInvert bool
	// Host filters on addresses: blank separated addresses, networks (net), MAC addresses (ether host) and the
	// operators and/or/not, e.g. "10.0.0.1 and not 10.0.0.2"
	Host string
	// Port (1-65535, 0 = any) matches source or destination port, PortInvert everything but it
	Port       int
	PortInvert bool
	// Snaplen is the number of bytes captured per packet (0 = whole packet)
	Snaplen int
	// Count is the number of packets after which tcpdump stops (per interface), 0 = until stopped
	Count int
}

// PacketCaptureJob is a capture job of search_jobs
type PacketCaptureJob struct {
	Id             string `json:"id"`
	Interface      string `json:"interface"` // comma separated devices
	Description    string `json:"description"`
	Promiscuous    string `json:"promiscuous"`
	Family         string `json:"fam"`
	ProtocolInvert string `json:"protocol_not"`
	Protocol       string `json:"protocol"`
	Host           string `json:"host"`
	PortInvert     string `json:"port_not"`
	Port           string `json:"port"`
	Snaplen        string `json:"snaplen"`
	Count          string `json:"count"`
	Status         string `json:"status"` // running or stopped
	// Raw is the row as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

// Interfaces returns the devices of the job
func (j PacketCaptureJob) Interfaces() []string {
	var result []string
	for _, device := range strings.Split(j.Interface, ",") {
		if device = strings.TrimSpace(device); device != "" {
			result = append(result, device)
		}
	}
	return result
}

// Running tells whether a tcpdump of the job is alive
func (j PacketCaptureJob) Running() bool {
	return j.Status == "running"
}

// PacketCaptureInterface is a device that can be captured on, Label is the name OPNsense shows, e.g. "vtnet0 [LAN]"
type PacketCaptureInterface struct {
	Device string
	Label  string
}

// Description returns the interface description of the label (LAN for "vtnet0 [LAN]"), "" when there is none
func (i PacketCaptureInterface) Description() string {
	var open, end = strings.Index(i.Label, "["), strings.LastIndex(i.Label, "]")
	if open < 0 || end < open {
		return ""
	}
	return i.Label[open+1 : end]
}

// PacketCaptureOptions are the interfaces (sorted by device) and protocols (upper case, "any" first) a capture
// can use
type PacketCaptureOptions struct {
	Interfaces []PacketCaptureInterface
	Protocols  []string
}

// PacketCaptureOptions reads the choices of the capture settings
func (opn *DiagnosticsApi) PacketCaptureOptions() (PacketCaptureOptions, error) {
	var container struct {
		PacketCapture struct {
			Settings struct {
				Interface map[string]toolsOption `json:"interface"`
				Protocol  map[string]toolsOption `json:"protocol"`
			} `json:"settings"`
		} `json:"packetcapture"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("packet_capture", "get"), nil, &container); err != nil {
		return PacketCaptureOptions{}, err
	}
	var settings = container.PacketCapture.Settings
	if len(settings.Interface) == 0 {
		return PacketCaptureOptions{}, fmt.Errorf("unexpected answer from packet_capture get: no interfaces")
	}
	var options PacketCaptureOptions
	for device, option := range settings.Interface {
		options.Interfaces = append(options.Interfaces, PacketCaptureInterface{Device: device, Label: option.Value})
	}
	sort.Slice(options.Interfaces, func(i, j int) bool { return options.Interfaces[i].Device < options.Interfaces[j].Device })
	for protocol := range settings.Protocol {
		if protocol != "any" {
			options.Protocols = append(options.Protocols, protocol)
		}
	}
	sort.Strings(options.Protocols)
	options.Protocols = append([]string{"any"}, options.Protocols...)
	return options, nil
}

// PacketCaptureCreate validates the settings and stores them as a new (not yet started) job, returning its id
func (opn *DiagnosticsApi) PacketCaptureCreate(settings PacketCaptureSettings) (string, error) {
	var family, protocol = settings.Family, settings.Protocol
	if family == "" {
		family = "any"
	}
	if protocol == "" {
		protocol = "any"
	}
	var values = map[string]string{
		"interface":    strings.Join(settings.Interfaces, ","),
		"description":  settings.Description,
		"promiscuous":  "0",
		"fam":          family,
		"protocol_not": toolsFlag(settings.ProtocolInvert),
		"protocol":     protocol,
		"host":         settings.Host,
		"port_not":     toolsFlag(settings.PortInvert),
		"port":         "",
		"snaplen":      "",
		"count":        strconv.Itoa(settings.Count),
	}
	if settings.Port != 0 {
		values["port"] = strconv.Itoa(settings.Port)
	}
	if settings.Snaplen != 0 {
		values["snaplen"] = strconv.Itoa(settings.Snaplen)
	}
	var result, err = opn.toolsSet("packet_capture", "packetcapture", values)
	if err != nil {
		return "", err
	}
	if err := toolsCheckJobId("capture", result.Uuid); err != nil {
		return "", err
	}
	return result.Uuid, nil
}

// PacketCaptureStart starts the tcpdumps of a job. They need a moment to open the interfaces: packets of the
// first ~100ms after the answer may be missed
func (opn *DiagnosticsApi) PacketCaptureStart(id string) error {
	var _, err = opn.toolsJobAction("capture", "packet_capture", "start", id)
	return err
}

// PacketCaptureStop stops the tcpdumps of a job, the captured packets are kept
func (opn *DiagnosticsApi) PacketCaptureStop(id string) error {
	var _, err = opn.toolsJobAction("capture", "packet_capture", "stop", id)
	return err
}

// PacketCaptureRemove stops the tcpdumps of a job and deletes the job with its captured packets
func (opn *DiagnosticsApi) PacketCaptureRemove(id string) error {
	var _, err = opn.toolsJobAction("capture", "packet_capture", "remove", id)
	return err
}

// PacketCaptureJobs lists all capture jobs (of every user)
func (opn *DiagnosticsApi) PacketCaptureJobs() ([]PacketCaptureJob, error) {
	var rows, err = opn.toolsSearchRaw("packet_capture", "search_jobs")
	if err != nil {
		return nil, err
	}
	return toolsDecodeRows("capture job", rows, func(job *PacketCaptureJob, raw json.RawMessage) { job.Raw = raw })
}

// PacketCaptureJob returns one capture job, *coreapi.NotFoundError when it does not exist
func (opn *DiagnosticsApi) PacketCaptureJob(id string) (PacketCaptureJob, error) {
	var jobs, err = opn.PacketCaptureJobs()
	if err != nil {
		return PacketCaptureJob{}, err
	}
	for _, job := range jobs {
		if job.Id == id {
			return job, nil
		}
	}
	return PacketCaptureJob{}, &coreapi.NotFoundError{Name: "capture job " + id}
}

// PacketCapturePacket is a captured packet as decoded by tcpdump. Timestamp is the local time of the firewall
// without zone (e.g. 2026-10-25T15:40:37.803032), the MAC addresses are nil on interfaces without ethernet header
// (lo0, enc0), Text is the tcpdump output after the MAC addresses (with medium/high detail several lines)
type PacketCapturePacket struct {
	Timestamp      string  `json:"timestamp"`
	SourceMac      *string `json:"esrc"`
	DestinationMac *string `json:"edst"`
	Text           string  `json:"raw"`
	Family         string  `json:"fam"` // ip, ip6 or "" (e.g. arp)
}

// PacketCaptureInterfacePackets are the packets of one interface of a capture, Name its description (LAN)
type PacketCaptureInterfacePackets struct {
	Name    string                `json:"name"`
	Packets []PacketCapturePacket `json:"rows"`
}

// PacketCaptureViewResult are the decoded packets per device of a capture
type PacketCaptureViewResult struct {
	Interfaces map[string]PacketCaptureInterfacePackets `json:"-"`
	Raw        json.RawMessage                          `json:"-"`
}

// Devices returns the devices of the view, sorted
func (v PacketCaptureViewResult) Devices() []string {
	var devices = make([]string, 0, len(v.Interfaces))
	for device := range v.Interfaces {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	return devices
}

// PacketCaptureView decodes the packets captured so far with the detail level normal (default), medium or high.
// OPNsense stops decoding after about 500 packets per interface
func (opn *DiagnosticsApi) PacketCaptureView(id string, detail string) (PacketCaptureViewResult, error) {
	if detail == "" {
		detail = "normal"
	}
	if !slices.Contains(PacketCaptureDetails, detail) {
		return PacketCaptureViewResult{}, fmt.Errorf("invalid detail %q, want one of %s", detail, strings.Join(PacketCaptureDetails, ", "))
	}
	if err := toolsCheckJobId("capture", id); err != nil {
		return PacketCaptureViewResult{}, err
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.endpoint("packet_capture", "view/"+id+"/"+detail), nil, &raw); err != nil {
		return PacketCaptureViewResult{}, err
	}
	var container struct {
		Status     string          `json:"status"`
		Interfaces json.RawMessage `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		return PacketCaptureViewResult{}, fmt.Errorf("unexpected answer from packet_capture view: %w", err)
	}
	if container.Status != "ok" {
		return PacketCaptureViewResult{}, &coreapi.NotFoundError{Name: "capture job " + id}
	}
	var result = PacketCaptureViewResult{Interfaces: map[string]PacketCaptureInterfacePackets{}, Raw: raw}
	if err := trafficDecodeObject(container.Interfaces, &result.Interfaces); err != nil {
		return PacketCaptureViewResult{}, fmt.Errorf("unexpected answer from packet_capture view: %w", err)
	}
	return result, nil
}

// PacketCaptureDownload returns the zip archive of a capture (one <id>_<device>.pcap per interface and the
// settings as <id>.json) and the file name OPNsense suggests (<id>.zip)
func (opn *DiagnosticsApi) PacketCaptureDownload(id string) ([]byte, string, error) {
	if err := toolsCheckJobId("capture", id); err != nil {
		return nil, "", err
	}
	var response, content, err = opn.toolsDoRaw("GET", opn.endpoint("packet_capture", "download/"+id), "")
	if err != nil {
		return nil, "", err
	}
	// unknown jobs are answered with an empty 200
	if len(content) == 0 {
		return nil, "", &coreapi.NotFoundError{Name: "capture job " + id}
	}
	var filename = id + ".zip"
	if _, params, parseErr := mime.ParseMediaType(response.Header.Get("Content-Disposition")); parseErr == nil {
		if name := params["filename"]; name != "" {
			filename = name
		}
	}
	filename = filename[strings.LastIndexAny(filename, `/\`)+1:]
	if filename == "" || filename == "." || filename == ".." {
		filename = id + ".zip"
	}
	return content, filename, nil
}
