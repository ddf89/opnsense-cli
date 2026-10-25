package cli

import (
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// /tool/sniffer: Interfaces > Diagnostics > Packet Capture (api/diagnostics/packet_capture). A capture is a job on
// the firewall (one tcpdump per interface writing a pcap file) that start creates and starts; print lists the jobs
// of all users, view decodes the captured packets, download saves the pcap files as zip, stop ends the capture and
// remove deletes it with its files

// toolSnifferPoll is how often start duration= checks whether the capture ended by itself
const toolSnifferPoll = time.Second

func init() {
	var menu = Root.Menu("tool/sniffer")
	menu.Help = "packet capture on the firewall (tcpdump jobs)"
	var item = Arg{Name: "item", Positional: true, Required: true, Help: "the #, job id or description of the capture", Complete: toolSnifferCompleteJobs}
	menu.Add(
		&Command{
			Name: "print",
			Help: "list the captures (of all users) with their filters and state",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all settings of every capture"},
				{Name: "json", Type: Bool, Help: "print the raw jobs as JSON, one object per line"},
			},
			Run: toolSnifferPrint,
		},
		&Command{
			Name: "start",
			Help: "start a capture, prints its job id",
			Long: `Creates a capture job and starts one tcpdump per interface on the firewall. tcpdump stops by itself
after count packets per interface (0: until stop). The filters are combined with "and"; host takes addresses,
networks (10.0.0.0/8) and MAC addresses, combined with and/or/not ("10.0.0.1 and not 10.0.0.2").
tcpdump needs a moment to start, packets right after the start may be missed.

Without duration the capture keeps running after the command (see print, stop). With duration the command
waits that long, until the capture ended by itself or until Ctrl-C, and then stops it. Use view or download
afterwards and remove the capture when done.

  start interface=lan host=192.168.1.10 port=53 count=50
  start interface=wan,lan protocol=icmp duration=30s`,
			Args: []Arg{
				{Name: "interface", Type: List, Required: true, Complete: toolSnifferCompleteInterfaces,
					Help: "interfaces to capture on, by name (lan, wan, opt1), description or device (vtnet0)"},
				{Name: "family", Default: "any", Values: diagnostics.PacketCaptureFamilies, Help: "only IPv4 (ip), IPv6 (ip6) or ARP packets"},
				{Name: "protocol", Default: "any", Complete: toolSnifferCompleteProtocols, Help: "only this IP protocol (tcp, udp, icmp, esp, gre, carp, ...)"},
				{Name: "protocol-invert", Type: Bool, Help: "capture everything but the protocol"},
				{Name: "host", Help: "only packets from or to these addresses, networks or MACs (and/or/not allowed)"},
				{Name: "port", Type: Int, Help: "only packets with this source or destination port", Validate: ValidatePort},
				{Name: "port-invert", Type: Bool, Help: "capture everything but the port"},
				{Name: "snaplen", Type: Int, Help: "bytes to capture per packet (default: the whole packet)", Validate: ValidateRange(1, 262144)},
				{Name: "count", Type: Int, Default: "100", Help: "stop after this many packets per interface, 0 for no limit", Validate: ValidateRange(0, 100000000)},
				{Name: "description", Default: "opn sniffer", Help: "description of the capture"},
				{Name: "duration", Type: Duration, Help: "wait this long (or until Ctrl-C) and then stop the capture", Validate: systemActivityValidateInterval},
			},
			Check: func(args *Args) error {
				if args.Bool("protocol-invert") && strings.EqualFold(args.String("protocol"), "any") {
					return errors.New("protocol-invert needs a protocol")
				}
				if args.Bool("port-invert") && !args.Has("port") {
					return errors.New("port-invert needs a port")
				}
				return nil
			},
			Run: toolSnifferStart,
		},
		&Command{Name: "stop", Help: "stop a capture, its packets are kept", Args: []Arg{item}, Run: toolSnifferStop},
		&Command{Name: "remove", Help: "stop a capture and delete it with its packets", Args: []Arg{item}, Run: toolSnifferRemove},
		&Command{
			Name: "view",
			Help: "show the packets of a capture decoded by tcpdump",
			Long: `Decodes the captured packets on the firewall (tcpdump -r, at most about 500 per interface). Times are
the local time of the firewall. verbosity medium and high add the header details (tcpdump -v, -vv).`,
			Args: []Arg{
				item,
				{Name: "verbosity", Default: "normal", Values: diagnostics.PacketCaptureDetails, Help: "how much tcpdump decodes"},
				{Name: "interface", Type: List, Help: "only the packets of these interfaces (name, description or device)"},
				{Name: "json", Type: Bool, Help: "print the raw answer as one JSON object"},
			},
			Run: toolSnifferView,
		},
		&Command{
			Name: "download",
			Help: "save the packets of a capture as zip of pcap files",
			Long: `Saves a zip archive with one pcap file per interface (<id>_<device>.pcap, for Wireshark or tcpdump -r)
and the settings of the capture, named like OPNsense suggests (<id>.zip) unless file= is given; file=- writes
to stdout. An existing file is only overwritten with overwrite.`,
			Args: []Arg{
				item,
				{Name: "file", Help: "file to write, - for stdout (default: <id>.zip)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: toolSnifferDownload,
		},
	)
}

// --- helpers

func toolSnifferJobs(c *Context) (*diagnostics.DiagnosticsApi, []diagnostics.PacketCaptureJob, error) {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil, nil, err
	}
	jobs, err := api.PacketCaptureJobs()
	if err != nil {
		return nil, nil, err
	}
	// the job list comes from a directory listing: sort for stable # indexes
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].Id < jobs[j].Id })
	return api, jobs, nil
}

func toolSnifferSelect(c *Context, args *Args) (*diagnostics.DiagnosticsApi, diagnostics.PacketCaptureJob, error) {
	var api, jobs, err = toolSnifferJobs(c)
	if err != nil {
		return nil, diagnostics.PacketCaptureJob{}, err
	}
	job, err := Select(c, args.String("item"), jobs,
		func(job diagnostics.PacketCaptureJob) string { return job.Id },
		func(job diagnostics.PacketCaptureJob) []string { return []string{job.Description} })
	return api, job, err
}

func toolSnifferCompleteJobs(c *Context) []string {
	var _, jobs, err = toolSnifferJobs(c)
	if err != nil {
		return nil
	}
	var names []string
	for _, job := range jobs {
		names = append(names, job.Id)
	}
	return names
}

func toolSnifferCompleteInterfaces(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var options, optionsErr = api.PacketCaptureOptions()
	if optionsErr != nil {
		return nil
	}
	var names []string
	for _, iface := range options.Interfaces {
		if description := iface.Description(); description != "" {
			names = append(names, strings.ToLower(description))
		}
		names = append(names, iface.Device)
	}
	return names
}

func toolSnifferCompleteProtocols(c *Context) []string {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return nil
	}
	var options, optionsErr = api.PacketCaptureOptions()
	if optionsErr != nil {
		return nil
	}
	var names = make([]string, 0, len(options.Protocols))
	for _, protocol := range options.Protocols {
		names = append(names, strings.ToLower(protocol))
	}
	return names
}

// toolSnifferResolveInterfaces maps names (device, description or interface name like lan/opt1) to devices
func toolSnifferResolveInterfaces(api *diagnostics.DiagnosticsApi, options diagnostics.PacketCaptureOptions, names []string) ([]string, error) {
	var devices []string
	var add = func(device string) {
		if !slices.Contains(devices, device) {
			devices = append(devices, device)
		}
	}
	var byKey map[string]diagnostics.TrafficInterface // interface name -> totals with the device, loaded when needed
	for _, name := range names {
		var found = false
		for _, iface := range options.Interfaces {
			if strings.EqualFold(iface.Device, name) || strings.EqualFold(iface.Description(), name) {
				add(iface.Device)
				found = true
				break
			}
		}
		if found {
			continue
		}
		if byKey == nil {
			var err error
			if byKey, err = api.TrafficInterfaces(); err != nil {
				return nil, err
			}
		}
		for key, values := range byKey {
			if strings.EqualFold(key, name) && values["device"] != "" {
				add(values["device"])
				found = true
			}
		}
		if !found {
			var available = make([]string, 0, len(options.Interfaces))
			for _, iface := range options.Interfaces {
				available = append(available, iface.Label)
			}
			return nil, fmt.Errorf("unknown interface %q, OPNsense can capture on: %s", name, strings.Join(available, ", "))
		}
	}
	return devices, nil
}

func toolSnifferInverted(invert string, value string) string {
	if value == "" || strings.EqualFold(value, "any") {
		return value
	}
	if invert == "1" {
		return "!" + value
	}
	return value
}

// --- print

func toolSnifferPrint(c *Context, args *Args) error {
	var _, jobs, err = toolSnifferJobs(c)
	if err != nil {
		return err
	}
	var ids = make([]string, 0, len(jobs))
	for _, job := range jobs {
		ids = append(ids, job.Id)
	}
	switch {
	case args.Bool("json"):
		for _, job := range jobs {
			if err := c.JSON(job.Raw); err != nil {
				return err
			}
		}
	case args.Bool("detail"):
		var items = make([][][2]string, 0, len(jobs))
		for _, job := range jobs {
			items = append(items, [][2]string{
				{"id", job.Id}, {"description", job.Description}, {"status", job.Status},
				{"interface", job.Interface}, {"family", job.Family},
				{"protocol", toolSnifferInverted(job.ProtocolInvert, strings.ToLower(job.Protocol))},
				{"host", job.Host}, {"port", toolSnifferInverted(job.PortInvert, job.Port)},
				{"snaplen", job.Snaplen}, {"count", job.Count},
			})
		}
		c.Details(items, ids)
	default:
		var rows = make([][]string, 0, len(jobs))
		for _, job := range jobs {
			rows = append(rows, []string{
				job.Description, job.Interface, job.Family, toolSnifferInverted(job.ProtocolInvert, strings.ToLower(job.Protocol)),
				job.Host, toolSnifferInverted(job.PortInvert, job.Port), job.Count, job.Status,
			})
		}
		c.Items([]string{"DESCRIPTION", "INTERFACE", "FAMILY", "PROTOCOL", "HOST", "PORT", "COUNT", "STATUS"}, rows, ids)
	}
	return nil
}

// --- start

func toolSnifferStart(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	options, err := api.PacketCaptureOptions()
	if err != nil {
		return err
	}
	devices, err := toolSnifferResolveInterfaces(api, options, args.List("interface"))
	if err != nil {
		return err
	}
	var protocol = ""
	for _, known := range options.Protocols {
		if strings.EqualFold(known, args.String("protocol")) {
			protocol = known
		}
	}
	if protocol == "" {
		return fmt.Errorf("unknown protocol %q (e.g. tcp, udp, icmp, esp, gre, carp, ospf, pfsync; TAB completes them)", args.String("protocol"))
	}

	var settings = diagnostics.PacketCaptureSettings{
		Interfaces:     devices,
		Description:    args.String("description"),
		Family:         strings.ToLower(args.String("family")),
		Protocol:       protocol,
		ProtocolInvert: args.Bool("protocol-invert"),
		Host:           strings.TrimSpace(args.String("host")),
		Port:           args.Int("port"),
		PortInvert:     args.Bool("port-invert"),
		Snaplen:        args.Int("snaplen"),
		Count:          args.Int("count"),
	}
	id, err := api.PacketCaptureCreate(settings)
	if err != nil {
		return err
	}
	if err := api.PacketCaptureStart(id); err != nil {
		if removeErr := api.PacketCaptureRemove(id); removeErr != nil {
			c.Infof("warning: could not remove the capture job %s: %v", id, removeErr)
		}
		return err
	}
	c.Println(id)
	if !args.Has("duration") {
		return nil
	}
	return toolSnifferWait(c, api, id, args.Duration("duration"))
}

// toolSnifferWait waits until duration passed, the capture ended or Ctrl-C, then stops the capture
func toolSnifferWait(c *Context, api *diagnostics.DiagnosticsApi, id string, duration time.Duration) error {
	var deadline = time.NewTimer(duration)
	defer deadline.Stop()
	var ticker = time.NewTicker(toolSnifferPoll)
	defer ticker.Stop()
	c.Infof("capturing for %s (Ctrl-C stops earlier)", duration)
	var ended = false
wait:
	for {
		select {
		case <-c.Done():
			break wait
		case <-deadline.C:
			break wait
		case <-ticker.C:
			var job, err = systemActivityAwait(c, func() (diagnostics.PacketCaptureJob, error) { return api.PacketCaptureJob(id) })
			if c.Err() != nil {
				break wait
			}
			if err != nil {
				return err
			}
			if !job.Running() {
				ended = true
				break wait
			}
		}
	}
	if !ended {
		if err := api.PacketCaptureStop(id); err != nil {
			return err
		}
	}
	c.Infof("capture %s stopped, see view or download, remove it when done", id)
	return nil
}

// --- stop, remove

func toolSnifferStop(c *Context, args *Args) error {
	var api, job, err = toolSnifferSelect(c, args)
	if err != nil {
		return err
	}
	return api.PacketCaptureStop(job.Id)
}

func toolSnifferRemove(c *Context, args *Args) error {
	var api, job, err = toolSnifferSelect(c, args)
	if err != nil {
		return err
	}
	return api.PacketCaptureRemove(job.Id)
}

// --- view

func toolSnifferView(c *Context, args *Args) error {
	var api, job, err = toolSnifferSelect(c, args)
	if err != nil {
		return err
	}
	view, err := systemActivityAwait(c, func() (diagnostics.PacketCaptureViewResult, error) {
		return api.PacketCaptureView(job.Id, strings.ToLower(args.String("verbosity")))
	})
	if c.Err() != nil {
		return nil
	}
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return c.JSON(view.Raw)
	}

	var devices = view.Devices()
	if names := args.List("interface"); len(names) > 0 {
		var wanted []string
		for _, device := range devices {
			for _, name := range names {
				if strings.EqualFold(device, name) || strings.EqualFold(view.Interfaces[device].Name, name) {
					wanted = append(wanted, device)
					break
				}
			}
		}
		if len(wanted) == 0 {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("interface %s in the capture (it has %s)", strings.Join(names, ","), strings.Join(devices, ", "))}
		}
		devices = wanted
	}

	// all packets in time order, the timestamps of one capture have the same format
	type packet struct {
		device string
		diagnostics.PacketCapturePacket
	}
	var packets []packet
	for _, device := range devices {
		for _, p := range view.Interfaces[device].Packets {
			packets = append(packets, packet{device, p})
		}
	}
	sort.SliceStable(packets, func(i, j int) bool { return packets[i].Timestamp < packets[j].Timestamp })
	for _, p := range packets {
		var line = p.Timestamp + " " + p.device
		if p.SourceMac != nil && p.DestinationMac != nil {
			line += " " + *p.SourceMac + " > " + *p.DestinationMac
		}
		var text = strings.TrimRight(p.Text, "\n")
		c.Println(line + " " + strings.ReplaceAll(text, "\n", "\n    "))
	}
	if len(packets) == 0 {
		c.Infof("no packets captured (yet)")
	}
	return nil
}

// --- download

func toolSnifferDownload(c *Context, args *Args) error {
	var api, job, err = toolSnifferSelect(c, args)
	if err != nil {
		return err
	}
	content, filename, err := api.PacketCaptureDownload(job.Id)
	if err != nil {
		return err
	}
	var output = args.String("file")
	if output == "-" {
		_, err = c.Out.Write(content)
		return err
	}
	if output != "" {
		filename = output
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(content))
	return nil
}
