package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"strconv"
	"strings"
	"time"
)

// /tool ping: Interfaces > Diagnostics > Ping (api/diagnostics/ping). OPNsense runs the ping as a background job
// and only reports its running statistics, so ping creates a job, starts it, polls the statistics and prints a line
// whenever another packet was sent, until count packets were sent or Ctrl-C. The job is always removed at the end

// toolPingPoll is how often the statistics are read while pinging
const toolPingPoll = 500 * time.Millisecond

func init() {
	Root.Menu("tool").Add(&Command{
		Name: "ping",
		Help: "ping a host from the firewall until count packets were sent or Ctrl-C",
		Long: `Pings from the firewall. OPNsense runs the ping as a job and reports only its running statistics (not the
single replies), so a line is printed whenever more packets were sent: the packets sent and received so far, the
loss and the round trip times. The statistics lag up to a second behind. Without count the ping runs until
Ctrl-C. At the end a summary is printed and the job is removed (also on Ctrl-C or an error).
json prints the raw job statistics instead, one JSON object per line.

  ping 192.168.1.10 count=4
  ping fd00::1 size=1400 do-not-fragment`,
		Args: []Arg{
			toolDiagAddressArg("host name or address to ping"),
			{Name: "count", Type: Int, Help: "stop after this many packets (default: until Ctrl-C)", Validate: ValidateRange(1, 86400)},
			{Name: "size", Type: Int, Help: "number of data bytes per packet (ping -s)", Validate: ValidateRange(1, 65535)},
			{Name: "interval", Type: Duration, Default: "1s", Help: "pause between two packets, whole seconds from 1s to 120s", Validate: toolPingValidateInterval},
			toolDiagSourceArg,
			toolDiagFamilyArg,
			{Name: "do-not-fragment", Type: Bool, Help: "set the don't fragment bit"},
			{Name: "description", Default: "opn ping", Help: "description of the job (shown in the GUI while it runs)"},
			{Name: "json", Type: Bool, Help: "print the raw job statistics as JSON, one object per line"},
		},
		Check: toolDiagCheckFamily,
		Run:   toolPingRun,
	})
}

func toolPingValidateInterval(value string) error {
	var interval, err = parseDuration(value)
	if err != nil {
		return err
	}
	if interval < time.Second || interval > 120*time.Second || interval%time.Second != 0 {
		return fmt.Errorf("must be whole seconds from 1s to 120s, got %q", value)
	}
	return nil
}

func toolPingRun(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var settings = diagnostics.PingSettings{
		Hostname:             args.String("address"),
		Family:               "ip",
		SourceAddress:        args.String("source"),
		PacketSize:           args.Int("size"),
		DisableFragmentation: args.Bool("do-not-fragment"),
		Description:          args.String("description"),
	}
	if toolDiagFamily(args) == "ipv6" {
		settings.Family = "ip6"
	}
	if args.Has("interval") {
		settings.Interval = int(args.Duration("interval") / time.Second)
	}

	id, err := api.PingCreate(settings)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := api.PingRemove(id); removeErr != nil {
			c.Infof("warning: could not remove the ping job %s: %v", id, removeErr)
		}
	}()
	if err := api.PingStart(id); err != nil {
		return err
	}
	return toolPingWatch(c, api, id, int64(args.Int("count")), args.Bool("json"))
}

// toolPingWatch polls the job until count packets were sent (count 0: until Ctrl-C), printing a line per change
func toolPingWatch(c *Context, api *diagnostics.DiagnosticsApi, id string, count int64, asJSON bool) error {
	var last *diagnostics.PingJob
	var printedSent int64 = 0
	if !asJSON {
		toolPingLine(c, "SENT", "RECEIVED", "LOSS", "MIN-RTT", "AVG-RTT", "MAX-RTT", "STATUS")
	}
	for {
		var job, err = systemActivityAwait(c, func() (diagnostics.PingJob, error) { return api.PingJob(id) })
		if c.Err() != nil {
			break // Ctrl-C
		}
		if err != nil {
			return err
		}
		last = &job

		if sent := toolPingValue(job.Sent); sent > printedSent {
			printedSent = sent
			if asJSON {
				if err := c.JSON(job.Raw); err != nil {
					return err
				}
			} else {
				toolPingLine(c, strconv.FormatInt(sent, 10), strconv.FormatInt(toolPingValue(job.Received), 10),
					toolPingLoss(job), toolDiagMs(job.Min), toolDiagMs(job.Avg), toolDiagMs(job.Max), toolPingError(job))
			}
		}
		if count > 0 && printedSent >= count {
			break
		}
		if !job.Running() {
			if message := toolPingError(job); message != "" {
				return fmt.Errorf("ping %s: %s", job.Hostname, message)
			}
			return fmt.Errorf("the ping of %s ended (stopped by someone else?)", job.Hostname)
		}

		var timer = time.NewTimer(toolPingPoll)
		select {
		case <-c.Done():
			timer.Stop()
		case <-timer.C:
		}
		if c.Err() != nil {
			break
		}
	}
	if last != nil && !asJSON {
		c.Printf("sent=%d received=%d packet-loss=%s", toolPingValue(last.Sent), toolPingValue(last.Received), toolPingLoss(*last))
		if last.Min != nil {
			c.Printf(" min-rtt=%s avg-rtt=%s max-rtt=%s", toolDiagMs(last.Min), toolDiagMs(last.Avg), toolDiagMs(last.Max))
		}
		c.Println()
	}
	return nil
}

func toolPingLine(c *Context, sent, received, loss, minRtt, avgRtt, maxRtt, status string) {
	c.Println(strings.TrimRight(fmt.Sprintf("%6s %9s %6s %10s %10s %10s  %s", sent, received, loss, minRtt, avgRtt, maxRtt, status), " "))
}

func toolPingValue(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// toolPingLoss computes the packet loss of the statistics (the loss text of OPNsense differs between IPv4 and IPv6)
func toolPingLoss(job diagnostics.PingJob) string {
	var sent, received = toolPingValue(job.Sent), toolPingValue(job.Received)
	if sent <= 0 {
		return "0%"
	}
	var loss = float64(sent-received) * 100 / float64(sent)
	if loss < 0 {
		loss = 0
	}
	return strconv.FormatFloat(float64(int64(loss*10+0.5))/10, 'f', -1, 64) + "%"
}

func toolPingError(job diagnostics.PingJob) string {
	if job.LastError == nil {
		return ""
	}
	return *job.LastError
}
