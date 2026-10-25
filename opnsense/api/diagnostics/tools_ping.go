package diagnostics

import (
	"encoding/json"
	"strconv"

	coreapi "opnsense-cli/opnsense/api"
)

// Interfaces > Diagnostics > Ping (api/diagnostics/ping, OPNsense\Diagnostics\Api\PingController). A ping is a job:
// set stores the settings and answers the job id, start runs "ping -c 86400" in the background, search_jobs lists
// the jobs with the statistics of the latest summary, stop kills the ping, remove kills it and deletes the job.
// There are no per packet results: every search_jobs sends SIGINFO to the running pings and reads the summary
// they printed last, so the statistics lag one listing behind. Jobs are shared by all users of the firewall and
// keep running (up to a day) until stopped or removed

// PingFamilies are the address families of a ping (ip = IPv4, ip6 = IPv6)
var PingFamilies = []string{"ip", "ip6"}

// PingSettings configure a ping job. Empty or zero values use the defaults of ping
type PingSettings struct {
	Hostname string // host name or address, required
	Family   string // "ip" (default) or "ip6"
	// SourceAddress is the address to send from (ping -S)
	SourceAddress string
	// PacketSize is the number of data bytes (ping -s), 1-65535
	PacketSize int
	// DisableFragmentation sets the don't fragment bit (ping -D)
	DisableFragmentation bool
	// Interval is the number of seconds between two packets (ping -i), 1-120
	Interval    int
	Description string
}

// PingJob is a ping job of search_jobs. The statistics are nil until the first summary was read
type PingJob struct {
	Id                   string   `json:"id"`
	Hostname             string   `json:"hostname"`
	Family               string   `json:"fam"`
	SourceAddress        string   `json:"source_address"`
	PacketSize           string   `json:"packetsize"`
	DisableFragmentation string   `json:"disable_frag"`
	Interval             string   `json:"interval"`
	Description          string   `json:"description"`
	Status               string   `json:"status"` // running or stopped
	Sent                 *int64   `json:"send"`
	Received             *int64   `json:"received"`
	Loss                 *string  `json:"loss"` // as printed by OPNsense, e.g. "0.0%"
	Min                  *float64 `json:"min"`  // round trip times in milliseconds
	Avg                  *float64 `json:"avg"`
	Max                  *float64 `json:"max"`
	StdDev               *float64 `json:"std-dev"`
	// LastError is the last "ping: ..." message of the log, e.g. "sendto: Host is down"
	LastError *string `json:"last_error"`
	// Raw is the row as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

// Running tells whether the ping process is alive
func (j PingJob) Running() bool {
	return j.Status == "running"
}

// PingCreate validates the settings and stores them as a new (not yet started) job, returning its id
func (opn *DiagnosticsApi) PingCreate(settings PingSettings) (string, error) {
	var family = settings.Family
	if family == "" {
		family = "ip"
	}
	var values = map[string]string{
		"hostname":       settings.Hostname,
		"fam":            family,
		"source_address": settings.SourceAddress,
		"packetsize":     "",
		"disable_frag":   toolsFlag(settings.DisableFragmentation),
		"interval":       "",
		"description":    settings.Description,
	}
	if settings.PacketSize != 0 {
		values["packetsize"] = strconv.Itoa(settings.PacketSize)
	}
	if settings.Interval != 0 {
		values["interval"] = strconv.Itoa(settings.Interval)
	}
	var result, err = opn.toolsSet("ping", "ping", values)
	if err != nil {
		return "", err
	}
	if err := toolsCheckJobId("ping", result.Uuid); err != nil {
		return "", err
	}
	return result.Uuid, nil
}

// PingStart starts the ping of a job. Starting a running job fails ("already active")
func (opn *DiagnosticsApi) PingStart(id string) error {
	var _, err = opn.toolsJobAction("ping", "ping", "start", id)
	return err
}

// PingStop stops the ping of a job, the job and its last statistics are kept
func (opn *DiagnosticsApi) PingStop(id string) error {
	var _, err = opn.toolsJobAction("ping", "ping", "stop", id)
	return err
}

// PingRemove stops the ping of a job and deletes the job
func (opn *DiagnosticsApi) PingRemove(id string) error {
	var _, err = opn.toolsJobAction("ping", "ping", "remove", id)
	return err
}

// PingJobs lists all ping jobs (of every user) with their latest statistics
func (opn *DiagnosticsApi) PingJobs() ([]PingJob, error) {
	var rows, err = opn.toolsSearchRaw("ping", "search_jobs")
	if err != nil {
		return nil, err
	}
	return toolsDecodeRows("ping job", rows, func(job *PingJob, raw json.RawMessage) { job.Raw = raw })
}

// PingJob returns one ping job, *coreapi.NotFoundError when it does not exist
func (opn *DiagnosticsApi) PingJob(id string) (PingJob, error) {
	var jobs, err = opn.PingJobs()
	if err != nil {
		return PingJob{}, err
	}
	for _, job := range jobs {
		if job.Id == id {
			return job, nil
		}
	}
	return PingJob{}, &coreapi.NotFoundError{Name: "ping job " + id}
}
