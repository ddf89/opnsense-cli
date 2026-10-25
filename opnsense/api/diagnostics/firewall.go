package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FirewallLogEntry is a parsed pf (filterlog) record, as returned by api/diagnostics/firewall/log and stream_log.
// Which fields are set depends on the IP version and protocol (see Spec), all values are strings
type FirewallLogEntry struct {
	// Timestamp is the firewall's local time without zone, e.g. 2026-10-25T00:03:19
	Timestamp string `json:"__timestamp__"`
	Host      string `json:"__host__"`
	// Digest is the md5 of the raw log line. The stream hashes the line including its newline, so the same record has a
	// different digest in log and stream_log; use Key to compare records of both
	Digest string `json:"__digest__"`
	// Spec lists the filterlog fields of this record in log order
	Spec []string `json:"__spec__"`
	// RuleNr is the pf rule number, Rid the rule id (uuid or md5) and Label the rule description of the running config
	RuleNr    string `json:"rulenr"`
	Rid       string `json:"rid"`
	Label     string `json:"label"`
	Interface string `json:"interface"` // the device, e.g. vtnet0, see FirewallInterfaceNames
	Reason    string `json:"reason"`
	Action    string `json:"action"` // pass, block, rdr, nat, binat
	Dir       string `json:"dir"`    // in, out
	IpVersion string `json:"ipversion"`
	ProtoName string `json:"protoname"`
	ProtoNum  string `json:"protonum"`
	Length    string `json:"length"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	SrcPort   string `json:"srcport"`
	DstPort   string `json:"dstport"`
	TcpFlags  string `json:"tcpflags"`

	// Raw is the record as sent by OPNsense
	Raw json.RawMessage `json:"-"`
}

func (entry *FirewallLogEntry) UnmarshalJSON(data []byte) error {
	type plainEntry FirewallLogEntry
	var plain plainEntry
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	*entry = FirewallLogEntry(plain)
	entry.Raw = append(json.RawMessage(nil), data...)
	return nil
}

// Fields returns all fields of the raw record (including ones without struct field) with their string values
func (entry FirewallLogEntry) Fields() map[string]string {
	var raw map[string]any
	var fields = map[string]string{}
	if json.Unmarshal(entry.Raw, &raw) != nil {
		return fields
	}
	for name, value := range raw {
		switch typed := value.(type) {
		case string:
			fields[name] = typed
		case float64:
			fields[name] = strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
	return fields
}

// Key identifies a record independent of its source (log or stream): timestamp, host and the filterlog fields
func (entry FirewallLogEntry) Key() string {
	var fields = entry.Fields()
	var parts = []string{entry.Timestamp, entry.Host}
	var spec = entry.Spec
	if len(spec) == 0 {
		// no spec, use all fields except the ones differing between log and stream
		for name := range fields {
			if name != "__digest__" && name != "counter" && name != "label" {
				spec = append(spec, name)
			}
		}
		sort.Strings(spec)
	}
	for _, name := range spec {
		parts = append(parts, name+"="+fields[name])
	}
	return strings.Join(parts, "|")
}

// FirewallLogFilters are the choices of the firewall log view (api/diagnostics/firewall/log_filters)
type FirewallLogFilters struct {
	Action []string `json:"action"`
	// InterfaceName are the interface descriptions (or keys like lan when there is none), not devices
	InterfaceName []string `json:"interface_name"`
	Dir           []string `json:"dir"`
}

// FirewallStat is a top-10 entry of api/diagnostics/firewall/stats, the 11th entry is labelled "other"
type FirewallStat struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

// FirewallLogDefaultLimit is what OPNsense uses when no limit is given
const FirewallLogDefaultLimit = 1000

// FirewallLog returns the newest limit records, newest first. When sinceDigest is set, only the records newer than
// the one with this Digest are returned (OPNsense stops reading there); if it is not found within limit records,
// all limit records are returned and found is false
func (opn *DiagnosticsApi) FirewallLog(limit int, sinceDigest string) (entries []FirewallLogEntry, found bool, err error) {
	if limit <= 0 {
		// OPNsense treats 0 / empty as its default
		limit = FirewallLogDefaultLimit
	}
	var query = url.Values{"limit": {strconv.Itoa(limit)}}
	if sinceDigest != "" {
		query.Set("digest", sinceDigest)
	}

	if err = opn.DoJSON("GET", opn.endpoint("firewall", "log")+"?"+query.Encode(), nil, &entries); err != nil {
		return nil, false, err
	}
	if entries == nil {
		// e.g. an invalid limit makes the backend script fail, which is answered with null
		return nil, false, fmt.Errorf("no firewall log answer from OPNsense (invalid limit?)")
	}
	if sinceDigest == "" {
		return entries, false, nil
	}
	// the record with the digest is included as last one
	for i, entry := range entries {
		if entry.Digest == sinceDigest {
			return entries[:i], true, nil
		}
	}
	return entries, false, nil
}

// FirewallLogFilters returns the filter choices of the firewall log view
func (opn *DiagnosticsApi) FirewallLogFilters() (FirewallLogFilters, error) {
	var filters FirewallLogFilters
	var err = opn.DoJSON("GET", opn.endpoint("firewall", "log_filters"), nil, &filters)
	return filters, err
}

// FirewallInterfaceNames maps devices to interface names (description or upper-cased key), e.g. vtnet0 -> LAN
func (opn *DiagnosticsApi) FirewallInterfaceNames() (map[string]string, error) {
	var names map[string]string
	if err := opn.DoJSON("GET", opn.endpoint("interface", "getInterfaceNames"), nil, &names); err != nil {
		return nil, err
	}
	if names == nil {
		names = map[string]string{}
	}
	return names, nil
}

// FirewallStats counts the newest limit records (0 for OPNsense's default of 5000) grouped by a record field
// (interface, action, dir, protoname, src, dst, dstport, label, ...), returning the top 10 plus "other".
// Interfaces are labelled with their names; unknown fields give an empty result
func (opn *DiagnosticsApi) FirewallStats(groupBy string, limit int) ([]FirewallStat, error) {
	var query = url.Values{}
	if groupBy != "" {
		query.Set("group_by", groupBy)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var endpoint = opn.endpoint("firewall", "stats")
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var stats []FirewallStat
	if err := opn.DoJSON("GET", endpoint, nil, &stats); err != nil {
		return nil, err
	}
	if stats == nil {
		stats = []FirewallStat{}
	}
	return stats, nil
}

// FirewallLogStream reads api/diagnostics/firewall/stream_log once and calls handle for every record. OPNsense first
// replays the last 5 records. Note the stream is lossy: OPNsense throttles it and drops records (see FirewallLogFollow).
// It returns nil when ctx is cancelled and io.EOF when the server ends the stream
func (opn *DiagnosticsApi) FirewallLogStream(ctx context.Context, handle func(FirewallLogEntry) error) error {
	return opn.Stream(ctx, opn.endpoint("firewall", "stream_log"), func(event coreapi.StreamEvent) error {
		if event.Event != "message" || strings.TrimSpace(event.Data) == "" {
			return nil
		}
		var entry FirewallLogEntry
		if err := json.Unmarshal([]byte(event.Data), &entry); err != nil {
			return fmt.Errorf("could not decode firewall log event: %w", err)
		}
		return handle(entry)
	})
}

// FirewallFollowOptions configures FirewallLogFollow
type FirewallFollowOptions struct {
	// SinceDigest is the Digest of the newest record already seen (from FirewallLog), polling continues after it
	SinceDigest string
	// Seen are records already handled, the stream mode skips them when OPNsense replays them
	Seen []FirewallLogEntry
	// Stream uses stream_log instead of polling the log. It is faster but lossy: OPNsense (read_log.py --stream)
	// only passes records arriving within 100ms of a throttle window and drops the rest
	Stream bool
	// Interval between polls, default 1s
	Interval time.Duration
	// MaxBackoff is the maximum wait before retrying after an error, default 30s
	MaxBackoff time.Duration
	// OnWarning is called for errors which are retried and for possibly skipped records
	OnWarning func(error)
}

// FirewallLogGapError is passed to OnWarning when records may have been skipped between two polls
type FirewallLogGapError struct {
	SinceDigest string
}

func (e *FirewallLogGapError) Error() string {
	return fmt.Sprintf("the last seen record %s is no longer in the newest %d records, some records may have been skipped",
		e.SinceDigest, FirewallLogDefaultLimit)
}

// firewallFatal reports errors that retrying does not fix (authentication, permissions, unknown endpoint)
func firewallFatal(err error) bool {
	var httpErr *coreapi.HttpError
	return errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusUnauthorized ||
		httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusNotFound)
}

// firewallSleep waits for d, returns false when ctx is cancelled first
func firewallSleep(ctx context.Context, d time.Duration) bool {
	var timer = time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// FirewallLogFollow calls handle for every new firewall log record (oldest first) until ctx is cancelled (returns nil),
// handle returns an error or a non retryable error (401/403/404) occurs. Other errors are retried with exponential backoff.
// By default it polls the log since the last seen digest, which is complete; see FirewallFollowOptions.Stream
func (opn *DiagnosticsApi) FirewallLogFollow(ctx context.Context, options FirewallFollowOptions, handle func(FirewallLogEntry) error) error {
	if options.Interval <= 0 {
		options.Interval = time.Second
	}
	if options.MaxBackoff <= 0 {
		options.MaxBackoff = 30 * time.Second
	}
	if options.OnWarning == nil {
		options.OnWarning = func(error) {}
	}
	if options.Stream {
		return opn.firewallFollowStream(ctx, options, handle)
	}
	return opn.firewallFollowPoll(ctx, options, handle)
}

// firewallBackoff doubles the wait up to max
func firewallBackoff(current time.Duration, max time.Duration) time.Duration {
	if current <= 0 {
		return min(time.Second, max)
	}
	if current*2 > max {
		return max
	}
	return current * 2
}

func (opn *DiagnosticsApi) firewallFollowPoll(ctx context.Context, options FirewallFollowOptions, handle func(FirewallLogEntry) error) error {
	var since = options.SinceDigest
	var backoff time.Duration
	for {
		if ctx.Err() != nil {
			return nil
		}
		var entries, found, err = opn.FirewallLog(FirewallLogDefaultLimit, since)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if firewallFatal(err) {
				return err
			}
			backoff = firewallBackoff(backoff, options.MaxBackoff)
			options.OnWarning(fmt.Errorf("%w, retrying in %s", err, backoff))
			if !firewallSleep(ctx, backoff) {
				return nil
			}
			continue
		}
		backoff = 0

		if since != "" && !found && len(entries) >= FirewallLogDefaultLimit {
			options.OnWarning(&FirewallLogGapError{SinceDigest: since})
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if err := handle(entries[i]); err != nil {
				return err
			}
		}
		if len(entries) > 0 {
			since = entries[0].Digest
		}

		if !firewallSleep(ctx, options.Interval) {
			return nil
		}
	}
}

// firewallSeenKeys remembers the keys of the last records, to skip the replay after (re)connecting
type firewallSeenKeys struct {
	keys  map[string]bool
	order []string
}

const firewallSeenKeysMax = 1000

func (seen *firewallSeenKeys) add(key string) bool {
	if seen.keys[key] {
		return false
	}
	seen.keys[key] = true
	seen.order = append(seen.order, key)
	if len(seen.order) > firewallSeenKeysMax {
		delete(seen.keys, seen.order[0])
		seen.order = seen.order[1:]
	}
	return true
}

func (opn *DiagnosticsApi) firewallFollowStream(ctx context.Context, options FirewallFollowOptions, handle func(FirewallLogEntry) error) error {
	var seen = &firewallSeenKeys{keys: map[string]bool{}}
	for _, entry := range options.Seen {
		seen.add(entry.Key())
	}

	var backoff time.Duration
	// errors before the first record are not retried (e.g. an OPNsense version without stream_log)
	var connected bool
	for {
		var handleErr error
		var err = opn.FirewallLogStream(ctx, func(entry FirewallLogEntry) error {
			// connected and receiving: a later drop starts with a short wait again
			connected = true
			backoff = 0
			if !seen.add(entry.Key()) {
				return nil
			}
			if err := handle(entry); err != nil {
				handleErr = err
				return err
			}
			return nil
		})
		if handleErr != nil {
			return handleErr
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) && (!connected || firewallFatal(err)) {
			return err
		}
		if err == nil || errors.Is(err, io.EOF) {
			err = errors.New("stream closed by OPNsense")
		}
		backoff = firewallBackoff(backoff, options.MaxBackoff)
		options.OnWarning(fmt.Errorf("%w, reconnecting in %s", err, backoff))
		if !firewallSleep(ctx, backoff) {
			return nil
		}
	}
}
