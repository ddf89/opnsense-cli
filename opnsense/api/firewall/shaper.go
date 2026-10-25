package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Traffic shaper (Firewall > Shaper, api/trafficshaper/settings and api/trafficshaper/service): pipes (bandwidth
// limits), queues (weighted shares of a pipe) and rules (which traffic goes to a pipe or queue). Changes are only
// saved, ShaperReconfigure applies them.
//
// Pipes and queues are named by their description (rules and queues refer to them by uuid, OPNsense shows the
// description), set_<kind>/<unknown uuid> creates a record (when the body is complete), so updates check existence
// first. Deleting a pipe or queue that is referenced answers HTTP 500 with an "in use by" message.

// ShaperFields holds a partial pipe, queue or rule keyed by the API field name (see ShaperPipeFieldNames,
// ShaperQueueFieldNames, ShaperRuleFieldNames). Only the given keys are sent, OPNsense keeps all other fields
type ShaperFields map[string]string

// ShaperPipe is a dummynet pipe (api/trafficshaper/settings/*_pipe, body key "pipe")
type ShaperPipe struct {
	Uuid    string `json:"uuid,omitempty"`
	Number  string `json:"number"` // assigned by OPNsense (10000 and up), read only
	Enabled string `json:"enabled"`
	// Bandwidth is a whole number in BandwidthMetric units: bit, Kbit, Mbit or Gbit (per second, at most 4294967295 bit/s)
	Bandwidth       string `json:"bandwidth"`
	BandwidthMetric string `json:"bandwidthMetric"`
	Queue           string `json:"queue"` // queue size in slots (2-100), empty for the default
	// Mask creates a dynamic pipe per address: none, src-ip, dst-ip, src-ip6, dst-ip6
	Mask    string `json:"mask"`
	Buckets string `json:"buckets"`
	// Scheduler is "" (weighted fair queueing), fifo, rr, qfq, fq_codel or fq_pie
	Scheduler      string `json:"scheduler"`
	CodelEnable    string `json:"codel_enable"`
	CodelTarget    string `json:"codel_target"`   // ms
	CodelInterval  string `json:"codel_interval"` // ms
	CodelEcnEnable string `json:"codel_ecn_enable"`
	PieEnable      string `json:"pie_enable"`
	FqcodelQuantum string `json:"fqcodel_quantum"`
	FqcodelLimit   string `json:"fqcodel_limit"`
	FqcodelFlows   string `json:"fqcodel_flows"`
	Origin         string `json:"origin,omitempty"` // "TrafficShaper" for records added by the GUI / add_pipe, read only
	Delay          string `json:"delay"`            // ms
	Description    string `json:"description"`
}

// ShaperQueue is a dummynet queue: a weighted share of a pipe (api/trafficshaper/settings/*_queue, body key "queue")
type ShaperQueue struct {
	Uuid    string `json:"uuid,omitempty"`
	Number  string `json:"number"` // assigned by OPNsense, read only
	Enabled string `json:"enabled"`
	Pipe    string `json:"pipe"` // uuid of the pipe
	// PipeLabel is the description of the pipe, only in search rows
	PipeLabel      string `json:"%pipe,omitempty"`
	Weight         string `json:"weight"` // 1-100
	Mask           string `json:"mask"`
	Buckets        string `json:"buckets"`
	CodelEnable    string `json:"codel_enable"`
	CodelTarget    string `json:"codel_target"`
	CodelInterval  string `json:"codel_interval"`
	CodelEcnEnable string `json:"codel_ecn_enable"`
	PieEnable      string `json:"pie_enable"`
	Description    string `json:"description"`
	Origin         string `json:"origin,omitempty"`
}

// ShaperRule sends matching traffic to a pipe or queue (api/trafficshaper/settings/*_rule, body key "rule")
type ShaperRule struct {
	Uuid     string `json:"uuid,omitempty"`
	Enabled  string `json:"enabled"`
	Sequence string `json:"sequence"`
	// Interface / Interface2 are interface keys (wan, lan, opt1), Interface2 optionally limits to traffic between both
	Interface       string `json:"interface"`
	InterfaceLabel  string `json:"%interface,omitempty"`
	Interface2      string `json:"interface2"`
	Interface2Label string `json:"%interface2,omitempty"`
	// Proto is ip, ip4, ip6, udp, tcp, tcp_ack, tcp_ack_not, icmp, ipv6-icmp, igmp, esp, ah or gre
	Proto string `json:"proto"`
	Iplen string `json:"iplen"` // match packets up to this length
	// Source / Destination are "any" or comma separated networks / addresses
	Source         string `json:"source"`
	SourceNot      string `json:"source_not"`
	SrcPort        string `json:"src_port"` // any, a port, a range 1000-2000 or a service name
	Destination    string `json:"destination"`
	DestinationNot string `json:"destination_not"`
	DstPort        string `json:"dst_port"`
	Dscp           string `json:"dscp"`      // comma separated: be, ef, af11 ... cs7
	Direction      string `json:"direction"` // in, out or "" for both
	Target         string `json:"target"`    // uuid of a pipe or queue
	// TargetLabel is the description of the target, only in search rows
	TargetLabel string `json:"%target,omitempty"`
	Description string `json:"description"`
	Origin      string `json:"origin,omitempty"`
}

// ShaperPipeFieldNames are the writable fields of a pipe
var ShaperPipeFieldNames = []string{
	"enabled", "bandwidth", "bandwidthMetric", "queue", "mask", "buckets", "scheduler", "codel_enable", "codel_target",
	"codel_interval", "codel_ecn_enable", "pie_enable", "fqcodel_quantum", "fqcodel_limit", "fqcodel_flows", "delay",
	"description",
}

// ShaperQueueFieldNames are the writable fields of a queue
var ShaperQueueFieldNames = []string{
	"enabled", "pipe", "weight", "mask", "buckets", "codel_enable", "codel_target", "codel_interval", "codel_ecn_enable",
	"pie_enable", "description",
}

// ShaperRuleFieldNames are the writable fields of a rule
var ShaperRuleFieldNames = []string{
	"enabled", "sequence", "interface", "interface2", "proto", "iplen", "source", "source_not", "src_port", "destination",
	"destination_not", "dst_port", "dscp", "direction", "target", "description",
}

// Option values of the model
var (
	ShaperBandwidthMetrics = []string{"bit", "Kbit", "Mbit", "Gbit"}
	ShaperMasks            = []string{"none", "src-ip", "dst-ip", "src-ip6", "dst-ip6"}
	ShaperSchedulers       = []string{"", "fifo", "rr", "qfq", "fq_codel", "fq_pie"}
	ShaperProtocols        = []string{"ip", "ip4", "ip6", "udp", "tcp", "tcp_ack", "tcp_ack_not", "icmp", "ipv6-icmp", "igmp", "esp", "ah", "gre"}
	ShaperDscpValues       = []string{"be", "ef", "af11", "af12", "af13", "af21", "af22", "af23", "af31", "af32", "af33",
		"af41", "af42", "af43", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6", "cs7"}
	ShaperDirections = []string{"", "in", "out"}
)

// ShaperMaxBandwidth is the largest bandwidth of a pipe in bit/s
const ShaperMaxBandwidth = 4294967295

func shaperOr(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// Fields returns all writable fields of p with the model defaults for empty flags (enabled 1, metric Kbit, mask none)
func (p ShaperPipe) Fields() ShaperFields {
	return ShaperFields{
		"enabled": shaperOr(p.Enabled, "1"), "bandwidth": p.Bandwidth, "bandwidthMetric": shaperOr(p.BandwidthMetric, "Kbit"),
		"queue": p.Queue, "mask": shaperOr(p.Mask, "none"), "buckets": p.Buckets, "scheduler": p.Scheduler,
		"codel_enable": shaperOr(p.CodelEnable, "0"), "codel_target": p.CodelTarget, "codel_interval": p.CodelInterval,
		"codel_ecn_enable": shaperOr(p.CodelEcnEnable, "0"), "pie_enable": shaperOr(p.PieEnable, "0"),
		"fqcodel_quantum": p.FqcodelQuantum, "fqcodel_limit": p.FqcodelLimit, "fqcodel_flows": p.FqcodelFlows,
		"delay": p.Delay, "description": p.Description,
	}
}

// Fields returns all writable fields of q with the model defaults for empty flags (enabled 1, weight 100, mask none)
func (q ShaperQueue) Fields() ShaperFields {
	return ShaperFields{
		"enabled": shaperOr(q.Enabled, "1"), "pipe": q.Pipe, "weight": shaperOr(q.Weight, "100"), "mask": shaperOr(q.Mask, "none"),
		"buckets": q.Buckets, "codel_enable": shaperOr(q.CodelEnable, "0"), "codel_target": q.CodelTarget,
		"codel_interval": q.CodelInterval, "codel_ecn_enable": shaperOr(q.CodelEcnEnable, "0"),
		"pie_enable": shaperOr(q.PieEnable, "0"), "description": q.Description,
	}
}

// Fields returns all writable fields of r with the model defaults for empty values (enabled 1, sequence 1, interface
// wan, proto ip, any source / destination / ports)
func (r ShaperRule) Fields() ShaperFields {
	return ShaperFields{
		"enabled": shaperOr(r.Enabled, "1"), "sequence": shaperOr(r.Sequence, "1"), "interface": shaperOr(r.Interface, "wan"),
		"interface2": r.Interface2, "proto": shaperOr(r.Proto, "ip"), "iplen": r.Iplen, "source": shaperOr(r.Source, "any"),
		"source_not": shaperOr(r.SourceNot, "0"), "src_port": shaperOr(r.SrcPort, "any"),
		"destination": shaperOr(r.Destination, "any"), "destination_not": shaperOr(r.DestinationNot, "0"),
		"dst_port": shaperOr(r.DstPort, "any"), "dscp": r.Dscp, "direction": r.Direction, "target": r.Target,
		"description": r.Description,
	}
}

// --- shared CRUD of pipes, queues and rules

// shaperKind describes one record type of the settings controller
type shaperKind struct {
	what   string // for messages: "shaper pipe"
	key    string // body key and method suffix: pipe -> add_pipe, {"pipe":{...}}
	search string // search method: search_pipes
	fields []string
}

var (
	shaperPipeKind  = shaperKind{what: "shaper pipe", key: "pipe", search: "search_pipes", fields: ShaperPipeFieldNames}
	shaperQueueKind = shaperKind{what: "shaper queue", key: "queue", search: "search_queues", fields: ShaperQueueFieldNames}
	shaperRuleKind  = shaperKind{what: "shaper rule", key: "rule", search: "search_rules", fields: ShaperRuleFieldNames}
)

func (opn *FirewallApi) shaperSettingsEndpoint(method string) string {
	return opn.endpoint("trafficshaper", "settings", method)
}

func (opn *FirewallApi) shaperServiceEndpoint(method string) string {
	return opn.endpoint("trafficshaper", "service", method)
}

func shaperNotFound(kind shaperKind, name string, err error) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("%s %s", kind.what, name), Err: err}
}

// shaperListRaw returns the search rows raw and decoded, in API order (pipes and queues by number, rules by sequence)
func shaperListRaw[T any](opn *FirewallApi, kind shaperKind, searchPhrase string) ([]json.RawMessage, []T, error) {
	var endpoint = opn.shaperSettingsEndpoint(kind.search)
	var raws, err = coreapi.Search[json.RawMessage](opn.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var items = make([]T, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &items[i]); err != nil {
			return nil, nil, fmt.Errorf("could not decode a row of %s: %w", endpoint, err)
		}
	}
	return raws, items, nil
}

func shaperGet[T any](opn *FirewallApi, kind shaperKind, uuid string, uuidOf func(T) string) (T, error) {
	var _, items, err = shaperListRaw[T](opn, kind, "")
	if err != nil {
		var zero T
		return zero, err
	}
	for _, item := range items {
		if strings.EqualFold(uuidOf(item), uuid) {
			return item, nil
		}
	}
	var zero T
	return zero, shaperNotFound(kind, uuid, nil)
}

// shaperFindByDescription returns the records whose description equals description (case-insensitive, trimmed)
func shaperFindByDescription[T any](opn *FirewallApi, kind shaperKind, description string, descriptionOf func(T) string) ([]T, error) {
	description = strings.TrimSpace(description)
	if description == "" {
		return nil, errors.New("description must not be empty")
	}
	// searchPhrase is a substring match over all columns, compare exactly
	var _, items, err = shaperListRaw[T](opn, kind, description)
	if err != nil {
		return nil, err
	}
	return coreapi.Filter(items, func(item T) bool { return strings.EqualFold(strings.TrimSpace(descriptionOf(item)), description) }), nil
}

func (opn *FirewallApi) shaperCreate(kind shaperKind, fields ShaperFields) (string, error) {
	return opn.Mutate(opn.shaperSettingsEndpoint("add_"+kind.key), map[string]ShaperFields{kind.key: fields})
}

func shaperCheckFields(kind shaperKind, fields ShaperFields) error {
	for name := range fields {
		if !slices.Contains(kind.fields, name) {
			return fmt.Errorf("unknown %s field %q", kind.what, name)
		}
	}
	return nil
}

// shaperUpdate sends only fields to set_<kind>/<uuid> after checking that uuid exists (set would create it)
func shaperUpdate[T any](opn *FirewallApi, kind shaperKind, uuid string, fields ShaperFields, uuidOf func(T) string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := shaperCheckFields(kind, fields); err != nil {
		return err
	}
	var existing, err = shaperGet(opn, kind, uuid, uuidOf)
	if err != nil {
		return err
	}
	return opn.shaperSet(kind, uuidOf(existing), fields)
}

// shaperSet sends fields to set_<kind>/<uuid> without checking that uuid exists
func (opn *FirewallApi) shaperSet(kind shaperKind, uuid string, fields ShaperFields) error {
	var _, err = opn.Mutate(opn.shaperSettingsEndpoint("set_"+kind.key)+"/"+uuid, map[string]ShaperFields{kind.key: fields})
	// a malformed uuid is answered with a plain {"result":"failed"} without validation messages
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return shaperNotFound(kind, uuid, err)
	}
	return err
}

// shaperCreateOrUpdate adds fields as a new record, or overwrites the one record with this description
func shaperCreateOrUpdate[T any](opn *FirewallApi, kind shaperKind, fields ShaperFields, uuidOf func(T) string, descriptionOf func(T) string) (string, bool, error) {
	var existing, err = shaperFindByDescription(opn, kind, fields["description"], descriptionOf)
	if err != nil {
		return "", false, err
	}
	switch len(existing) {
	case 0:
		var created, createErr = opn.shaperCreate(kind, fields)
		return created, false, createErr
	case 1:
		// just found by the search, no need to check for existence again
		return uuidOf(existing[0]), true, opn.shaperSet(kind, uuidOf(existing[0]), fields)
	default:
		var uuids = make([]string, len(existing))
		for i, item := range existing {
			uuids[i] = uuidOf(item)
		}
		sort.Strings(uuids)
		return "", false, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d %ss described %q (uuids: %s)",
			len(existing), kind.what, fields["description"], strings.Join(uuids, ", "))}
	}
}

// shaperRemove deletes a record. Pipes and queues in use by queues / rules are refused by OPNsense with HTTP 500
// {"errorTitle":"Item pipes.pipe {desc} in use by:","errorMessage":"TrafficShaper - <desc> {TrafficShaper.queues.queue.<uuid>}\n"}
func (opn *FirewallApi) shaperRemove(kind shaperKind, uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	var _, err = opn.Mutate(opn.shaperSettingsEndpoint("del_"+kind.key)+"/"+uuid, nil)
	if coreapi.IsNotFound(err) {
		return shaperNotFound(kind, uuid, err)
	}
	var httpErr *coreapi.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 500 && strings.Contains(httpErr.Message, "{TrafficShaper.") {
		var users []string
		for _, line := range strings.Split(strings.TrimSpace(httpErr.Message), "\n") {
			users = append(users, strings.TrimPrefix(strings.TrimSpace(line), "TrafficShaper - "))
		}
		return fmt.Errorf("%s %s is in use by: %s", kind.what, uuid, strings.Join(users, "; "))
	}
	return err
}

// shaperSetEnabled sets the state with toggle_<kind>/<uuid>/<0|1>: {"result":"Enabled"|"Disabled","changed":bool},
// an unknown uuid answers {"result":"failed"}
func (opn *FirewallApi) shaperSetEnabled(kind shaperKind, uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("uuid must not be empty")
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.shaperSettingsEndpoint("toggle_"+kind.key), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, map[string]any{}, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed", "not found":
		return false, shaperNotFound(kind, uuid, nil)
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// --- pipes

func shaperPipeUuid(p ShaperPipe) string        { return p.Uuid }
func shaperPipeDescription(p ShaperPipe) string { return p.Description }

// ShaperPipeList returns the pipes ordered by number, searchPhrase is a substring match over all columns ("" for all)
func (opn *FirewallApi) ShaperPipeList(searchPhrase string) ([]ShaperPipe, error) {
	var _, pipes, err = shaperListRaw[ShaperPipe](opn, shaperPipeKind, searchPhrase)
	return pipes, err
}

// ShaperPipeListRaw returns the pipes raw (for JSON output) and decoded, in the same order
func (opn *FirewallApi) ShaperPipeListRaw(searchPhrase string) ([]json.RawMessage, []ShaperPipe, error) {
	return shaperListRaw[ShaperPipe](opn, shaperPipeKind, searchPhrase)
}

// ShaperPipeGet returns the pipe with the given uuid or a *NotFoundError
func (opn *FirewallApi) ShaperPipeGet(uuid string) (ShaperPipe, error) {
	return shaperGet(opn, shaperPipeKind, uuid, shaperPipeUuid)
}

// ShaperPipeFindByDescription returns the pipes with this description (case-insensitive)
func (opn *FirewallApi) ShaperPipeFindByDescription(description string) ([]ShaperPipe, error) {
	return shaperFindByDescription(opn, shaperPipeKind, description, shaperPipeDescription)
}

// ShaperPipeCreate adds a pipe (OPNsense assigns its number) and returns its uuid. Duplicates are not checked
func (opn *FirewallApi) ShaperPipeCreate(pipe ShaperPipe) (string, error) {
	return opn.shaperCreate(shaperPipeKind, pipe.Fields())
}

// ShaperPipeUpdate sends only the given fields, *NotFoundError when the uuid does not exist (checked first)
func (opn *FirewallApi) ShaperPipeUpdate(uuid string, fields ShaperFields) error {
	return shaperUpdate(opn, shaperPipeKind, uuid, fields, shaperPipeUuid)
}

// ShaperPipeCreateOrUpdate adds pipe, or overwrites the pipe with the same description with all fields of pipe.
// Returns the uuid and whether an existing pipe was replaced, *TooManyFoundError for duplicate descriptions
func (opn *FirewallApi) ShaperPipeCreateOrUpdate(pipe ShaperPipe) (string, bool, error) {
	return shaperCreateOrUpdate(opn, shaperPipeKind, pipe.Fields(), shaperPipeUuid, shaperPipeDescription)
}

// ShaperPipeRemove deletes the pipe, *NotFoundError when it does not exist, an error naming the users when queues
// or rules refer to it
func (opn *FirewallApi) ShaperPipeRemove(uuid string) error {
	return opn.shaperRemove(shaperPipeKind, uuid)
}

// ShaperPipeSetEnabled enables or disables the pipe and returns whether its state changed
func (opn *FirewallApi) ShaperPipeSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.shaperSetEnabled(shaperPipeKind, uuid, enabled)
}

// --- queues

func shaperQueueUuid(q ShaperQueue) string        { return q.Uuid }
func shaperQueueDescription(q ShaperQueue) string { return q.Description }

// ShaperQueueList returns the queues ordered by number, searchPhrase is a substring match over all columns
func (opn *FirewallApi) ShaperQueueList(searchPhrase string) ([]ShaperQueue, error) {
	var _, queues, err = shaperListRaw[ShaperQueue](opn, shaperQueueKind, searchPhrase)
	return queues, err
}

// ShaperQueueListRaw returns the queues raw (for JSON output) and decoded, in the same order
func (opn *FirewallApi) ShaperQueueListRaw(searchPhrase string) ([]json.RawMessage, []ShaperQueue, error) {
	return shaperListRaw[ShaperQueue](opn, shaperQueueKind, searchPhrase)
}

// ShaperQueueGet returns the queue with the given uuid or a *NotFoundError
func (opn *FirewallApi) ShaperQueueGet(uuid string) (ShaperQueue, error) {
	return shaperGet(opn, shaperQueueKind, uuid, shaperQueueUuid)
}

// ShaperQueueFindByDescription returns the queues with this description (case-insensitive)
func (opn *FirewallApi) ShaperQueueFindByDescription(description string) ([]ShaperQueue, error) {
	return shaperFindByDescription(opn, shaperQueueKind, description, shaperQueueDescription)
}

// ShaperQueueCreate adds a queue (OPNsense assigns its number) and returns its uuid. Duplicates are not checked
func (opn *FirewallApi) ShaperQueueCreate(queue ShaperQueue) (string, error) {
	return opn.shaperCreate(shaperQueueKind, queue.Fields())
}

// ShaperQueueUpdate sends only the given fields, *NotFoundError when the uuid does not exist (checked first)
func (opn *FirewallApi) ShaperQueueUpdate(uuid string, fields ShaperFields) error {
	return shaperUpdate(opn, shaperQueueKind, uuid, fields, shaperQueueUuid)
}

// ShaperQueueCreateOrUpdate adds queue, or overwrites the queue with the same description with all fields of queue
func (opn *FirewallApi) ShaperQueueCreateOrUpdate(queue ShaperQueue) (string, bool, error) {
	return shaperCreateOrUpdate(opn, shaperQueueKind, queue.Fields(), shaperQueueUuid, shaperQueueDescription)
}

// ShaperQueueRemove deletes the queue, *NotFoundError when it does not exist, an error naming the users when rules
// refer to it
func (opn *FirewallApi) ShaperQueueRemove(uuid string) error {
	return opn.shaperRemove(shaperQueueKind, uuid)
}

// ShaperQueueSetEnabled enables or disables the queue and returns whether its state changed
func (opn *FirewallApi) ShaperQueueSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.shaperSetEnabled(shaperQueueKind, uuid, enabled)
}

// --- rules

func shaperRuleUuid(r ShaperRule) string        { return r.Uuid }
func shaperRuleDescription(r ShaperRule) string { return r.Description }

// ShaperRuleList returns the rules ordered by sequence, searchPhrase is a substring match over all columns
func (opn *FirewallApi) ShaperRuleList(searchPhrase string) ([]ShaperRule, error) {
	var _, rules, err = shaperListRaw[ShaperRule](opn, shaperRuleKind, searchPhrase)
	return rules, err
}

// ShaperRuleListRaw returns the rules raw (for JSON output) and decoded, in the same order
func (opn *FirewallApi) ShaperRuleListRaw(searchPhrase string) ([]json.RawMessage, []ShaperRule, error) {
	return shaperListRaw[ShaperRule](opn, shaperRuleKind, searchPhrase)
}

// ShaperRuleGet returns the rule with the given uuid or a *NotFoundError
func (opn *FirewallApi) ShaperRuleGet(uuid string) (ShaperRule, error) {
	return shaperGet(opn, shaperRuleKind, uuid, shaperRuleUuid)
}

// ShaperRuleFindByDescription returns the rules with this description (case-insensitive)
func (opn *FirewallApi) ShaperRuleFindByDescription(description string) ([]ShaperRule, error) {
	return shaperFindByDescription(opn, shaperRuleKind, description, shaperRuleDescription)
}

// ShaperRuleCreate adds a rule and returns its uuid. Duplicates are not checked
func (opn *FirewallApi) ShaperRuleCreate(rule ShaperRule) (string, error) {
	return opn.shaperCreate(shaperRuleKind, rule.Fields())
}

// ShaperRuleUpdate sends only the given fields, *NotFoundError when the uuid does not exist (checked first)
func (opn *FirewallApi) ShaperRuleUpdate(uuid string, fields ShaperFields) error {
	return shaperUpdate(opn, shaperRuleKind, uuid, fields, shaperRuleUuid)
}

// ShaperRuleCreateOrUpdate adds rule, or overwrites the rule with the same (non-empty) description with all fields
// of rule
func (opn *FirewallApi) ShaperRuleCreateOrUpdate(rule ShaperRule) (string, bool, error) {
	if strings.TrimSpace(rule.Description) == "" {
		return "", false, errors.New("a rule is only found by its description, give one")
	}
	return shaperCreateOrUpdate(opn, shaperRuleKind, rule.Fields(), shaperRuleUuid, shaperRuleDescription)
}

// ShaperRuleRemove deletes the rule, *NotFoundError when it does not exist
func (opn *FirewallApi) ShaperRuleRemove(uuid string) error {
	return opn.shaperRemove(shaperRuleKind, uuid)
}

// ShaperRuleSetEnabled enables or disables the rule and returns whether its state changed
func (opn *FirewallApi) ShaperRuleSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.shaperSetEnabled(shaperRuleKind, uuid, enabled)
}

// ShaperOption is a choice of an option field: the key the API stores and the text OPNsense shows
type ShaperOption struct {
	Key   string
	Label string
}

// ShaperRuleOptions are the choices of a new rule (get_rule): the interfaces, the targets (pipes and queues) and the
// sequence OPNsense proposes (the highest sequence + 1)
type ShaperRuleOptions struct {
	Interfaces   []ShaperOption
	Targets      []ShaperOption
	NextSequence string
}

// ShaperRuleOptions returns the interfaces and targets a rule can use, sorted by label
func (opn *FirewallApi) ShaperRuleOptions() (ShaperRuleOptions, error) {
	var container struct {
		Rule struct {
			Sequence  string          `json:"sequence"`
			Interface json.RawMessage `json:"interface"`
			Target    json.RawMessage `json:"target"`
		} `json:"rule"`
	}
	var endpoint = opn.shaperSettingsEndpoint("get_rule")
	if err := opn.DoJSON("GET", endpoint, nil, &container); err != nil {
		return ShaperRuleOptions{}, err
	}
	if container.Rule.Interface == nil {
		return ShaperRuleOptions{}, fmt.Errorf("unexpected answer from %s: no interface options", endpoint)
	}
	var interfaces, err = shaperOptions(container.Rule.Interface)
	if err != nil {
		return ShaperRuleOptions{}, fmt.Errorf("could not decode the interfaces of %s: %w", endpoint, err)
	}
	targets, err := shaperOptions(container.Rule.Target)
	if err != nil {
		return ShaperRuleOptions{}, fmt.Errorf("could not decode the targets of %s: %w", endpoint, err)
	}
	return ShaperRuleOptions{Interfaces: interfaces, Targets: targets, NextSequence: container.Rule.Sequence}, nil
}

// shaperOptions decodes an option map {"<key>":{"value":"<label>","selected":0}}, which is [] when empty
func shaperOptions(raw json.RawMessage) ([]ShaperOption, error) {
	var text = strings.TrimSpace(string(raw))
	if text == "" || text == "[]" || text == "null" {
		return nil, nil
	}
	var options map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &options); err != nil {
		return nil, err
	}
	var result = make([]ShaperOption, 0, len(options))
	for key, option := range options {
		result = append(result, ShaperOption{Key: key, Label: option.Value})
	}
	sort.Slice(result, func(i, j int) bool {
		var a, b = strings.ToLower(result[i].Label), strings.ToLower(result[j].Label)
		if a != b {
			return a < b
		}
		return result[i].Key < result[j].Key
	})
	return result, nil
}

// --- service

// ShaperReconfigure applies the saved shaper configuration: regenerates the dummynet and ipfw configuration and
// reloads both. OPNsense answers {"status":"ok"} or {"status":"error reloading shaper (...)"}
func (opn *FirewallApi) ShaperReconfigure() error {
	var result struct {
		Status string `json:"status"`
	}
	// actions must be POSTed, a GET answers {"status":"failed"} without doing anything
	if err := opn.DoJSON("POST", opn.shaperServiceEndpoint("reconfigure"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(result.Status, "ok") {
		return fmt.Errorf("shaper reconfigure failed: %s", shaperOr(result.Status, "no status given"))
	}
	return nil
}

// ShaperFlushReload flushes all ipfw rules and reloads dummynet and ipfw (service/flushreload). OPNsense answers
// {"status":"<output of ipfw reload>"}, "OK" on success
func (opn *FirewallApi) ShaperFlushReload() error {
	var result struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.shaperServiceEndpoint("flushreload"), nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(result.Status), "ok") {
		return fmt.Errorf("shaper flush and reload failed: %s", shaperOr(result.Status, "no status given"))
	}
	return nil
}

// ShaperStatistics are the live dummynet statistics (service/statistics): pipes, each followed by its queues
type ShaperStatistics struct {
	Items []ShaperStatItem
}

// ShaperStatItem is a pipe or queue of the statistics. OPNsense merges the dnctl output with the model, values come
// as strings or numbers; Raw is the item as received
type ShaperStatItem struct {
	Type        string // pipe, queue or unknown (the header of queues without pipe)
	Id          string // pipe number, "<pipe>.<queue>" for queues
	Uuid        string // of the pipe / queue in the model, empty for the automatic queue of a pipe
	Description string
	// Template marks the queue dummynet creates for a pipe itself (traffic sent to the pipe directly)
	Template bool
	// Bandwidth, Delay and Burst are set for pipes (dnctl text, e.g. "100.000 Mbit/s")
	Bandwidth string
	Delay     string
	Burst     string
	// FlowSetNr, Weight, QueueSize and SchedNr are set for queues
	FlowSetNr string
	Weight    string
	QueueSize string
	SchedNr   string
	// SchedulerType is the dummynet scheduler of a pipe, e.g. "FQ_CODEL"
	SchedulerType string
	Flows         []ShaperStatFlow
	Rules         []ShaperStatRule
	Raw           json.RawMessage
}

// ShaperStatFlow is an active flow (dynamic queue) of a pipe or queue
type ShaperStatFlow struct {
	Bucket      string
	Proto       string
	Source      string
	Destination string
	Packets     int64
	Bytes       int64
	DropPackets int64
	DropBytes   int64
}

// ShaperStatRule is an ipfw rule sending traffic to a queue (or a pipe's automatic queue), with its counters
type ShaperStatRule struct {
	Rule          string // ipfw rule number
	Packets       int64
	Bytes         int64
	AccessedEpoch int64
	AttachedTo    string
	RuleUuid      string
	Description   string
}

// Packets, Bytes and Drops sum up the flows
func (item ShaperStatItem) Packets() (packets int64, bytes int64, drops int64) {
	for _, flow := range item.Flows {
		packets += flow.Packets
		bytes += flow.Bytes
		drops += flow.DropPackets
	}
	return packets, bytes, drops
}

// UnmarshalJSON decodes an item leniently (strings, numbers and nulls)
func (item *ShaperStatItem) UnmarshalJSON(data []byte) error {
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	var text = func(key string) string { return shaperText(row[key]) }
	*item = ShaperStatItem{
		Type: text("type"), Id: text("id"), Uuid: text("uuid"), Description: text("description"),
		Template: shaperBool(row["template"]), Bandwidth: text("bw"), Delay: text("delay"), Burst: text("burst"),
		FlowSetNr: text("flow_set_nr"), Weight: text("weight"), QueueSize: text("queue_size"), SchedNr: text("sched_nr"),
		Raw: append(json.RawMessage(nil), data...),
	}
	if scheduler, ok := row["scheduler"].(map[string]any); ok {
		item.SchedulerType = shaperText(scheduler["sched_type"])
	}
	if flows, ok := row["flows"].([]any); ok {
		for _, value := range flows {
			if flow, ok := value.(map[string]any); ok {
				item.Flows = append(item.Flows, ShaperStatFlow{
					Bucket: shaperText(flow["BKT"]), Proto: shaperText(flow["Prot"]), Source: shaperText(flow["Source"]),
					Destination: shaperText(flow["Destination"]), Packets: shaperInt(flow["pkt"]), Bytes: shaperInt(flow["bytes"]),
					DropPackets: shaperInt(flow["drop_pkt"]), DropBytes: shaperInt(flow["drop_bytes"]),
				})
			}
		}
	}
	if rules, ok := row["rules"].([]any); ok {
		for _, value := range rules {
			if rule, ok := value.(map[string]any); ok {
				item.Rules = append(item.Rules, ShaperStatRule{
					Rule: shaperText(rule["rule"]), Packets: shaperInt(rule["pkts"]), Bytes: shaperInt(rule["bytes"]),
					AccessedEpoch: shaperInt(rule["accessed_epoch"]), AttachedTo: shaperText(rule["attached_to"]),
					RuleUuid: shaperText(rule["rule_uuid"]), Description: shaperText(rule["description"]),
				})
			}
		}
	}
	return nil
}

func shaperText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "1"
		}
		return "0"
	default:
		var encoded, _ = json.Marshal(v)
		return string(encoded)
	}
}

func shaperInt(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case string:
		var number, _ = strconv.ParseInt(v, 10, 64)
		return number
	}
	return 0
}

func shaperBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "1" || v == "true"
	case float64:
		return v != 0
	}
	return false
}

// ShaperStatisticsGet returns the live statistics. Without enabled pipes (or before the first reconfigure) there are
// no items; {"status":"failed"} (configd error) is an error
func (opn *FirewallApi) ShaperStatisticsGet() (ShaperStatistics, error) {
	var result struct {
		Status string           `json:"status"`
		Items  []ShaperStatItem `json:"items"`
	}
	var endpoint = opn.shaperServiceEndpoint("statistics")
	if err := opn.DoJSON("GET", endpoint, nil, &result); err != nil {
		return ShaperStatistics{}, err
	}
	if result.Status != "ok" {
		return ShaperStatistics{}, fmt.Errorf("shaper statistics failed: %s", shaperOr(result.Status, "no status given"))
	}
	return ShaperStatistics{Items: result.Items}, nil
}
