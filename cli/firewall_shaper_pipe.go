package cli

import (
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/shaper/pipe: dummynet pipes (bandwidth limits), named by their description

var firewallShaperPipes = firewallShaperKind[firewall.ShaperPipe]{
	what:        "pipe",
	list:        func(api *firewall.FirewallApi) ([]firewall.ShaperPipe, error) { return api.ShaperPipeList("") },
	uuid:        func(p firewall.ShaperPipe) string { return p.Uuid },
	description: func(p firewall.ShaperPipe) string { return p.Description },
	enabled:     func(p firewall.ShaperPipe) string { return p.Enabled },
	remove:      (*firewall.FirewallApi).ShaperPipeRemove,
	setEnabled:  (*firewall.FirewallApi).ShaperPipeSetEnabled,
}

func init() {
	var menu = Root.Menu("firewall/shaper/pipe")
	menu.Help = "shaper pipes: bandwidth limits"
	menu.Add(firewallShaperPipes.commands(
		firewallShaperPrintArgs("pipe"), firewallShaperPipePrint, firewallShaperPipeShow,
		`A pipe limits the bandwidth of the traffic rules send to it directly or through its queues. The
description names the pipe (queues and rules refer to it by it): if a pipe with the same description exists, add fails
unless replace is given, then that pipe is replaced completely (fields not given are reset).

  add bandwidth=100Mbit description="WAN download" scheduler=fq_codel`,
		firewallShaperPipeArgs(true), firewallShaperPipeAdd,
		firewallShaperPipeArgs(false), firewallShaperPipeSet,
	)...)
}

func firewallShaperPipeArgs(add bool) []Arg {
	var args = []Arg{
		{Name: "bandwidth", Required: add, Validate: firewallShaperValidateBandwidth,
			Help: "bandwidth with unit: 100Mbit, 512Kbit, 1Gbit, 64000bit (without unit in bandwidth-metric units, Kbit by default)"},
		{Name: "bandwidth-metric", Values: firewall.ShaperBandwidthMetrics, Help: "unit of a bandwidth given without unit"},
		{Name: "queue-size", Type: Int, Validate: ValidateRange(2, 100), Help: "queue size in slots (2-100), empty for the default"},
		firewallShaperMaskArg,
		{Name: "buckets", Type: Int, Validate: ValidateRange(1, 65535), Help: "hash table size for the dynamic pipes of mask, empty for the default"},
		{Name: "scheduler", Values: []string{"wfq", "fifo", "rr", "qfq", "fq_codel", "fq_pie"},
			Help: "wfq (weighted fair queueing, the default), fifo, rr (deficit round robin), qfq, fq_codel, fq_pie"},
	}
	args = append(args, firewallShaperCodelArgs()...)
	return append(args,
		Arg{Name: "fq-codel-quantum", Type: Int, Validate: ValidateRange(1, 65535), Help: "FQ-CoDel quantum in bytes"},
		Arg{Name: "fq-codel-limit", Type: Int, Validate: ValidateRange(1, 65535), Help: "FQ-CoDel queue limit in packets"},
		Arg{Name: "fq-codel-flows", Type: Int, Validate: ValidateRange(1, 65535), Help: "FQ-CoDel number of flow queues"},
		Arg{Name: "delay", Type: Int, Validate: ValidateRange(1, 3000), Help: "added delay in ms (1-3000), empty for none"},
		Arg{Name: "description", Required: add, Validate: dnsmasqNotEmpty, Help: "description, names the pipe"},
		Arg{Name: "disabled", Type: Bool, Help: "keep the pipe, but don't use it"},
	)
}

var firewallShaperPipeFieldMap = append([]firewallShaperArgField{
	{"queue-size", "queue", "text"}, {"mask", "mask", "text"}, {"buckets", "buckets", "text"}, {"scheduler", "scheduler", "text"},
	{"fq-codel-quantum", "fqcodel_quantum", "text"}, {"fq-codel-limit", "fqcodel_limit", "text"},
	{"fq-codel-flows", "fqcodel_flows", "text"}, {"delay", "delay", "text"}, {"description", "description", "text"},
	{"disabled", "enabled", "notFlag"},
}, firewallShaperCodelFields...)

// firewallShaperPipeFields returns the arguments as API fields (all for add, the given ones for set)
func firewallShaperPipeFields(args *Args, onlyGiven bool) (firewall.ShaperFields, error) {
	if err := firewallShaperCheckCodel(args); err != nil {
		return nil, err
	}
	var fields = firewallShaperFields(args, firewallShaperPipeFieldMap, onlyGiven)
	if scheduler, given := fields["scheduler"]; given {
		fields["scheduler"] = strings.ToLower(scheduler)
		if fields["scheduler"] == "wfq" {
			fields["scheduler"] = ""
		}
	}
	if mask, given := fields["mask"]; given {
		fields["mask"] = strings.ToLower(firewallShaperMaskOrNone(mask))
	}
	var defaultMetric = ""
	if !onlyGiven {
		defaultMetric = "Kbit"
	}
	var bandwidth, err = firewallShaperBandwidth(args, defaultMetric)
	if err != nil {
		return nil, err
	}
	for field, value := range bandwidth {
		fields[field] = value
	}
	return fields, nil
}

func firewallShaperMaskOrNone(mask string) string {
	if mask == "" {
		return "none"
	}
	return mask
}

func firewallShaperPipeScheduler(pipe firewall.ShaperPipe) string {
	if pipe.Scheduler == "" {
		return "wfq"
	}
	return pipe.Scheduler
}

func firewallShaperPipeDetail(pipe firewall.ShaperPipe) [][2]string {
	return [][2]string{
		{"uuid", pipe.Uuid},
		{"number", pipe.Number},
		{"description", pipe.Description},
		{"disabled", firewallShaperDisabled(pipe.Enabled)},
		{"bandwidth", firewallShaperBandwidthText(pipe.Bandwidth, pipe.BandwidthMetric)},
		{"queue-size", pipe.Queue},
		{"mask", pipe.Mask},
		{"buckets", pipe.Buckets},
		{"scheduler", firewallShaperPipeScheduler(pipe)},
		{"codel", YesNo(pipe.CodelEnable)},
		{"codel-target", pipe.CodelTarget},
		{"codel-interval", pipe.CodelInterval},
		{"codel-ecn", YesNo(pipe.CodelEcnEnable)},
		{"pie", YesNo(pipe.PieEnable)},
		{"fq-codel-quantum", pipe.FqcodelQuantum},
		{"fq-codel-limit", pipe.FqcodelLimit},
		{"fq-codel-flows", pipe.FqcodelFlows},
		{"delay", pipe.Delay},
	}
}

func firewallShaperPipePrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	raws, pipes, err := api.ShaperPipeListRaw(args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return firewallShaperPrintJSON(c, raws)
	}
	var uuids = make([]string, len(pipes))
	for i, pipe := range pipes {
		uuids[i] = pipe.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(pipes))
		for i, pipe := range pipes {
			details[i] = firewallShaperPipeDetail(pipe)
		}
		c.Details(details, uuids)
		return nil
	}
	var rows = make([][]string, len(pipes))
	for i, pipe := range pipes {
		rows[i] = []string{firewallShaperDisabled(pipe.Enabled), pipe.Number, firewallShaperBandwidthText(pipe.Bandwidth, pipe.BandwidthMetric),
			pipe.Mask, firewallShaperPipeScheduler(pipe), pipe.Description}
	}
	c.Items([]string{"DISABLED", "NUMBER", "BANDWIDTH", "MASK", "SCHEDULER", "DESCRIPTION"}, rows, uuids)
	return nil
}

func firewallShaperPipeShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	pipe, _, err := firewallShaperPipes.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(firewallShaperPipeDetail(pipe))
	return nil
}

func firewallShaperPipeAdd(c *Context, args *Args) error {
	var fields, err = firewallShaperPipeFields(args, false)
	if err != nil {
		return err
	}
	var pipe = firewall.ShaperPipe{
		Enabled: fields["enabled"], Bandwidth: fields["bandwidth"], BandwidthMetric: fields["bandwidthMetric"],
		Queue: fields["queue"], Mask: fields["mask"], Buckets: fields["buckets"], Scheduler: fields["scheduler"],
		CodelEnable: fields["codel_enable"], CodelTarget: fields["codel_target"], CodelInterval: fields["codel_interval"],
		CodelEcnEnable: fields["codel_ecn_enable"], PieEnable: fields["pie_enable"], FqcodelQuantum: fields["fqcodel_quantum"],
		FqcodelLimit: fields["fqcodel_limit"], FqcodelFlows: fields["fqcodel_flows"], Delay: fields["delay"],
		Description: fields["description"],
	}
	api, err := firewallApi(c)
	if err != nil {
		return err
	}
	return firewallShaperAdd(c, args.Bool("replace"), "pipe", pipe.Description,
		func() ([]string, error) {
			return firewallShaperPipes.uuids(api.ShaperPipeFindByDescription(pipe.Description))
		},
		func() (string, error) { return api.ShaperPipeCreate(pipe) },
		func() (string, bool, error) { return api.ShaperPipeCreateOrUpdate(pipe) })
}

func firewallShaperPipeSet(c *Context, args *Args) error {
	var fields, err = firewallShaperPipeFields(args, true)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return errors.New("set: nothing to change, give at least one field like bandwidth= or description= (type \"set ?\" for help)")
	}
	api, err := firewallApi(c)
	if err != nil {
		return err
	}
	pipe, pipes, err := firewallShaperPipes.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if description, renamed := fields["description"]; renamed {
		for _, other := range pipes {
			if other.Uuid != pipe.Uuid && strings.EqualFold(strings.TrimSpace(other.Description), description) {
				return fmt.Errorf("another pipe described %q exists already (%s)", description, other.Uuid)
			}
		}
	}
	return api.ShaperPipeUpdate(pipe.Uuid, fields)
}

// --- shared by the add commands of pipes, queues and rules

// firewallShaperAdd adds a record (failing when one with the same description exists) or with replace creates or
// replaces it, and prints the uuid
func firewallShaperAdd(c *Context, replace bool, what string, description string, find func() ([]string, error),
	create func() (string, error), createOrUpdate func() (string, bool, error)) error {
	if replace {
		var uuid, replaced, err = createOrUpdate()
		var tooMany *coreapi.TooManyFoundError
		if errors.As(err, &tooMany) {
			return fmt.Errorf("%w, change one with set or remove the duplicates", err)
		}
		if err != nil {
			return err
		}
		if replaced {
			c.Infof("replaced the existing %s %s", what, description)
		}
		c.Println(uuid)
		return nil
	}
	if description != "" {
		var existing, err = find()
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return fmt.Errorf("a %s described %q exists already (%s), change it with set or replace it with add ... replace",
				what, description, strings.Join(existing, ", "))
		}
	}
	var uuid, err = create()
	if err != nil {
		return err
	}
	c.Println(uuid)
	return nil
}

// firewallShaperPrintJSON writes raw rows as ndjson
func firewallShaperPrintJSON[T any](c *Context, raws []T) error {
	for _, raw := range raws {
		if err := c.JSON(raw); err != nil {
			return err
		}
	}
	return nil
}
