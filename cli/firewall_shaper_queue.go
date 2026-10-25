package cli

import (
	"errors"
	"fmt"
	"strings"

	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/shaper/queue: dummynet queues (weighted shares of a pipe), named by their description

var firewallShaperQueues = firewallShaperKind[firewall.ShaperQueue]{
	what:        "queue",
	list:        func(api *firewall.FirewallApi) ([]firewall.ShaperQueue, error) { return api.ShaperQueueList("") },
	uuid:        func(q firewall.ShaperQueue) string { return q.Uuid },
	description: func(q firewall.ShaperQueue) string { return q.Description },
	enabled:     func(q firewall.ShaperQueue) string { return q.Enabled },
	remove:      (*firewall.FirewallApi).ShaperQueueRemove,
	setEnabled:  (*firewall.FirewallApi).ShaperQueueSetEnabled,
}

func init() {
	var menu = Root.Menu("firewall/shaper/queue")
	menu.Help = "shaper queues: weighted shares of a pipe"
	menu.Add(firewallShaperQueues.commands(
		firewallShaperPrintArgs("queue"), firewallShaperQueuePrint, firewallShaperQueueShow,
		`A queue shares the bandwidth of its pipe with the other queues of the pipe by weight. The description
names the queue (rules refer to it by it): if a queue with the same description exists, add fails unless replace is
given, then that queue is replaced completely (fields not given are reset).

  add pipe="WAN download" weight=80 description="WAN download interactive"`,
		firewallShaperQueueArgs(true), firewallShaperQueueAdd,
		firewallShaperQueueArgs(false), firewallShaperQueueSet,
	)...)
}

func firewallShaperQueueArgs(add bool) []Arg {
	var args = []Arg{
		{Name: "pipe", Required: add, Validate: dnsmasqNotEmpty, Complete: firewallShaperPipes.names,
			Help: "the pipe (description or uuid) the queue shares"},
		{Name: "weight", Type: Int, Validate: ValidateRange(1, 100), Help: "share of the pipe's bandwidth (1-100, default 100)"},
		firewallShaperMaskArg,
		{Name: "buckets", Type: Int, Validate: ValidateRange(1, 65535), Help: "hash table size for the dynamic queues of mask, empty for the default"},
	}
	args = append(args, firewallShaperCodelArgs()...)
	return append(args,
		Arg{Name: "description", Required: add, Validate: dnsmasqNotEmpty, Help: "description, names the queue"},
		Arg{Name: "disabled", Type: Bool, Help: "keep the queue, but don't use it"},
	)
}

var firewallShaperQueueFieldMap = append([]firewallShaperArgField{
	{"weight", "weight", "text"}, {"mask", "mask", "text"}, {"buckets", "buckets", "text"},
	{"description", "description", "text"}, {"disabled", "enabled", "notFlag"},
}, firewallShaperCodelFields...)

// firewallShaperQueueFields returns the arguments as API fields (all for add, the given ones for set), resolving the
// pipe by description or uuid
func firewallShaperQueueFields(api *firewall.FirewallApi, args *Args, onlyGiven bool) (firewall.ShaperFields, error) {
	if err := firewallShaperCheckCodel(args); err != nil {
		return nil, err
	}
	var fields = firewallShaperFields(args, firewallShaperQueueFieldMap, onlyGiven)
	if mask, given := fields["mask"]; given {
		fields["mask"] = strings.ToLower(firewallShaperMaskOrNone(mask))
	}
	if weight, given := fields["weight"]; given && weight == "" {
		fields["weight"] = "100"
	}
	if args.Has("pipe") {
		var pipes, err = api.ShaperPipeList("")
		if err != nil {
			return nil, err
		}
		var options = make([]firewall.ShaperOption, len(pipes))
		for i, pipe := range pipes {
			options[i] = firewall.ShaperOption{Key: pipe.Uuid, Label: pipe.Description}
		}
		pipe, err := firewallShaperResolveOption("pipe", options, args.String("pipe"))
		if err != nil {
			return nil, err
		}
		fields["pipe"] = pipe
	}
	return fields, nil
}

func firewallShaperQueueDetail(queue firewall.ShaperQueue) [][2]string {
	return [][2]string{
		{"uuid", queue.Uuid},
		{"number", queue.Number},
		{"description", queue.Description},
		{"disabled", firewallShaperDisabled(queue.Enabled)},
		{"pipe", firewallShaperLabel(queue.PipeLabel, queue.Pipe)},
		{"weight", queue.Weight},
		{"mask", queue.Mask},
		{"buckets", queue.Buckets},
		{"codel", YesNo(queue.CodelEnable)},
		{"codel-target", queue.CodelTarget},
		{"codel-interval", queue.CodelInterval},
		{"codel-ecn", YesNo(queue.CodelEcnEnable)},
		{"pie", YesNo(queue.PieEnable)},
	}
}

// firewallShaperLabel prefers OPNsense's display text of a reference over the uuid
func firewallShaperLabel(label string, uuid string) string {
	if label != "" {
		return label
	}
	return uuid
}

func firewallShaperQueuePrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	raws, queues, err := api.ShaperQueueListRaw(args.String("search"))
	if err != nil {
		return err
	}
	if args.Bool("json") {
		return firewallShaperPrintJSON(c, raws)
	}
	var uuids = make([]string, len(queues))
	for i, queue := range queues {
		uuids[i] = queue.Uuid
	}
	if args.Bool("detail") {
		var details = make([][][2]string, len(queues))
		for i, queue := range queues {
			details[i] = firewallShaperQueueDetail(queue)
		}
		c.Details(details, uuids)
		return nil
	}
	var rows = make([][]string, len(queues))
	for i, queue := range queues {
		rows[i] = []string{firewallShaperDisabled(queue.Enabled), queue.Number, firewallShaperLabel(queue.PipeLabel, queue.Pipe),
			queue.Weight, queue.Mask, queue.Description}
	}
	c.Items([]string{"DISABLED", "NUMBER", "PIPE", "WEIGHT", "MASK", "DESCRIPTION"}, rows, uuids)
	return nil
}

func firewallShaperQueueShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	queue, _, err := firewallShaperQueues.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	c.Fields(firewallShaperQueueDetail(queue))
	return nil
}

func firewallShaperQueueAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	fields, err := firewallShaperQueueFields(api, args, false)
	if err != nil {
		return err
	}
	var queue = firewall.ShaperQueue{
		Enabled: fields["enabled"], Pipe: fields["pipe"], Weight: fields["weight"], Mask: fields["mask"], Buckets: fields["buckets"],
		CodelEnable: fields["codel_enable"], CodelTarget: fields["codel_target"], CodelInterval: fields["codel_interval"],
		CodelEcnEnable: fields["codel_ecn_enable"], PieEnable: fields["pie_enable"], Description: fields["description"],
	}
	return firewallShaperAdd(c, args.Bool("replace"), "queue", queue.Description,
		func() ([]string, error) {
			return firewallShaperQueues.uuids(api.ShaperQueueFindByDescription(queue.Description))
		},
		func() (string, error) { return api.ShaperQueueCreate(queue) },
		func() (string, bool, error) { return api.ShaperQueueCreateOrUpdate(queue) })
}

func firewallShaperQueueSet(c *Context, args *Args) error {
	if len(args.Given()) <= 1 {
		return errors.New("set: nothing to change, give at least one field like weight= or description= (type \"set ?\" for help)")
	}
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	fields, err := firewallShaperQueueFields(api, args, true)
	if err != nil {
		return err
	}
	queue, queues, err := firewallShaperQueues.selectItem(c, api, args.String("item"))
	if err != nil {
		return err
	}
	if description, renamed := fields["description"]; renamed {
		for _, other := range queues {
			if other.Uuid != queue.Uuid && strings.EqualFold(strings.TrimSpace(other.Description), description) {
				return fmt.Errorf("another queue described %q exists already (%s)", description, other.Uuid)
			}
		}
	}
	return api.ShaperQueueUpdate(queue.Uuid, fields)
}
