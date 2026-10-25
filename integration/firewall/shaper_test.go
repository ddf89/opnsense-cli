//go:build integration

package integrationfirewall

import (
	"errors"
	"strings"
	"testing"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
)

// Shaper records created here are always disabled, rules only match documentation networks (192.0.2.0/24,
// 198.51.100.0/24) on lan, and nothing is ever applied (no reconfigure, no flush)

// shaperRawRows returns the raw search rows of a shaper kind (pipes, queues, rules) with this uuid
func shaperRawRows(t *testing.T, core *api.OPNsense, kind string, uuid string) []map[string]any {
	t.Helper()
	var rows, err = api.Search[map[string]any](core, core.EndpointForModule("trafficshaper/settings/search_"+kind+"s"), "")
	if err != nil {
		t.Fatalf("raw search of %ss: %v", kind, err)
	}
	return api.Filter(rows, func(row map[string]any) bool { return row["uuid"] == uuid })
}

// shaperCleanup removes the record when the test ends (when it still exists) and checks it is gone. Register pipes
// first, then queues, then rules: cleanups run in reverse order, rules before queues before pipes
func shaperCleanup(t *testing.T, core *api.OPNsense, kind string, uuid string) {
	t.Cleanup(func() {
		if len(shaperRawRows(t, core, kind, uuid)) > 0 {
			if _, err := core.Mutate(core.EndpointForModule("trafficshaper/settings/del_"+kind+"/"+uuid), nil); err != nil {
				t.Errorf("removing shaper %s %s: %v", kind, uuid, err)
			}
		}
		if len(shaperRawRows(t, core, kind, uuid)) > 0 {
			t.Errorf("shaper %s %s still exists", kind, uuid)
		}
	})
}

func TestShaperLifecycle(t *testing.T) {
	var core = coreApi(t)
	var fw = &firewall.FirewallApi{OPNsense: core}
	var pipeDescription, queueDescription, ruleDescription = testDescription("shaper-lib-pipe"), testDescription("shaper-lib-queue"),
		testDescription("shaper-lib-rule")

	pipe, err := fw.ShaperPipeCreate(firewall.ShaperPipe{Enabled: "0", Bandwidth: "1", BandwidthMetric: "Mbit", Description: pipeDescription})
	if err != nil {
		t.Fatalf("ShaperPipeCreate: %v", err)
	}
	shaperCleanup(t, core, "pipe", pipe)
	queue, err := fw.ShaperQueueCreate(firewall.ShaperQueue{Enabled: "0", Pipe: pipe, Weight: "10", Description: queueDescription})
	if err != nil {
		t.Fatalf("ShaperQueueCreate: %v", err)
	}
	shaperCleanup(t, core, "queue", queue)

	options, err := fw.ShaperRuleOptions()
	if err != nil {
		t.Fatalf("ShaperRuleOptions: %v", err)
	}
	var targets = map[string]string{}
	for _, option := range options.Targets {
		targets[option.Key] = option.Label
	}
	if targets[pipe] != pipeDescription || targets[queue] != queueDescription || options.NextSequence == "" {
		t.Errorf("the rule options lack the new pipe / queue: %+v", options)
	}

	rule, err := fw.ShaperRuleCreate(firewall.ShaperRule{Enabled: "0", Sequence: options.NextSequence, Interface: "lan", Proto: "tcp",
		Source: "192.0.2.0/24", Destination: "198.51.100.0/24", DstPort: "1000-2000", Dscp: "ef", Direction: "in", Target: queue,
		Description: ruleDescription})
	if err != nil {
		t.Fatalf("ShaperRuleCreate: %v", err)
	}
	shaperCleanup(t, core, "rule", rule)

	// read back
	gotPipe, err := fw.ShaperPipeGet(pipe)
	if err != nil || gotPipe.Enabled != "0" || gotPipe.Bandwidth != "1" || gotPipe.BandwidthMetric != "Mbit" || gotPipe.Number == "" ||
		gotPipe.Origin != "TrafficShaper" || gotPipe.Mask != "none" {
		t.Errorf("pipe: %+v / %v", gotPipe, err)
	}
	gotQueue, err := fw.ShaperQueueGet(queue)
	if err != nil || gotQueue.Pipe != pipe || gotQueue.PipeLabel != pipeDescription || gotQueue.Weight != "10" || gotQueue.Enabled != "0" {
		t.Errorf("queue: %+v / %v", gotQueue, err)
	}
	gotRule, err := fw.ShaperRuleGet(rule)
	if err != nil || gotRule.Target != queue || gotRule.TargetLabel != queueDescription || gotRule.Interface != "lan" ||
		gotRule.DstPort != "1000-2000" || gotRule.SrcPort != "any" || gotRule.Enabled != "0" || gotRule.Direction != "in" {
		t.Errorf("rule: %+v / %v", gotRule, err)
	}
	if found, err := fw.ShaperQueueFindByDescription(strings.ToUpper(queueDescription)); err != nil || len(found) != 1 || found[0].Uuid != queue {
		t.Errorf("FindByDescription: %+v / %v", found, err)
	}

	// partial updates keep the other fields
	if err := fw.ShaperPipeUpdate(pipe, firewall.ShaperFields{"bandwidth": "512", "bandwidthMetric": "Kbit"}); err != nil {
		t.Fatalf("ShaperPipeUpdate: %v", err)
	}
	if gotPipe, _ = fw.ShaperPipeGet(pipe); gotPipe.Bandwidth != "512" || gotPipe.BandwidthMetric != "Kbit" || gotPipe.Enabled != "0" ||
		gotPipe.Description != pipeDescription {
		t.Errorf("after update: %+v", gotPipe)
	}
	err = fw.ShaperPipeUpdate(pipe, firewall.ShaperFields{"bandwidth": "5", "bandwidthMetric": "Gbit"})
	var validation *api.ValidationError
	if !errors.As(err, &validation) || !strings.Contains(validation.Validations["pipe.bandwidth"], "exceeds the maximum bandwidth") {
		t.Errorf("want OPNsense's maximum bandwidth validation, got %v", err)
	}

	// set_rule/<unknown uuid> with a complete body would create a rule, the library refuses
	const ghost = "0f0f0f0f-1111-4222-8333-a8f0a8f0a8f0"
	err = fw.ShaperRuleUpdate(ghost, firewall.ShaperFields{"enabled": "0", "interface": "lan", "source": "192.0.2.1", "target": queue,
		"description": testDescription("shaper-ghost")})
	if !api.IsNotFound(err) {
		t.Errorf("update of an unknown uuid: want NotFoundError, got %v", err)
	}
	if rows := shaperRawRows(t, core, "rule", ghost); len(rows) != 0 {
		t.Errorf("the update of an unknown uuid created %v", rows)
	}

	// referenced pipes and queues can not be removed
	if err := fw.ShaperPipeRemove(pipe); err == nil || !strings.Contains(err.Error(), "in use by") || !strings.Contains(err.Error(), queue) {
		t.Errorf("removing a pipe in use: %v", err)
	}
	if err := fw.ShaperQueueRemove(queue); err == nil || !strings.Contains(err.Error(), "in use by") || !strings.Contains(err.Error(), rule) {
		t.Errorf("removing a queue in use: %v", err)
	}

	// replace by description, keeping it disabled
	replaced, wasReplaced, err := fw.ShaperQueueCreateOrUpdate(firewall.ShaperQueue{Enabled: "0", Pipe: pipe, Weight: "20", Description: queueDescription})
	if err != nil || replaced != queue || !wasReplaced {
		t.Errorf("CreateOrUpdate: %q %v %v", replaced, wasReplaced, err)
	}

	// toggling to the current state answers unchanged (enabling is never done live)
	if changed, err := fw.ShaperRuleSetEnabled(rule, false); err != nil || changed {
		t.Errorf("SetEnabled(false): %v %v", changed, err)
	}
	if _, err := fw.ShaperPipeSetEnabled(ghost, false); !api.IsNotFound(err) {
		t.Errorf("toggle of an unknown uuid: want NotFoundError, got %v", err)
	}

	if _, err := fw.ShaperStatisticsGet(); err != nil {
		t.Errorf("ShaperStatisticsGet: %v", err)
	}

	for _, remove := range []struct {
		kind, uuid string
		call       func(string) error
	}{{"rule", rule, fw.ShaperRuleRemove}, {"queue", queue, fw.ShaperQueueRemove}, {"pipe", pipe, fw.ShaperPipeRemove}} {
		if err := remove.call(remove.uuid); err != nil {
			t.Fatalf("removing %s: %v", remove.kind, err)
		}
		if rows := shaperRawRows(t, core, remove.kind, remove.uuid); len(rows) != 0 {
			t.Errorf("%s still there after remove: %v", remove.kind, rows)
		}
		if err := remove.call(remove.uuid); !api.IsNotFound(err) {
			t.Errorf("second remove of the %s: want NotFoundError, got %v", remove.kind, err)
		}
	}
}
