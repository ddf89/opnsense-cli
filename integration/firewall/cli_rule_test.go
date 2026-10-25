//go:build integration

package integrationfirewall

import (
	"encoding/json"
	"strings"
	"testing"
)

// ruleCliHarmless are the arguments every rule of the CLI test gets: disabled, LAN, blocking to TEST-NET-2
var ruleCliHarmless = []string{"interface=lan", "action=block", "disabled", "destination=198.51.100.0/24"}

func ruleCliAdd(t *testing.T, description string, extra ...string) string {
	t.Helper()
	var args = append(append([]string{"/firewall/rule", "add", "description=" + description}, ruleCliHarmless...), extra...)
	var added = mustOpn(t, args...)
	var uuid = uuidFrom(t, added)
	if strings.TrimSpace(added.stdout) != uuid {
		t.Errorf("add must print only the uuid:\n%s", added)
	}
	ruleCleanup(t, ruleTestApi(t), uuid)
	return uuid
}

// ruleCliOrder returns the uuids of this run's rules as print json lists them
func ruleCliOrder(t *testing.T) []string {
	t.Helper()
	var printed = mustOpn(t, "/firewall/rule", "print", "json", "automatic=no", "search="+runPrefix)
	var uuids []string
	for _, line := range strings.Split(strings.TrimSpace(printed.stdout), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("print json: %v:\n%s", err, printed)
		}
		uuids = append(uuids, row["uuid"].(string))
	}
	return uuids
}

func TestCliRuleLifecycle(t *testing.T) {
	const menu = "/firewall/rule"
	var description = testDescription("rule-cli")
	var uuid = ruleCliAdd(t, description)

	t.Run("print and show", func(t *testing.T) {
		var printed = mustOpn(t, menu, "print", "search="+description, "interface=LAN")
		requireContains(t, printed, printed.stdout, "DISABLED", "block", "198.51.100.0/24", description)
		if lines := strings.Split(strings.TrimSpace(printed.stdout), "\n"); len(lines) != 2 || !strings.Contains(lines[1], "yes") {
			t.Errorf("want the header and one disabled row:\n%s", printed)
		}
		var shown = mustOpn(t, menu, "show", strings.ToUpper(description))
		requireContains(t, shown, shown.stdout, "uuid:              "+uuid, "automatic:         no", "disabled:          yes",
			"action:            block", "interface:         lan", "destination:       198.51.100.0/24")
	})

	t.Run("set changes only the given fields", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "set", uuid, "protocol=tcp", "destination-port=https", "source=!10.0.0.0/8", "log"))
		var shown = mustOpn(t, menu, "show", uuid)
		requireContains(t, shown, shown.stdout, "protocol:          TCP", "destination-port:  https", "source:            !10.0.0.0/8",
			"log:               yes", "disabled:          yes", "destination:       198.51.100.0/24")

		requireNoStdout(t, mustOpn(t, menu, "set", uuid, "log=no")) // the log switch
		shown = mustOpn(t, menu, "show", uuid)
		requireContains(t, shown, shown.stdout, "log:               no")

		var refused = mustFailOpn(t, menu, "set", uuid, "protocol=any") // the port needs TCP/UDP
		requireContains(t, refused, refused.stderr, "needs protocol TCP")
		refused = mustFailOpn(t, menu, "set", uuid, "interface=a8nonexistent")
		requireContains(t, refused, refused.stderr, "unknown interface")
	})

	t.Run("disable of a disabled rule", func(t *testing.T) {
		var again = mustOpn(t, menu, "disable", description)
		requireContains(t, again, again.stderr, "already disabled")
	})

	t.Run("place-before and move between own rules", func(t *testing.T) {
		var second = ruleCliAdd(t, testDescription("rule-cli second"), "place-before="+description)
		if order := ruleCliOrder(t); len(order) != 2 || order[0] != second || order[1] != uuid {
			t.Errorf("place-before: want %s before %s, got %v", second, uuid, order)
		}
		requireNoStdout(t, mustOpn(t, menu, "move", uuid, "before="+second))
		if order := ruleCliOrder(t); len(order) != 2 || order[0] != uuid || order[1] != second {
			t.Errorf("move: want %s before %s, got %v", uuid, second, order)
		}
	})

	t.Run("add of an existing description needs replace", func(t *testing.T) {
		var refused = mustFailOpn(t, append([]string{menu, "add", "description=" + description}, ruleCliHarmless...)...)
		requireContains(t, refused, refused.stderr, "exists already", uuid)
		var replaced = mustOpn(t, append([]string{menu, "add", "description=" + description, "replace"}, ruleCliHarmless...)...)
		if strings.TrimSpace(replaced.stdout) != uuid {
			t.Errorf("replace must print the uuid of the replaced rule:\n%s", replaced)
		}
		var shown = mustOpn(t, menu, "show", uuid)
		// replaced completely: protocol and ports are back at their defaults, still disabled
		requireContains(t, shown, shown.stdout, "protocol:          any", "destination-port:  \n", "source:            any", "disabled:          yes")
	})

	t.Run("automatic rules can only be shown", func(t *testing.T) {
		var printed = mustOpn(t, menu, "print", "json")
		var automatic string
		for _, line := range strings.Split(strings.TrimSpace(printed.stdout), "\n") {
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) == nil && row["is_automatic"] == true {
				automatic = row["uuid"].(string)
				break
			}
		}
		if automatic == "" {
			t.Skip("no automatic rule listed")
		}
		var shown = mustOpn(t, menu, "show", automatic)
		requireContains(t, shown, shown.stdout, "automatic:         yes")
		for _, command := range [][]string{{"set", automatic, "log"}, {"remove", automatic}, {"disable", automatic}} {
			var refused = mustFailOpn(t, append([]string{menu}, command...)...)
			requireContains(t, refused, refused.stderr, "automatic rule")
		}
	})

	t.Run("remove", func(t *testing.T) {
		requireNoStdout(t, mustOpn(t, menu, "remove", uuid))
		var refused = mustFailOpn(t, menu, "show", uuid)
		requireContains(t, refused, refused.stderr, "not found")
	})
}
