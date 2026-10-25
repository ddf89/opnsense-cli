package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

type testItem struct{ uuid, name string }

// newTestSession builds a private menu tree (not Root) with recording commands
func newTestSession(t *testing.T) (*Session, *bytes.Buffer, *[]string) {
	t.Helper()
	var root = &Menu{Help: "test root"}
	var calls []string
	var record = func(c *Context, args *Args) error {
		var parts = []string{c.Menu.Path()}
		for _, name := range args.Given() {
			parts = append(parts, name+"="+args.String(name))
		}
		calls = append(calls, strings.Join(parts, " "))
		return nil
	}
	var items = []testItem{{"u-0", "web.example.lan"}, {"u-1", "mail.example.lan"}, {"u-2", "dup"}, {"u-3", "dup"}}
	var host = root.Menu("dnsmasq/host")
	host.Help = "host overrides"
	host.Add(
		&Command{Name: "print", Help: "list", Args: []Arg{{Name: "detail", Type: Bool}, {Name: "search"}}, Run: func(c *Context, args *Args) error {
			var rows [][]string
			var uuids []string
			// printed in reverse, so print order differs from list order
			for i := len(items) - 1; i >= 0; i-- {
				rows = append(rows, []string{items[i].name})
				uuids = append(uuids, items[i].uuid)
			}
			c.Items([]string{"NAME"}, rows, uuids)
			return nil
		}},
		&Command{Name: "add", Help: "add", Args: []Arg{
			{Name: "host", Required: true, Complete: func(*Context) []string { return []string{"my host"} }},
			{Name: "ip", Type: List},
			{Name: "local", Type: Bool},
			{Name: "lease-time", Type: Int},
			{Name: "rr", Values: []string{"A", "AAAA"}},
			{Name: "interval", Type: Duration, Default: "1s"},
		}, Run: record},
		&Command{Name: "remove", Aliases: []string{"rm"}, Help: "remove", Args: []Arg{{Name: "item", Positional: true, Required: true,
			Complete: func(*Context) []string { return []string{"web.example.lan", "mail.example.lan"} }}}, Run: func(c *Context, args *Args) error {
			var item, err = Select(c, args.String("item"), items, func(i testItem) string { return i.uuid }, func(i testItem) []string { return []string{i.name} })
			if err != nil {
				return err
			}
			calls = append(calls, "removed "+item.uuid)
			return nil
		}},
		&Command{Name: "reset", Help: "dangerous", Confirm: "This wipes everything.", Args: []Arg{{Name: "keep", Type: Bool}, {Name: "what"}},
			Check: func(args *Args) error {
				if args.Has("what") && !args.Bool("keep") {
					return errors.New("what only together with keep")
				}
				return nil
			}, Run: record},
	)
	root.Menu("dnsmasq/domain").Add(&Command{Name: "print", Help: "list", Run: record})
	root.Menu("diag").Add(&Command{Name: "follow", Help: "until cancelled", Run: func(c *Context, args *Args) error {
		<-c.Done()
		calls = append(calls, "cancelled")
		return nil
	}})

	var out bytes.Buffer
	var session = NewSession(&out, &out)
	session.root, session.cwd = root, root
	session.Configure = func() (*coreapi.OPNsense, error) { return nil, errors.New("no api in tests") }
	return session, &out, &calls
}

func TestSplitLine(t *testing.T) {
	for line, want := range map[string][]string{
		`  /dnsmasq host  print `:            {"/dnsmasq", "host", "print"},
		`add txtdata="v=spf1 -all" ttl=60`:   {"add", "txtdata=v=spf1 -all", "ttl=60"},
		`set description='it''s'`:            {"set", "description=its"},
		`set description="say \"hi\" \\ ok"`: {"set", `description=say "hi" \ ok`},
		`# a comment`:                        nil,
		`add host=""`:                        {"add", "host="},
	} {
		var words, err = SplitLine(line)
		if err != nil || !reflect.DeepEqual(words, want) {
			t.Errorf("SplitLine(%q) = %q, %v; want %q", line, words, err, want)
		}
	}
	if _, err := SplitLine(`add host="open`); err == nil {
		t.Errorf("unterminated quote must fail")
	}
}

func TestNavigationAndPrefixes(t *testing.T) {
	var session, _, calls = newTestSession(t)
	for _, step := range []struct{ line, cwd string }{
		{"/dnsmasq/host", "/dnsmasq/host"},
		{"..", "/dnsmasq"},
		{"ho", "/dnsmasq/host"},
		{"/", "/"},
		{"dns dom", "/dnsmasq/domain"},
		{"../host", "/dnsmasq/host"},
		{"/diag", "/diag"},
	} {
		if err := session.ExecuteLine(step.line); err != nil {
			t.Fatalf("%q: %v", step.line, err)
		}
		if got := session.Cwd().Path(); got != step.cwd {
			t.Errorf("after %q: cwd %s, want %s", step.line, got, step.cwd)
		}
	}

	// commands run in the menu they were given in, the current menu stays
	for _, line := range []string{"/dnsmasq domain print", "/dnsmasq/domain pr", "../dnsmasq/do pr"} {
		if err := session.ExecuteLine(line); err != nil {
			t.Errorf("%q: %v", line, err)
		}
	}
	if session.Cwd().Path() != "/diag" {
		t.Errorf("running a command elsewhere must not navigate, cwd %s", session.Cwd().Path())
	}
	if len(*calls) != 3 || (*calls)[0] != "/dnsmasq/domain" {
		t.Errorf("calls %q", *calls)
	}

	for line, want := range map[string]string{
		"/nope":               "no such menu or command",
		"/dnsmasq/host/x":     "no such menu or command",
		"/dnsmasq/host/add/x": "is a command, not a menu",
		"/d":                  "ambiguous",
	} {
		if err := session.ExecuteLine(line); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", line, err, want)
		}
	}
}

func TestArgs(t *testing.T) {
	var session, _, calls = newTestSession(t)
	var ok = map[string]string{
		"/dnsmasq/host add host=web":                                         "/dnsmasq/host host=web",
		"/dnsmasq/host add host=web ip=10.0.0.1,fd00::1 local lease-time=60": "/dnsmasq/host host=web ip=10.0.0.1,fd00::1 lease-time=60 local=yes",
		"/dnsmasq/host add ho=web loc=no rr=aaaa interval=2":                 "/dnsmasq/host host=web interval=2 local=no rr=aaaa",
		"/dnsmasq/host add host=web ip=":                                     "/dnsmasq/host host=web ip=",
	}
	for line, want := range ok {
		*calls = nil
		if err := session.ExecuteLine(line); err != nil {
			t.Errorf("%q: %v", line, err)
			continue
		}
		if len(*calls) != 1 || (*calls)[0] != want {
			t.Errorf("%q: calls %q, want %q", line, *calls, want)
		}
	}

	for line, want := range map[string]string{
		"/dnsmasq/host add":                         "host=<string> is required",
		"/dnsmasq/host add host=a nope=1":           `unknown argument "nope"`,
		"/dnsmasq/host add host=a l=1":              "ambiguous",
		"/dnsmasq/host add host=a host=b":           "given twice",
		"/dnsmasq/host add host=a local=maybe":      "must be yes or no",
		"/dnsmasq/host add host=a lease-time=soon":  "must be a number",
		"/dnsmasq/host add host=a rr=MX":            "must be one of A, AAAA",
		"/dnsmasq/host add host=a interval=forever": "must be a duration",
		"/dnsmasq/host add host=a stray":            `unexpected "stray"`,
	} {
		*calls = nil
		if err := session.ExecuteLine(line); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", line, err, want)
		}
		if len(*calls) != 0 {
			t.Errorf("%q must not run", line)
		}
	}
}

func TestArgsGetters(t *testing.T) {
	var command = &Command{Name: "x", Args: []Arg{
		{Name: "s", Default: "dflt"}, {Name: "b", Type: Bool}, {Name: "i", Type: Int, Default: "5"},
		{Name: "d", Type: Duration, Default: "1m"}, {Name: "l", Type: List},
	}}
	var args, err = parseArgs(command, []string{"b=on", "d=1.5", "l= a, ,b "})
	if err != nil {
		t.Fatal(err)
	}
	if args.String("s") != "dflt" || args.Has("s") || !args.Bool("b") || args.Int("i") != 5 ||
		args.Duration("d").String() != "1.5s" || !reflect.DeepEqual(args.List("l"), []string{"a", "b"}) || !args.Has("l") {
		t.Errorf("getters: s=%q b=%v i=%d d=%s l=%q", args.String("s"), args.Bool("b"), args.Int("i"), args.Duration("d"), args.List("l"))
	}
}

func TestSelect(t *testing.T) {
	var session, _, calls = newTestSession(t)
	var run = func(line string) error {
		*calls = nil
		return session.ExecuteLine(line)
	}

	// without a print the index is the list position
	if err := run("/dnsmasq/host remove 1"); err != nil || (*calls)[0] != "removed u-1" {
		t.Errorf("index without print: %v %q", err, *calls)
	}
	// after a print the index refers to the printed rows (printed in reverse)
	if err := run("/dnsmasq/host print"); err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{
		"/dnsmasq/host remove 1":                "removed u-2",
		"/dnsmasq/host rm item=0":               "removed u-3",
		"/dnsmasq/host remove U-1":              "removed u-1",
		"/dnsmasq/host remove WEB.example.lan.": "removed u-0",
	} {
		if err := run(line); err != nil || len(*calls) != 1 || (*calls)[0] != want {
			t.Errorf("%q: %v %q, want %q", line, err, *calls, want)
		}
	}

	var notFound *coreapi.NotFoundError
	if err := run("/dnsmasq/host remove 9"); !errors.As(err, &notFound) {
		t.Errorf("index out of range: %v", err)
	}
	if err := run("/dnsmasq/host remove nope"); !errors.As(err, &notFound) {
		t.Errorf("unknown name: %v", err)
	}
	var tooMany *coreapi.TooManyFoundError
	if err := run("/dnsmasq/host remove dup"); !errors.As(err, &tooMany) || !strings.Contains(err.Error(), "u-2, u-3") {
		t.Errorf("ambiguous name: %v", err)
	}
}

func TestConfirm(t *testing.T) {
	var session, _, calls = newTestSession(t)
	if err := session.ExecuteLine("/dnsmasq/host reset"); err == nil || !strings.Contains(err.Error(), "confirm=yes") || len(*calls) != 0 {
		t.Errorf("non-interactive without confirm: %v %q", err, *calls)
	}
	if err := session.ExecuteLine("/dnsmasq/host reset confirm"); err != nil || len(*calls) != 1 {
		t.Errorf("confirm flag: %v %q", err, *calls)
	}

	// Check runs before the confirmation question
	session.Ask = func(string) (bool, error) {
		t.Errorf("asked although Check failed")
		return true, nil
	}
	if err := session.ExecuteLine("/dnsmasq/host reset what=x"); err == nil || !strings.Contains(err.Error(), "reset: what only together with keep") {
		t.Errorf("Check: %v", err)
	}

	var asked []string
	var answer bool
	session.Ask = func(question string) (bool, error) {
		asked = append(asked, question)
		return answer, nil
	}
	*calls = nil
	if err := session.ExecuteLine("/dnsmasq/host reset"); !errors.Is(err, ErrCancelled) || len(*calls) != 0 {
		t.Errorf("declined: %v %q", err, *calls)
	}
	answer = true
	if err := session.ExecuteLine("/dnsmasq/host reset"); err != nil || len(*calls) != 1 {
		t.Errorf("confirmed: %v %q", err, *calls)
	}
	if len(asked) != 2 || !strings.Contains(asked[0], "This wipes everything.") {
		t.Errorf("questions %q", asked)
	}
}

func TestRunCancelsOnInterrupt(t *testing.T) {
	var session, _, calls = newTestSession(t)
	session.Run = func(run func(ctx context.Context) error) error {
		var ctx, cancel = context.WithCancel(context.Background())
		cancel() // Ctrl-C right away
		return run(ctx)
	}
	if err := session.ExecuteLine("/diag follow"); err != nil || (*calls)[0] != "cancelled" {
		t.Errorf("%v %q", err, *calls)
	}
}

func TestHelp(t *testing.T) {
	var session, out, _ = newTestSession(t)
	for line, want := range map[string][]string{
		"?":                      {"test root", "dnsmasq", "diag", "import"[:0]},
		"/dnsmasq/host ?":        {"/dnsmasq/host: host overrides", "commands:", "add", "remove", "print"},
		"/dnsmasq/host add ?":    {"/dnsmasq/host add", "host=<string>", "required", "ip=<list>", "local[=yes|no]", "rr=A|AAAA", "default 1s"},
		"/dnsmasq/host remove ?": {"may be given without name", "aliases: rm"},
		"/dnsmasq/host reset ?":  {"This wipes everything.", "confirm[=yes|no]"},
		"/dnsmasq/host help":     {"/dnsmasq/host: host overrides"},
	} {
		out.Reset()
		if err := session.ExecuteLine(line); err != nil {
			t.Errorf("%q: %v", line, err)
		}
		for _, w := range want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%q: help lacks %q:\n%s", line, w, out.String())
			}
		}
	}
}

func TestComplete(t *testing.T) {
	var session, _, _ = newTestSession(t)
	for line, want := range map[string][]string{
		"":                                      {"diag", "dnsmasq"},
		"e":                                     {"exit"},
		"/dnsmasq/host e":                       {"exit"},
		"/dn":                                   {"/dnsmasq"},
		"/dnsmasq/h":                            {"/dnsmasq/host"},
		"/dnsmasq/he":                           {"/dnsmasq/help"},
		"dnsmasq ":                              {"domain", "host"},
		"/dnsmasq host a":                       {"add"},
		"/dnsmasq host add ":                    {"host=", "interval=", "ip=", "lease-time=", "local", "rr="},
		"/dnsmasq host add host=x l":            {"lease-time=", "local"},
		"/dnsmasq host add rr=a":                {"rr=A", "rr=AAAA"},
		"/dnsmasq host add local=":              {"local=no", "local=yes"},
		"/dnsmasq host print detail ":           {"search="},
		"/dnsmasq host remove w":                {"web.example.lan"},
		"/dnsmasq host remove ":                 {"item=", "mail.example.lan", "web.example.lan"},
		"/dnsmasq host remove web.example.lan ": nil,
		"/dnsmasq host remove item=m":           {"item=mail.example.lan"},
		"/dnsmasq host add rr=AAAA host=\"my h": {`host="my host"`},
	} {
		var got, _ = session.Complete(line)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Complete(%q) = %q, want %q", line, got, want)
		}
	}
	if got, start := session.Complete("/dnsmasq host add rr=a"); start != len("/dnsmasq host add ") {
		t.Errorf("start %d for %q", start, got)
	}
	if got, start := session.Complete(`/dnsmasq host add host="my h`); start != len("/dnsmasq host add ") || len(got) != 1 {
		t.Errorf("quoted partial: start %d, %q", start, got)
	}
	if quoteValue("a b") != `"a b"` || quoteValue(`say "hi"`) != `"say \"hi\""` || quoteValue("plain") != "plain" {
		t.Errorf("quoteValue")
	}
	if commonPrefix([]string{"rr=A", "rr=AAAA"}) != "rr=A" {
		t.Errorf("commonPrefix")
	}
}

func TestRunScript(t *testing.T) {
	var session, _, calls = newTestSession(t)
	var script = "# setup\n/dnsmasq/host\nadd host=a\n\n  add host=\"b c\"\n/dnsmasq domain print\n"
	if err := session.RunScript(strings.NewReader(script), "s.rsc"); err != nil {
		t.Fatal(err)
	}
	var want = []string{"/dnsmasq/host host=a", "/dnsmasq/host host=b c", "/dnsmasq/domain"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("calls %q, want %q", *calls, want)
	}

	var err = session.RunScript(strings.NewReader("/dnsmasq/host\nadd host=a\nadd\nadd host=never"), "s.rsc")
	if err == nil || !strings.Contains(err.Error(), "s.rsc:3:") {
		t.Errorf("error with line number: %v", err)
	}
	if err := session.RunScript(strings.NewReader("exit\n/nope"), "s.rsc"); err != nil {
		t.Errorf("exit ends a script: %v", err)
	}
}

func TestItemsAndFieldsOutput(t *testing.T) {
	var session, out, _ = newTestSession(t)
	if err := session.ExecuteLine("/dnsmasq/host print"); err != nil {
		t.Fatal(err)
	}
	var lines = strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "#  NAME") || !strings.HasPrefix(lines[1], "0  dup") || !strings.HasPrefix(lines[4], "3  web.example.lan") {
		t.Errorf("print output:\n%s", out.String())
	}
	if YesNo("1") != "yes" || YesNo("0") != "no" || YesNo("") != "no" || Flag(true) != "1" || Flag(false) != "0" {
		t.Errorf("YesNo/Flag")
	}
}

func TestGlobalCommandsDoNotShadowMenuEntries(t *testing.T) {
	var session, out, _ = newTestSession(t)
	// in /dnsmasq "h" is the host menu, not the global help, and "e" (no entry of the menu) is still exit
	for _, step := range []struct{ line, cwd string }{
		{"/dnsmasq", "/dnsmasq"},
		{"h", "/dnsmasq/host"},
		{"/dnsmasq/h", "/dnsmasq/host"},
	} {
		if err := session.ExecuteLine(step.line); err != nil {
			t.Fatalf("%q: %v", step.line, err)
		}
		if got := session.Cwd().Path(); got != step.cwd {
			t.Errorf("after %q: cwd %s, want %s", step.line, got, step.cwd)
		}
	}
	if err := session.ExecuteLine("e"); !errors.Is(err, errExit) {
		t.Errorf("e is exit when the menu has no e: %v", err)
	}
	out.Reset()
	if err := session.ExecuteLine("/dnsmasq he"); err != nil || !strings.Contains(out.String(), "host    host overrides") {
		t.Errorf("he is help: %v\n%s", err, out.String())
	}
}

func TestSelectMessages(t *testing.T) {
	var session, _, _ = newTestSession(t)
	for line, want := range map[string]string{
		"/dnsmasq/host remove 7": "item #7, the list has 4 items",
	} {
		if err := session.ExecuteLine(line); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", line, err, want)
		}
	}
	if itemCount(1) != "1 item" || itemCount(0) != "0 items" || itemCount(2) != "2 items" {
		t.Errorf("itemCount")
	}
}

func TestHelpFormatting(t *testing.T) {
	var root = &Menu{}
	root.Menu("system").Add(&Command{Name: "reboot", Help: "reboot",
		Confirm: strings.Repeat("This is a long warning sentence. ", 8),
		Args:    []Arg{{Name: "timeout", Type: Duration, Default: "10m0s"}, {Name: "poll", Type: Duration, Default: "1h0m0s"}}})
	var out bytes.Buffer
	var session = NewSession(&out, &out)
	session.root, session.cwd = root, root
	if err := session.ExecuteLine("/system reboot ?"); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if len(line) > helpWidth {
			t.Errorf("help line longer than %d: %q", helpWidth, line)
		}
	}
	wantContains(t, "help", out.String(), "(default 10m)", "(default 1h)", "It asks for confirmation")
	if wrapText("a b c", 3) != "a b\nc" {
		t.Errorf("wrapText: %q", wrapText("a b c", 3))
	}
}
