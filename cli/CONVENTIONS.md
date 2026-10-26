# Menu CLI conventions

`opn` is a menu driven CLI in the style of MikroTik RouterOS (with a bit of Junos): commands live in a tree of
menus (`/dnsmasq/host`), can be issued from anywhere with a path (`/dnsmasq host print`, `dnsmasq/host print`,
`../domain print`) and take `name=value` arguments. Without arguments `opn` is an interactive shell (TAB
completion, `?` help, history, Ctrl-C cancels a running command), with arguments it runs one command, and with
stdin not a terminal it runs a script (one command line per line, a menu path alone changes the menu).

The framework is in `menu.go`, `args.go`, `exec.go`, `context.go`, `select.go`, `complete.go`, `shell.go`,
`main.go`, `validate.go`. Features register their menus from an `init()` in their own files.

## Registering

```go
func init() {
	var menu = Root.Menu("dnsmasq/host")
	menu.Help = "host overrides and static DHCP reservations"
	menu.Add(&Command{Name: "print", Help: "...", Args: []Arg{...}, Run: dnsmasqHostPrint})
}
```

Menu and command names are lower case, multi word names use dashes (`host-override`, `monitor-traffic`).

## Commands of an item menu

| command | arguments | does |
|---|---|---|
| `print` | `detail` (flag), `json` (flag), `search=` | list as a table with a `#` column (`c.Items`), `detail`: numbered blocks (`c.Details`), `json`: one raw JSON object per line (`c.JSON`) |
| `show` | item (positional) | one item as `name: value` lines (`c.Fields`) |
| `add` | field args, `replace` (flag) | create; fails when an item with the same natural key exists unless `replace` is given (then it replaces that item completely, like the old create). Prints the new uuid on stdout |
| `set` | item (positional) + field args | change only the given fields (`args.Has`), fails for unknown items |
| `remove` | item (positional) | delete |
| `enable` / `disable` | item (positional) | where the API has an enabled flag |

Service like menus have plain verb commands: `status`, `start`, `stop`, `restart`, `reconfigure`.

- The item argument is named `item`, `Positional: true`, `Required: true` and resolved with `Select(c, selector,
  items, uuidOf, namesOf)`: `#` index of the last print in this menu (or the list position when there was no
  print), uuid, or a natural name (state which in the arg help, e.g. "the #, uuid or FQDN host.domain").
  `print` must call `c.Items`/`c.Details` with the uuids in the printed order; without a filter print shows the
  list in API order so one-shot indexes match.
- Field arguments are kebab-case (`lease-time`, `client-id`, `source-ip`), booleans are `Type: Bool` (`local`,
  `local=no`), lists are `Type: List` (comma separated, `ip=10.0.0.1,fd00::1`, `ip=` clears).
- The on/off state of an item is a RouterOS style `disabled` argument (`add … disabled`, `set 0 disabled=no`),
  shown as a DISABLED column in print and a `disabled:` field in show; `enable`/`disable` commands toggle it.
- Give the item argument a `Complete` function returning the item names, TAB then completes `remove we<TAB>`.
- Rules that involve several arguments ("timeout only with wait") go into `Command.Check`, which runs before a
  confirmation is asked.
- Validate everything you can in the argument spec (`Values`, `Validate: ValidateIP`, `ValidatePort`,
  `ValidateRange(…)`, `ValidateMACList`, …) so nothing is sent for invalid input.

## Output

- Data goes to `c.Out` (`c.Println`, `c.Printf`, `c.Items`, `c.Fields`, `c.JSON`), messages (progress, hints,
  warnings) to `c.ErrOut` via `c.Infof`. `*Context` is a `context.Context`, pass `c` to follow/stream functions. Never write to os.Stdout/os.Stderr, never use `log` or `os.Exit`.
- Mutations are silent on success like RouterOS, except `add` which prints the new uuid.
- `json` output is ndjson, one compact object per line, the raw API objects where there are such.

## Errors

Return errors, the framework prints `error: …` (exit 1 for one-shot and scripts, the shell continues). Wrap
`*NotFoundError` / `*TooManyFoundError` from the API layer as they are, they read well.

## Long running commands

`follow`, `monitor-traffic` and other streaming commands run until `c.Done()` (Ctrl-C) and then return nil. They
must not exit the shell. Use `c.Interactive()` only for cosmetics.

## Dangerous commands

Set `Command.Confirm` to a sentence describing the consequence ("This reboots the firewall."). The framework
adds a `confirm` flag, asks `[y/N]` in the shell and refuses to run non-interactively without `confirm=yes`.

When the danger depends on the item or the arguments (`set lan device=…` but not `set lan description=…`, the
restart of webgui but not of unbound), set `Command.ConfirmIf` instead: it runs after `Check` and before `Run`
(skipped with `confirm=yes`), resolves what it needs and returns the warning sentence for this invocation, `""`
when it is harmless, or an error (unknown item, locked service, …) that fails before anything is asked. A warning
is confirmed exactly like `Confirm`. `ConfirmHelp` is required with it and tells in the `?` help when it asks
("Asks for confirmation before restarting webgui, configd …: that interrupts the management access."). Prefer it over refusing in `Run` with a
hand made `confirm` argument, and over a static `Confirm` for commands that resolve an item: a bad `#` then
fails before the question. `Run` must not rely on `ConfirmIf` having run.

## Tests

Black-box tests in `<area>_test.go` use the harness in `fakeopn_test.go`: `f := newFakeOPN(t)`, canned answers
with `f.on`/`f.search`/`f.stream`, then `f.run("/dnsmasq", "host", "add", "host=web", "ip=10.0.0.5")` (each
argument one word, as the shell would split it) or `f.runScript("…lines…")`, and assert with `wantExit`,
`wantFailure`, `wantNoMutations`, `wantOneMutation`, `wantJSON`. Prefix every package level identifier of a
feature with its area (`dnsmasqHost…`, `TestDnsmasqHost…`) – all features share package `cli`.
