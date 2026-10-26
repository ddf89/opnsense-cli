package cli

import (
	"fmt"
	"sort"
	"strings"
)

// Menu is one level of the command tree, like /dnsmasq/host. It holds sub menus and the commands that can be
// issued at that level. Menus and commands are matched by name or by an unambiguous prefix of it
type Menu struct {
	Name     string
	Help     string
	parent   *Menu
	menus    []*Menu
	commands []*Command
}

// Command is something that can be issued in a menu, like "print" or "add"
type Command struct {
	Name    string
	Aliases []string
	Help    string
	// Long is an optional longer description shown by "<command> ?"
	Long string
	Args []Arg
	// Confirm makes the command dangerous: it only runs after the user confirmed this warning interactively, or
	// with the implicit confirm argument (confirm=yes). It must describe the consequences, e.g. "This reboots the firewall."
	Confirm string
	// ConfirmIf makes the command dangerous depending on the item and the arguments (set lan device=… but not set
	// lan description=…): it runs before Run (after Check, unless confirm=yes is given) and returns the warning
	// for this invocation, "" when it needs no confirmation, or an error (e.g. unknown item) that fails the
	// command before anything is asked. A warning is then confirmed exactly like Confirm. A command sets Confirm
	// or ConfirmIf, not both; ConfirmIf needs ConfirmHelp
	ConfirmIf func(c *Context, args *Args) (string, error)
	// ConfirmHelp tells in the "?" help when ConfirmIf asks and why, e.g. "Asks for confirmation before restarting
	// webgui or configd: that interrupts the management access."; the framework adds that confirm=yes skips it
	ConfirmHelp string
	// Check validates the arguments together (e.g. "timeout only with wait") before a confirmation is asked
	// and before Run; per argument checks belong in Arg.Validate
	Check func(args *Args) error
	Run   func(c *Context, args *Args) error
}

// Root is the top of the command tree, every feature adds its menus and commands to it from an init function
var Root = &Menu{Name: "", Help: "OPNsense command line"}

// Sub returns the sub menu with this name, creating it (with the help text) when it does not exist yet
func (m *Menu) Sub(name string, help string) *Menu {
	for _, sub := range m.menus {
		if sub.Name == name {
			if sub.Help == "" {
				sub.Help = help
			}
			return sub
		}
	}
	var sub = &Menu{Name: name, Help: help, parent: m}
	m.menus = append(m.menus, sub)
	return sub
}

// Menu returns the sub menu at the slash separated path (e.g. "dnsmasq/host") relative to m, creating missing menus
func (m *Menu) Menu(path string) *Menu {
	var menu = m
	for _, name := range strings.Split(strings.Trim(path, "/"), "/") {
		if name != "" {
			menu = menu.Sub(name, "")
		}
	}
	return menu
}

// Add registers commands in the menu. It panics on duplicate names, they are programming errors
func (m *Menu) Add(commands ...*Command) *Menu {
	for _, command := range commands {
		for _, name := range append([]string{command.Name}, command.Aliases...) {
			if m.find(name) != nil {
				panic(fmt.Sprintf("menu %s: duplicate name %q", m.Path(), name))
			}
		}
		if command.ConfirmIf != nil && (command.Confirm != "" || command.ConfirmHelp == "") {
			panic(fmt.Sprintf("menu %s: command %s: ConfirmIf needs ConfirmHelp and excludes Confirm", m.Path(), command.Name))
		}
		if command.Confirm != "" || command.ConfirmIf != nil {
			command.Args = append(command.Args, Arg{Name: confirmArg, Type: Bool, Help: "run without asking for confirmation"})
		}
		m.commands = append(m.commands, command)
	}
	return m
}

// Path returns the menu path like /dnsmasq/host, "/" for the root
func (m *Menu) Path() string {
	if m.parent == nil {
		return "/"
	}
	var names []string
	for menu := m; menu.parent != nil; menu = menu.parent {
		names = append([]string{menu.Name}, names...)
	}
	return "/" + strings.Join(names, "/")
}

// Parent returns the menu above, the root for the root itself
func (m *Menu) Parent() *Menu {
	if m.parent == nil {
		return m
	}
	return m.parent
}

// Menus returns the sub menus sorted by name
func (m *Menu) Menus() []*Menu {
	var menus = append([]*Menu(nil), m.menus...)
	sort.Slice(menus, func(i, j int) bool { return menus[i].Name < menus[j].Name })
	return menus
}

// Commands returns the commands of this menu sorted by name, without the global ones
func (m *Menu) Commands() []*Command {
	var commands = append([]*Command(nil), m.commands...)
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commands
}

// entry is a menu or a command, the things a word in a menu can refer to
type entry struct {
	menu    *Menu
	command *Command
	name    string // the name or alias that matched
}

// find returns the sub menu or command (incl. global commands) with exactly this name or alias
func (m *Menu) find(name string) *entry {
	for _, e := range m.entries() {
		if e.name == name {
			return &e
		}
	}
	return nil
}

// entries lists all names usable in this menu: sub menus, commands, their aliases and the global commands
func (m *Menu) entries() []entry {
	var entries []entry
	for _, sub := range m.menus {
		entries = append(entries, entry{menu: sub, name: sub.Name})
	}
	for _, command := range append(append([]*Command(nil), m.commands...), globalCommands...) {
		for _, name := range append([]string{command.Name}, command.Aliases...) {
			entries = append(entries, entry{command: command, name: name})
		}
	}
	return entries
}

// isGlobal tells whether the entry is one of the global commands (help, exit) available in every menu
func (e entry) isGlobal() bool {
	for _, command := range globalCommands {
		if e.command == command {
			return true
		}
	}
	return false
}

// prefixEntries returns the entries whose name starts with prefix. The entries of the menu itself win over the global
// commands: in /dnsmasq "h" is host, not help, and the global commands only match when nothing of the menu does
func (m *Menu) prefixEntries(prefix string) []entry {
	var local, global []entry
	for _, e := range m.entries() {
		switch {
		case !strings.HasPrefix(e.name, prefix):
		case e.isGlobal():
			global = append(global, e)
		default:
			local = append(local, e)
		}
	}
	if len(local) > 0 {
		return local
	}
	return global
}

// lookup resolves a word to a sub menu or command: an exact name, or else an unambiguous prefix of one name (see
// prefixEntries)
func (m *Menu) lookup(word string) (*entry, error) {
	if e := m.find(word); e != nil {
		return e, nil
	}
	var matches []entry
	var seen = map[any]bool{}
	for _, e := range m.prefixEntries(word) {
		var key any = e.menu
		if e.command != nil {
			key = e.command
		}
		if !seen[key] {
			seen[key] = true
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 1:
		return &matches[0], nil
	case 0:
		return nil, fmt.Errorf("no such menu or command in %s: %q, type ? for help", m.Path(), word)
	default:
		var names = make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, match.name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%q is ambiguous in %s: %s", word, m.Path(), strings.Join(names, ", "))
	}
}
