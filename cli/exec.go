package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// errExit is returned by the exit command to end the shell or a script
var errExit = errors.New("exit")

// ErrCancelled is returned when the user did not confirm a dangerous command
var ErrCancelled = errors.New("cancelled")

// globalCommands can be used in every menu
var globalCommands = []*Command{
	{Name: "help", Help: "show the menus and commands of the current menu (same as ?)"},
	{Name: "exit", Aliases: []string{"quit"}, Help: "leave the shell"},
}

// resolved is a parsed command line: the menu it ends in, the command (nil for a plain menu path) and its words
type resolved struct {
	menu    *Menu
	command *Command
	args    []string
	help    bool // a "?" was given: show help instead of running
	walked  bool // the line contained a menu path
}

// resolve walks the words of a line: menu names (or "/" for the root, ".." for the parent, also written like
// /dnsmasq/host) until a command, then the arguments of the command. Names may be abbreviated
func (s *Session) resolve(words []string) (*resolved, error) {
	var r = &resolved{menu: s.cwd}
	for i := 0; i < len(words); i++ {
		var word = words[i]
		if word == "?" {
			r.help = true
			continue
		}
		if strings.HasPrefix(word, "/") {
			r.menu, r.walked = s.root, true
		}
		var segments = strings.Split(word, "/")
		for j, segment := range segments {
			switch segment {
			case "":
				continue
			case "..":
				r.menu, r.walked = r.menu.Parent(), true
				continue
			}
			var e, err = r.menu.lookup(segment)
			if err != nil {
				return nil, err
			}
			if e.menu != nil {
				r.menu, r.walked = e.menu, true
				continue
			}
			if j != len(segments)-1 {
				return nil, fmt.Errorf("%s is a command, not a menu", segment)
			}
			r.command = e.command
			for _, arg := range words[i+1:] {
				if arg == "?" {
					r.help = true
				} else {
					r.args = append(r.args, arg)
				}
			}
			return r, nil
		}
	}
	return r, nil
}

// Execute runs one command line given as words: a menu path alone changes the current menu, a command runs in
// the menu it was given in, "?" shows help. Errors are returned, not printed
func (s *Session) Execute(words []string) error {
	if len(words) == 0 {
		return nil
	}
	var r, err = s.resolve(words)
	if err != nil {
		return err
	}
	if r.help || (r.command != nil && r.command.Name == "help") {
		s.printHelp(r.menu, helpCommand(r.command))
		return nil
	}
	if r.command == nil {
		s.cwd = r.menu
		return nil
	}
	if r.command.Name == "exit" {
		return errExit
	}

	var args, parseErr = parseArgs(r.command, r.args)
	if parseErr != nil {
		return parseErr
	}
	if r.command.Check != nil {
		if err := r.command.Check(args); err != nil {
			return fmt.Errorf("%s: %w", r.command.Name, err)
		}
	}
	if r.command.Confirm != "" && !args.Bool(confirmArg) {
		if s.Ask == nil {
			return fmt.Errorf("%s Not run: add confirm=yes to run it without asking", r.command.Confirm)
		}
		var confirmed, askErr = s.Ask(r.command.Confirm + " Continue? [y/N] ")
		if askErr != nil {
			return askErr
		}
		if !confirmed {
			return ErrCancelled
		}
	}

	return s.Run(func(ctx context.Context) error {
		var c = &Context{Context: ctx, Out: s.Out, ErrOut: s.Err, Session: s, Menu: r.menu}
		return r.command.Run(c, args)
	})
}

// helpCommand returns the command to show help for, nil for menu help (help itself shows the menu)
func helpCommand(command *Command) *Command {
	if command == nil || command.Name == "help" || command.Name == "exit" {
		return nil
	}
	return command
}

// runWithInterrupt runs a command with a context that is cancelled on Ctrl-C / SIGTERM
func runWithInterrupt(run func(ctx context.Context) error) error {
	var ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

// ExecuteLine splits a line into words (see SplitLine) and executes it. Empty lines and # comments do nothing
func (s *Session) ExecuteLine(line string) error {
	var words, err = SplitLine(line)
	if err != nil {
		return err
	}
	return s.Execute(words)
}

// RunScript executes the lines of a script one by one (like RouterOS /import): menu paths change the current menu
// for the following lines. It stops at the first error, reporting the line number
func (s *Session) RunScript(reader io.Reader, name string) error {
	var scanner = bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var number int
	for scanner.Scan() {
		number++
		var err = s.ExecuteLine(scanner.Text())
		if errors.Is(err, errExit) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %w", name, number, err)
		}
	}
	return scanner.Err()
}

// SplitLine splits a command line into words at spaces. "double" and 'single' quotes group words (name="a b"),
// inside double quotes \" and \\ escape. A line starting with # is a comment
func SplitLine(line string) ([]string, error) {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return nil, nil
	}
	var words []string
	var word strings.Builder
	var inWord bool
	var quote rune
	var runes = []rune(line)
	for i := 0; i < len(runes); i++ {
		var r = runes[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\') {
				i++
				word.WriteRune(runes[i])
			} else {
				word.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, nil
}

// printHelp shows the sub menus and commands of a menu, or the arguments of a command
func (s *Session) printHelp(menu *Menu, command *Command) {
	var out = s.Out
	if command != nil {
		_, _ = fmt.Fprintf(out, "%s: %s\n", commandPath(menu, command), command.Help)
		if len(command.Aliases) > 0 {
			_, _ = fmt.Fprintf(out, "aliases: %s\n", strings.Join(command.Aliases, ", "))
		}
		if command.Long != "" {
			_, _ = fmt.Fprintf(out, "\n%s\n", strings.TrimSpace(command.Long))
		}
		if command.Confirm != "" {
			_, _ = fmt.Fprintf(out, "\n%s\n", wrapText(command.Confirm+" It asks for confirmation, or runs directly with confirm=yes.", helpWidth))
		}
		if len(command.Args) == 0 {
			_, _ = fmt.Fprintln(out, "\nno arguments")
			return
		}
		_, _ = fmt.Fprintln(out, "\narguments:")
		var rows [][]string
		for _, spec := range command.Args {
			var notes []string
			if spec.Required {
				notes = append(notes, "required")
			}
			if spec.Positional {
				notes = append(notes, "may be given without name")
			}
			if spec.Default != "" {
				notes = append(notes, "default "+defaultUsage(spec))
			}
			var help = spec.Help
			if len(notes) > 0 {
				help += " (" + strings.Join(notes, ", ") + ")"
			}
			rows = append(rows, []string{"  " + argUsage(spec), help})
		}
		printPlain(out, rows)
		return
	}

	var title = menu.Path()
	if menu.Help != "" {
		title += ": " + menu.Help
	}
	_, _ = fmt.Fprintln(out, title)
	if menus := menu.Menus(); len(menus) > 0 {
		_, _ = fmt.Fprintln(out, "\nmenus:")
		var rows [][]string
		for _, sub := range menus {
			rows = append(rows, []string{"  " + sub.Name, sub.Help})
		}
		printPlain(out, rows)
	}
	if commands := menu.Commands(); len(commands) > 0 {
		_, _ = fmt.Fprintln(out, "\ncommands:")
		var rows [][]string
		for _, command := range commands {
			rows = append(rows, []string{"  " + command.Name, command.Help})
		}
		printPlain(out, rows)
	}
	_, _ = fmt.Fprintln(out, "\nnavigate with a menu name, .. (up) or / (root); \"<command> ?\" shows its arguments; help, exit")
}

// defaultUsage renders the default of an argument for the help, durations short like 10m instead of 10m0s
func defaultUsage(spec Arg) string {
	if spec.Type != Duration {
		return spec.Default
	}
	var duration, err = parseDuration(spec.Default)
	if err != nil {
		return spec.Default
	}
	var text = duration.String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}

// helpWidth is where generated help text (the confirmation paragraph) is wrapped, like the hand wrapped Long texts
const helpWidth = 110

// wrapText breaks a paragraph into lines of at most width characters at spaces
func wrapText(text string, width int) string {
	var lines []string
	var line string
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// printPlain prints rows as aligned columns without header and without "-" for empty cells
func printPlain(out io.Writer, rows [][]string) {
	var width int
	for _, row := range rows {
		width = max(width, len(row[0]))
	}
	for _, row := range rows {
		_, _ = fmt.Fprintf(out, "%-*s  %s\n", width, row[0], row[1])
	}
}

// commandPath renders a command with its menu like /dnsmasq/host add, or /import for the root
func commandPath(menu *Menu, command *Command) string {
	if menu.parent == nil {
		return "/" + command.Name
	}
	return menu.Path() + " " + command.Name
}
