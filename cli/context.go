package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	coreapi "opnsense-cli/opnsense/api"
	"strconv"
	"strings"
	"text/tabwriter"
)

// Session is the state of one CLI run: the current menu of the shell, the items of the last print per menu and
// the API connection, which is only configured when a command needs it
type Session struct {
	Out, Err    io.Writer
	Interactive bool
	Verbose     bool
	// Configure creates the API connection, ConfigureFromEnv by default
	Configure func() (*coreapi.OPNsense, error)
	// Ask asks a yes/no question interactively (nil when not interactive)
	Ask func(question string) (bool, error)
	// Run runs a command with a context that is cancelled on Ctrl-C, see runWithInterrupt
	Run func(run func(ctx context.Context) error) error

	root      *Menu
	cwd       *Menu
	api       *coreapi.OPNsense
	lastPrint map[string][]string
}

// NewSession creates a non-interactive session at the root menu writing to out and errOut
func NewSession(out io.Writer, errOut io.Writer) *Session {
	return &Session{
		Out:       out,
		Err:       errOut,
		Configure: coreapi.ConfigureFromEnv,
		Run:       runWithInterrupt,
		root:      Root,
		cwd:       Root,
		lastPrint: map[string][]string{},
	}
}

// Cwd returns the current menu
func (s *Session) Cwd() *Menu {
	return s.cwd
}

// api returns the API connection, configuring it on first use
func (s *Session) connection() (*coreapi.OPNsense, error) {
	if s.api == nil {
		var opn, err = s.Configure()
		if err != nil {
			return nil, err
		}
		opn.Verbose = s.Verbose
		s.api = opn
	}
	return s.api, nil
}

// Context is what a command gets to run: a context.Context cancelled on Ctrl-C (always stop on Done, e.g. follow loops),
// writers for output and messages, and access to the API and session
type Context struct {
	context.Context
	// Out is for data, ErrOut for messages. ErrOut is not called Err, so the context's Err() stays reachable and
	// *Context can be passed wherever a context.Context is needed
	Out, ErrOut io.Writer
	Session     *Session
	// Menu is the menu the command was issued in
	Menu *Menu
}

// Api returns the API connection, configured from the environment on first use
func (c *Context) Api() (*coreapi.OPNsense, error) {
	return c.Session.connection()
}

// Interactive tells whether the command runs in the interactive shell
func (c *Context) Interactive() bool {
	return c.Session.Interactive
}

// Printf writes formatted output, Println a line of output
func (c *Context) Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(c.Out, format, args...)
}

func (c *Context) Println(args ...any) {
	_, _ = fmt.Fprintln(c.Out, args...)
}

// Infof writes a message for the user (progress, hints, warnings) to ErrOut, keeping Out clean for data
func (c *Context) Infof(format string, args ...any) {
	_, _ = fmt.Fprintf(c.ErrOut, strings.TrimSuffix(format, "\n")+"\n", args...)
}

// JSON writes v as one compact JSON line (ndjson). <, > and & are written as they are, not as \u003c etc.
func (c *Context) JSON(v any) error {
	var line bytes.Buffer
	var encoder = json.NewEncoder(&line)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return err
	}
	_, _ = c.Out.Write(line.Bytes())
	return nil
}

// Table prints rows as aligned columns, empty cells are shown as "-"
func (c *Context) Table(headers []string, rows [][]string) {
	printTable(c.Out, headers, rows)
}

// Items prints a list like RouterOS does: a "#" column numbering the rows from 0, followed by the columns. The
// uuids (one per row) are remembered for this menu, so "set 2 ..." or "remove 2" refer to the printed rows
func (c *Context) Items(headers []string, rows [][]string, uuids []string) {
	var numbered = make([][]string, len(rows))
	for i, row := range rows {
		numbered[i] = append([]string{strconv.Itoa(i)}, row...)
	}
	printTable(c.Out, append([]string{"#"}, headers...), numbered)
	c.Session.lastPrint[c.Menu.Path()] = append([]string(nil), uuids...)
}

// Fields prints one item as aligned "name: value" lines in the given order
func (c *Context) Fields(fields [][2]string) {
	var writer = tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
	for _, field := range fields {
		_, _ = fmt.Fprintf(writer, "%s:\t%s\n", field[0], field[1])
	}
	_ = writer.Flush()
}

func printTable(out io.Writer, headers []string, rows [][]string) {
	var writer = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		var cells = make([]string, len(row))
		for i, cell := range row {
			if cell == "" {
				cell = "-"
			}
			cells[i] = cell
		}
		_, _ = fmt.Fprintln(writer, strings.Join(cells, "\t"))
	}
	_ = writer.Flush()
}

// YesNo renders a "1"/"0" API flag as yes/no
func YesNo(flag string) string {
	switch flag {
	case "1":
		return "yes"
	case "0", "":
		return "no"
	}
	return flag
}

// EnabledWord renders an on/off state for messages like "the job x is already disabled"
func EnabledWord(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// Flag renders a bool as the "1"/"0" the API expects
func Flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// Details prints items as numbered blocks of "name: value" lines (print detail), remembering the uuids like Items
func (c *Context) Details(items [][][2]string, uuids []string) {
	for i, fields := range items {
		if i > 0 {
			c.Println()
		}
		c.Printf("%d\n", i)
		var writer = tabwriter.NewWriter(c.Out, 0, 0, 2, ' ', 0)
		for _, field := range fields {
			_, _ = fmt.Fprintf(writer, "  %s:\t%s\n", field[0], field[1])
		}
		_ = writer.Flush()
	}
	c.Session.lastPrint[c.Menu.Path()] = append([]string(nil), uuids...)
}
