package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const usage = `usage: opn [-v] [<menu path> [<command> [<arguments>]]]

Without a command opn starts an interactive shell (or runs the commands read from stdin when it is not a
terminal). With a command it runs that one command, e.g.

  opn /dnsmasq host print
  opn dnsmasq/host add host=web domain=example.lan ip=10.0.0.5
  opn /system cron ?

Options:
  -v, --verbose   log every API request to stderr
  -h, --help      show this help and the top level menus
`

func init() {
	Root.Add(&Command{
		Name: "import",
		Help: "run the commands of a script file, one per line (stops at the first error)",
		Long: `Each line is a command line as typed in the shell. Menu paths on their own line change the current
menu for the following lines, # starts a comment line.`,
		Args: []Arg{{Name: "file", Help: "the script file, - for stdin", Required: true, Positional: true}},
		Run: func(c *Context, args *Args) error {
			var name = args.String("file")
			var reader io.Reader = os.Stdin
			if name != "-" {
				var file, err = os.Open(name)
				if err != nil {
					return err
				}
				defer func() { _ = file.Close() }()
				reader = file
			}
			// the script starts at the root and doesn't change the menu of the caller
			var cwd = c.Session.cwd
			c.Session.cwd = c.Session.root
			defer func() { c.Session.cwd = cwd }()
			return c.Session.RunScript(reader, name)
		},
	})
}

// Main runs opn with the command line arguments (without the program name) and returns the exit code
func Main(argv []string, stdin *os.File, stdout *os.File, stderr *os.File) int {
	var session = NewSession(stdout, stderr)

	for len(argv) > 0 && strings.HasPrefix(argv[0], "-") && argv[0] != "-" {
		switch argv[0] {
		case "-v", "--verbose":
			session.Verbose = true
		case "-h", "--help":
			_, _ = fmt.Fprint(stdout, usage+"\n")
			session.printHelp(session.root, nil)
			return 0
		default:
			_, _ = fmt.Fprintf(stderr, "error: unknown option %s\n\n%s", argv[0], usage)
			return 2
		}
		argv = argv[1:]
	}

	var err error
	switch {
	case len(argv) == 0 && term.IsTerminal(int(stdin.Fd())) && term.IsTerminal(int(stdout.Fd())):
		err = RunShell(session, stdin, stdout)
	case len(argv) == 0:
		err = session.RunScript(stdin, "stdin")
	default:
		err = runOneShot(session, argv)
	}

	if errors.Is(err, errExit) {
		// "opn exit" (or a menu path followed by exit) does nothing, like exit in a script
		err = nil
	}
	if errors.Is(err, ErrCancelled) {
		_, _ = fmt.Fprintln(stderr, "cancelled")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// runOneShot runs the command given as program arguments. A single argument with spaces is split like a shell
// line ("opn '/dnsmasq host print'"), a menu path without command shows the help of that menu
func runOneShot(session *Session, argv []string) error {
	var words = argv
	if len(argv) == 1 && strings.ContainsAny(argv[0], " \t") {
		var err error
		if words, err = SplitLine(argv[0]); err != nil {
			return err
		}
	}

	var r, err = session.resolve(words)
	if err != nil {
		return err
	}
	if r.command == nil && !r.help {
		session.printHelp(r.menu, nil)
		return nil
	}
	return session.Execute(words)
}
