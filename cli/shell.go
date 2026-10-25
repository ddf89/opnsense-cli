package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// keyInterrupt replaces Ctrl-C at the prompt: x/term ends ReadLine on Ctrl-C, the shell clears the line instead
const keyInterrupt = 0x1f

const historySize = 500

// interruptReader turns Ctrl-C (0x03) into keyInterrupt while the terminal is in raw mode. While a confirmation
// question is asked (*asking), Ctrl-C and Ctrl-D become keyInterrupt followed by Enter, so the question is answered
// (with "^C", which is no) instead of x/term ending ReadLine half way
type interruptReader struct {
	reader  io.Reader
	asking  *bool
	pending []byte
	err     error
}

func (r *interruptReader) Read(buf []byte) (int, error) {
	if len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		var chunk = make([]byte, len(buf))
		var n, err = r.reader.Read(chunk)
		r.err = err
		for _, b := range chunk[:n] {
			switch {
			case (b == 0x03 || b == 0x04) && r.asking != nil && *r.asking:
				r.pending = append(r.pending, keyInterrupt, '\r')
			case b == 0x03:
				r.pending = append(r.pending, keyInterrupt)
			default:
				r.pending = append(r.pending, b)
			}
		}
		if len(r.pending) == 0 {
			r.err = nil
			return 0, err
		}
	}
	var n = copy(buf, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// RunShell runs the interactive shell on the terminal stdin/stdout until exit or Ctrl-D
func RunShell(session *Session, stdin *os.File, stdout *os.File) error {
	var fd = int(stdin.Fd())
	var state, err = term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(fd, state) }()

	var asking bool
	var terminal = term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{&interruptReader{reader: stdin, asking: &asking}, stdout}, "")
	// some pseudo terminals report 0 columns, x/term then wraps after every character
	if width, height, sizeErr := term.GetSize(int(stdout.Fd())); sizeErr == nil && width > 0 && height > 0 {
		_ = terminal.SetSize(width, height)
	}
	var history = loadHistory()
	terminal.History = history
	defer history.save()

	// everything goes through the terminal, it adds the \r raw mode needs and keeps the prompt intact
	session.Out, session.Err, session.Interactive = terminal, terminal, true
	log.SetOutput(terminal)
	log.SetFlags(0)
	session.Ask = func(question string) (bool, error) {
		terminal.SetPrompt(question)
		asking = true
		defer func() {
			asking = false
			terminal.SetPrompt(shellPrompt(session))
		}()
		var answer, readErr = terminal.ReadLine()
		if readErr != nil {
			return false, nil
		}
		return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
	}
	// commands run in cooked mode, so Ctrl-C is a signal that cancels the command instead of a key. Their output
	// goes straight to the terminal: the tty adds the \r itself in cooked mode
	session.Run = func(run func(ctx context.Context) error) error {
		_ = term.Restore(fd, state)
		session.Out, session.Err = stdout, stdout
		log.SetOutput(stdout)
		defer func() {
			session.Out, session.Err = terminal, terminal
			log.SetOutput(terminal)
			_, _ = term.MakeRaw(fd)
		}()
		var ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var err = run(ctx)
		if ctx.Err() != nil {
			// the tty echoed ^C, start the prompt on a new line
			_, _ = fmt.Fprintln(stdout)
		}
		return err
	}
	terminal.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if asking {
			return askKey(line, pos, key)
		}
		return shellKey(session, terminal, line, pos, key)
	}

	_, _ = fmt.Fprintf(terminal, "OPNsense CLI on %s\n", hostOf(session))
	_, _ = fmt.Fprintln(terminal, "Type ? or help for help, TAB completes, / goes to the root, .. up, exit or Ctrl-D quits")
	for {
		terminal.SetPrompt(shellPrompt(session))
		var line, readErr = terminal.ReadLine()
		if errors.Is(readErr, io.EOF) {
			_, _ = fmt.Fprintln(terminal)
			return nil
		}
		if readErr != nil {
			return readErr
		}
		var execErr = session.ExecuteLine(line)
		if errors.Is(execErr, errExit) {
			return nil
		}
		if errors.Is(execErr, ErrCancelled) {
			_, _ = fmt.Fprintln(terminal, "cancelled")
		} else if execErr != nil {
			_, _ = fmt.Fprintf(terminal, "error: %v\n", execErr)
		}
	}
}

// askKey handles the keys of a confirmation question: Ctrl-C (and Ctrl-D) answer it with "^C" (the Enter after it
// comes from interruptReader), TAB and ? are plain keys there
func askKey(line string, pos int, key rune) (string, int, bool) {
	if key == keyInterrupt {
		return "^C", 2, true
	}
	return line, pos, key == '\t'
}

// shellKey handles TAB (completion), ? (help) and Ctrl-C (clear the line) while a line is typed
func shellKey(session *Session, terminal *term.Terminal, line string, pos int, key rune) (string, int, bool) {
	switch key {
	case keyInterrupt:
		// one Write: the terminal redraws the prompt after each write
		_, _ = fmt.Fprint(terminal, shellPrompt(session)+line+"^C\n")
		return "", 0, true
	case '?':
		// a ? inside quotes is part of a value
		if strings.Count(line[:pos], `"`)%2 == 1 {
			return "", 0, false
		}
		var help bytes.Buffer
		help.WriteString(shellPrompt(session) + line[:pos] + "?\n")
		var out = session.Out
		session.Out = &help
		if err := session.HelpFor(line[:pos]); err != nil {
			_, _ = fmt.Fprintf(&help, "error: %v\n", err)
		}
		session.Out = out
		_, _ = terminal.Write(help.Bytes())
		return line, pos, true
	case '\t':
		var candidates, start = session.Complete(line[:pos])
		if len(candidates) == 0 {
			return line, pos, true
		}
		var completion = commonPrefix(candidates)
		if len(candidates) == 1 && !strings.HasSuffix(completion, "=") && !strings.HasSuffix(completion, "/") {
			completion += " "
		}
		if len(completion) > pos-start {
			var newLine = line[:start] + completion + line[pos:]
			return newLine, start + len(completion), true
		}
		// nothing to add: show the choices
		_, _ = fmt.Fprint(terminal, shellPrompt(session)+line+"\n"+strings.Join(candidates, "  ")+"\n")
		return line, pos, true
	}
	return "", 0, false
}

// shellPrompt looks like RouterOS: [opn@firewall] /dnsmasq/host>
func shellPrompt(session *Session) string {
	return fmt.Sprintf("[opn@%s] %s> ", hostOf(session), session.Cwd().Path())
}

func hostOf(session *Session) string {
	if parsed, err := url.Parse(os.Getenv("OPN_URL")); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return "opnsense"
}

// fileHistory is the x/term history, kept in ~/.opn_history between sessions
type fileHistory struct {
	path    string
	entries []string // oldest first
}

func loadHistory() *fileHistory {
	var history = &fileHistory{}
	if home, err := os.UserHomeDir(); err == nil {
		history.path = filepath.Join(home, ".opn_history")
	}
	if file, err := os.Open(history.path); err == nil {
		var scanner = bufio.NewScanner(file)
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				history.entries = append(history.entries, line)
			}
		}
		_ = file.Close()
	}
	history.trim()
	return history
}

func (h *fileHistory) trim() {
	if len(h.entries) > historySize {
		h.entries = h.entries[len(h.entries)-historySize:]
	}
}

func (h *fileHistory) Add(entry string) {
	if entry == "" || (len(h.entries) > 0 && h.entries[len(h.entries)-1] == entry) {
		return
	}
	h.entries = append(h.entries, entry)
	h.trim()
}

func (h *fileHistory) Len() int {
	return len(h.entries)
}

// At returns the entry idx steps back, 0 is the newest
func (h *fileHistory) At(idx int) string {
	return h.entries[len(h.entries)-1-idx]
}

func (h *fileHistory) save() {
	if h.path == "" {
		return
	}
	_ = os.WriteFile(h.path, []byte(strings.Join(h.entries, "\n")+"\n"), 0o600)
}
