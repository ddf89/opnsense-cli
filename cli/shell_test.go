package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/term"
)

// newTestTerminal is an x/term terminal without input writing to out
func newTestTerminal(out io.Writer) *term.Terminal {
	return term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{strings.NewReader(""), out}, "")
}

func TestShellInterruptReader(t *testing.T) {
	var asking bool
	var read = func(input string) string {
		var reader = &interruptReader{reader: strings.NewReader(input), asking: &asking}
		var got, err = io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	// at the prompt Ctrl-C becomes keyInterrupt (clears the line), Ctrl-D stays (EOF on an empty line)
	if got := read("ab\x03\x04"); got != "ab\x1f\x04" {
		t.Errorf("prompt: %q", got)
	}
	// at a confirmation question Ctrl-C and Ctrl-D answer it: keyInterrupt and Enter
	asking = true
	if got := read("y\x03"); got != "y\x1f\r" {
		t.Errorf("question Ctrl-C: %q", got)
	}
	if got := read("\x04"); got != "\x1f\r" {
		t.Errorf("question Ctrl-D: %q", got)
	}
	// a small read buffer gets the expanded bytes over several reads
	var reader = &interruptReader{reader: strings.NewReader("\x03x"), asking: &asking}
	var one = make([]byte, 1)
	var got []byte
	for {
		var n, err = reader.Read(one)
		got = append(got, one[:n]...)
		if err == io.EOF {
			break
		}
	}
	if string(got) != "\x1f\rx" {
		t.Errorf("small buffer: %q", got)
	}
}

func TestShellAskKey(t *testing.T) {
	if line, pos, ok := askKey("ye", 2, keyInterrupt); line != "^C" || pos != 2 || !ok {
		t.Errorf("Ctrl-C: %q %d %v", line, pos, ok)
	}
	if _, _, ok := askKey("", 0, '?'); ok {
		t.Errorf("? is a plain key at a question")
	}
	if line, _, ok := askKey("y", 1, '\t'); line != "y" || !ok {
		t.Errorf("TAB is swallowed: %q %v", line, ok)
	}
}

func TestShellKeyHelpAndCompletion(t *testing.T) {
	var session, out, _ = newTestSession(t)
	var terminalOut bytes.Buffer
	var terminal = newTestTerminal(&terminalOut)
	// TAB completes the unique menu (with a space), the global help does not get in the way
	if line, pos, ok := shellKey(session, terminal, "/dnsmasq/h", 10, '\t'); line != "/dnsmasq/host " || pos != 14 || !ok {
		t.Errorf("TAB: %q %d %v", line, pos, ok)
	}
	// ? prints the help of the line typed so far and keeps the line
	if line, _, ok := shellKey(session, terminal, "/dnsmasq/host add ", 18, '?'); line != "/dnsmasq/host add " || !ok {
		t.Errorf("?: %q %v", line, ok)
	}
	if !strings.Contains(terminalOut.String(), "host=<string>") || out.Len() != 0 {
		t.Errorf("? help on the terminal:\n%s", terminalOut.String())
	}
	// a ? inside quotes is part of the value
	if _, _, ok := shellKey(session, terminal, `/dnsmasq/host add host="a`, 25, '?'); ok {
		t.Errorf("? inside quotes must be inserted")
	}
}
