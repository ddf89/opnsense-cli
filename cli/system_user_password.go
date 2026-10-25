package cli

import (
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/term"
)

// The password prompt of /system/user password: the terminal is put in raw mode while the password is typed, so
// nothing is echoed and Ctrl-C arrives as a key (in the shell a SIGINT would only be seen after Enter)

var errSystemUserNoTerminal = errors.New("the password is asked on the terminal, in scripts use set <user> password=... instead")

// systemUserAskPassword asks for the new password of user twice on the terminal (stdin) without echo
func systemUserAskPassword(c *Context, user string) (string, error) {
	var fd = int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errSystemUserNoTerminal
	}
	var ask = func(prompt string) (string, error) {
		_, _ = io.WriteString(c.ErrOut, prompt)
		var state, err = term.MakeRaw(fd)
		if err != nil {
			return "", err
		}
		var password, readErr = systemUserReadSecret(os.Stdin)
		_ = term.Restore(fd, state)
		_, _ = io.WriteString(c.ErrOut, "\n")
		return password, readErr
	}
	var password, err = ask("new password for " + user + ": ")
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("the password must not be empty")
	}
	var again, againErr = ask("retype the password: ")
	if againErr != nil {
		return "", againErr
	}
	if again != password {
		return "", errors.New("the passwords do not match")
	}
	return password, nil
}

// systemUserReadSecret reads one line from a terminal in raw mode: Enter ends it, Backspace removes the last
// character, Ctrl-U clears the line, Ctrl-C (and Ctrl-D on an empty line) cancel, other control keys are ignored
func systemUserReadSecret(reader io.Reader) (string, error) {
	var secret []byte
	var buf = make([]byte, 1)
	// escape is 1 after ESC, 2 inside an escape sequence like ESC [ A (cursor keys), which is skipped
	var escape = 0
	for {
		var n, err = reader.Read(buf)
		if n == 0 {
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) && len(secret) == 0 {
				return "", ErrCancelled
			}
			if errors.Is(err, io.EOF) {
				return string(secret), nil
			}
			return "", err
		}
		var b = buf[0]
		if escape == 1 && b != '[' && b != 'O' {
			escape = 0 // a lone ESC
		}
		switch {
		case escape == 1:
			escape = 2
		case escape == 2:
			if b >= 0x40 && b <= 0x7e {
				escape = 0
			}
		case b == 0x1b:
			escape = 1
		case b == '\r' || b == '\n':
			return string(secret), nil
		case b == 0x03:
			return "", ErrCancelled
		case b == 0x04:
			if len(secret) == 0 {
				return "", ErrCancelled
			}
		case b == 0x7f || b == 0x08:
			if len(secret) > 0 {
				var _, size = utf8.DecodeLastRune(secret)
				secret = secret[:len(secret)-size]
			}
		case b == 0x15:
			secret = secret[:0]
		case b < 0x20:
		default:
			secret = append(secret, b)
		}
	}
}
