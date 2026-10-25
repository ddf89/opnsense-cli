package cli

import (
	"context"
	"sort"
	"strings"
)

// Complete returns the candidates for the last (partial) word of line: menus and commands while walking the
// path, argument names (with a trailing "=") and argument values after a command. The candidates are complete
// replacements for the partial word, which starts at byte offset start
func (s *Session) Complete(line string) (candidates []string, start int) {
	var words, partial = splitPartial(line)
	start = lastWordStart(line)

	var r, err = s.resolve(words)
	if err != nil {
		return nil, start
	}

	if r.command == nil {
		// path: complete the last segment of e.g. "/dnsmasq/ho" against the menu the earlier segments lead to
		var menu = r.menu
		var prefix = ""
		if strings.HasPrefix(partial, "/") {
			menu = s.root
		}
		var segments = strings.Split(partial, "/")
		for _, segment := range segments[:len(segments)-1] {
			switch segment {
			case "":
				continue
			case "..":
				menu = menu.Parent()
				continue
			}
			var e, lookupErr = menu.lookup(segment)
			if lookupErr != nil || e.menu == nil {
				return nil, start
			}
			menu = e.menu
		}
		if i := strings.LastIndex(partial, "/"); i >= 0 {
			prefix = partial[:i+1]
		}
		var last = segments[len(segments)-1]
		for _, e := range menu.prefixEntries(last) {
			candidates = append(candidates, prefix+e.name)
		}
		if strings.HasPrefix("..", last) && last != "" && menu != s.root {
			candidates = append(candidates, prefix+"..")
		}
		return unique(candidates), start
	}

	var given = map[string]bool{}
	var positional = positionalArg(r.command)
	for _, word := range r.args {
		if name, _, hasValue := strings.Cut(word, "="); hasValue {
			if spec, lookupErr := lookupArg(r.command, name); lookupErr == nil {
				given[spec.Name] = true
			}
		} else if spec := exactArg(r.command, word); spec != nil && spec.Type == Bool {
			given[spec.Name] = true
		} else if positional != nil {
			given[positional.Name] = true
		}
	}

	if name, valuePrefix, hasValue := strings.Cut(partial, "="); hasValue {
		var spec, lookupErr = lookupArg(r.command, name)
		if lookupErr != nil {
			return nil, start
		}
		var values = s.argValues(r, spec)
		// lists complete their last element
		var listPrefix = ""
		if spec.Type == List {
			if i := strings.LastIndex(valuePrefix, ","); i >= 0 {
				listPrefix, valuePrefix = valuePrefix[:i+1], valuePrefix[i+1:]
			}
		}
		for _, value := range values {
			if strings.HasPrefix(strings.ToLower(value), strings.ToLower(valuePrefix)) {
				candidates = append(candidates, spec.Name+"="+quoteValue(listPrefix+value))
			}
		}
		return unique(candidates), start
	}

	// the positional argument completes its values without the name, like "remove web<TAB>"
	if positional != nil && !given[positional.Name] {
		for _, value := range s.argValues(r, positional) {
			if strings.HasPrefix(strings.ToLower(value), strings.ToLower(partial)) {
				candidates = append(candidates, quoteValue(value))
			}
		}
	}
	for _, spec := range r.command.Args {
		if given[spec.Name] || !strings.HasPrefix(spec.Name, partial) {
			continue
		}
		if spec.Type == Bool {
			candidates = append(candidates, spec.Name)
		} else {
			candidates = append(candidates, spec.Name+"=")
		}
	}
	return unique(candidates), start
}

// argValues returns the completion values of an argument: Complete (e.g. loaded from the API), else Values
func (s *Session) argValues(r *resolved, spec *Arg) []string {
	if spec.Complete != nil {
		var c = &Context{Context: context.Background(), Out: s.Out, ErrOut: s.Err, Session: s, Menu: r.menu}
		return spec.Complete(c)
	}
	if spec.Type == Bool {
		return []string{"yes", "no"}
	}
	return spec.Values
}

// HelpFor returns what "?" shows for a partial line, written to the session output
func (s *Session) HelpFor(line string) error {
	var words, _ = splitPartial(line)
	var r, err = s.resolve(words)
	if err != nil {
		return err
	}
	s.printHelp(r.menu, helpCommand(r.command))
	return nil
}

// lastWordStart returns the byte offset where the last word of a line being typed starts (len(line) after a
// space), honouring quotes like SplitLine, so a partial `command="fir` is replaced as a whole
func lastWordStart(line string) int {
	var start = 0
	var quote rune
	var inWord bool
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == ' ' || r == '\t':
			inWord = false
		default:
			if !inWord {
				start, inWord = i, true
			}
			if r == '"' || r == '\'' {
				quote = r
			}
		}
	}
	if !inWord && quote == 0 {
		return len(line)
	}
	return start
}

// quoteValue quotes a completed value that SplitLine would otherwise split or unquote
func quoteValue(value string) string {
	if !strings.ContainsAny(value, " \t\"'") {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// splitPartial splits a line being typed into its complete words and the partial last word (empty after a space)
func splitPartial(line string) ([]string, string) {
	var words, err = SplitLine(line)
	if err != nil {
		// an open quote: complete what is there
		words, _ = SplitLine(line + `"`)
	}
	if len(words) == 0 || strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
		return words, ""
	}
	return words[:len(words)-1], words[len(words)-1]
}

// commonPrefix returns the longest prefix shared by all candidates
func commonPrefix(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	var prefix = candidates[0]
	for _, candidate := range candidates[1:] {
		for !strings.HasPrefix(candidate, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

func unique(values []string) []string {
	sort.Strings(values)
	var result []string
	for i, value := range values {
		if i == 0 || value != values[i-1] {
			result = append(result, value)
		}
	}
	return result
}
