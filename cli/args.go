package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ArgType is the kind of value an argument takes, it is checked before the command runs
type ArgType int

const (
	String   ArgType = iota
	Bool             // yes/no, true/false, on/off, 1/0; can be given as a bare word (detail = detail=yes)
	Int              // a whole number
	Duration         // a Go duration like 2s or 1m30s, a bare number means seconds
	List             // comma separated values, "" for an empty list
)

func (t ArgType) String() string {
	switch t {
	case Bool:
		return "yes|no"
	case Int:
		return "number"
	case Duration:
		return "duration"
	case List:
		return "list"
	default:
		return "string"
	}
}

// Arg describes a name=value argument of a command
type Arg struct {
	Name     string
	Help     string
	Type     ArgType
	Required bool
	// Default is used by the getters when the argument was not given, it is shown in the help
	Default string
	// Values restricts the argument to these values (case-insensitive, for a List every element); also used for completion
	Values []string
	// Positional allows the value without a name: "remove 0" is "remove item=0". Only one argument per command
	Positional bool
	// Validate checks the raw value further, its error is shown with the argument name
	Validate func(value string) error
	// Complete suggests values for tab completion, e.g. loaded from the API; Values are used when nil
	Complete func(c *Context) []string
}

// confirmArg is added to every command with Command.Confirm or Command.ConfirmIf
const confirmArg = "confirm"

// Args are the parsed and validated arguments of one command invocation
type Args struct {
	command *Command
	values  map[string]string
}

func (a *Args) spec(name string) *Arg {
	for i := range a.command.Args {
		if a.command.Args[i].Name == name {
			return &a.command.Args[i]
		}
	}
	panic(fmt.Sprintf("command %s has no argument %q", a.command.Name, name))
}

// Has tells whether the argument was given explicitly (also when given with an empty value)
func (a *Args) Has(name string) bool {
	a.spec(name)
	var _, given = a.values[name]
	return given
}

// String returns the value, or the default when the argument was not given
func (a *Args) String(name string) string {
	var spec = a.spec(name)
	if value, given := a.values[name]; given {
		return value
	}
	return spec.Default
}

// Bool returns the value as bool (false when not given and without default)
func (a *Args) Bool(name string) bool {
	var value, _ = parseBool(a.String(name))
	return value
}

// Int returns the value as int (0 when not given and without default)
func (a *Args) Int(name string) int {
	var value, _ = strconv.Atoi(a.String(name))
	return value
}

// Duration returns the value as duration (0 when not given and without default)
func (a *Args) Duration(name string) time.Duration {
	var value, _ = parseDuration(a.String(name))
	return value
}

// List returns the comma separated values, trimmed and without empty elements
func (a *Args) List(name string) []string {
	return splitList(a.String(name))
}

// Given returns the names of all explicitly given arguments, sorted
func (a *Args) Given() []string {
	var names = make([]string, 0, len(a.values))
	for name := range a.values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func splitList(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "yes", "true", "on", "1":
		return true, nil
	case "no", "false", "off", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("must be yes or no, got %q", value)
}

func parseDuration(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		return time.Duration(seconds * float64(time.Second)), nil
	}
	var duration, err = time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("must be a duration like 5s or 1m, got %q", value)
	}
	return duration, nil
}

// parseArgs turns the words after the command into Args: name=value, a bare name of a Bool argument (= yes), or
// the value of the positional argument. Names may be abbreviated as long as they stay unambiguous
func parseArgs(command *Command, words []string) (*Args, error) {
	var args = &Args{command: command, values: map[string]string{}}
	for _, word := range words {
		var name, value, hasValue = strings.Cut(word, "=")
		var spec *Arg
		if hasValue {
			var err error
			if spec, err = lookupArg(command, name); err != nil {
				return nil, err
			}
		} else if flag := exactArg(command, word); flag != nil && flag.Type == Bool {
			spec, value = flag, "yes"
		} else if positional := positionalArg(command); positional != nil {
			spec, value = positional, word
		} else {
			return nil, fmt.Errorf("%s: unexpected %q, arguments are name=value (type \"%s ?\" for help)", command.Name, word, command.Name)
		}

		if _, duplicate := args.values[spec.Name]; duplicate {
			return nil, fmt.Errorf("%s: %s given twice", command.Name, spec.Name)
		}
		if err := checkValue(spec, value); err != nil {
			return nil, fmt.Errorf("%s: %s %w", command.Name, spec.Name, err)
		}
		args.values[spec.Name] = value
	}

	for _, spec := range command.Args {
		if _, given := args.values[spec.Name]; spec.Required && !given {
			return nil, fmt.Errorf("%s: %s is required (type \"%s ?\" for help)", command.Name, argUsage(spec), command.Name)
		}
	}
	return args, nil
}

func exactArg(command *Command, name string) *Arg {
	for i := range command.Args {
		if command.Args[i].Name == name {
			return &command.Args[i]
		}
	}
	return nil
}

func positionalArg(command *Command) *Arg {
	for i := range command.Args {
		if command.Args[i].Positional {
			return &command.Args[i]
		}
	}
	return nil
}

func lookupArg(command *Command, name string) (*Arg, error) {
	if spec := exactArg(command, name); spec != nil {
		return spec, nil
	}
	var matches []*Arg
	for i := range command.Args {
		if strings.HasPrefix(command.Args[i].Name, name) {
			matches = append(matches, &command.Args[i])
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		var names = make([]string, 0, len(command.Args))
		for _, spec := range command.Args {
			names = append(names, spec.Name)
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("%s takes no arguments", command.Name)
		}
		return nil, fmt.Errorf("%s: unknown argument %q, valid are: %s", command.Name, name, strings.Join(names, ", "))
	default:
		var names = make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, match.Name)
		}
		return nil, fmt.Errorf("%s: argument %q is ambiguous: %s", command.Name, name, strings.Join(names, ", "))
	}
}

// checkValue validates a raw value against the argument's type, allowed values and validator
func checkValue(spec *Arg, value string) error {
	switch spec.Type {
	case Bool:
		if _, err := parseBool(value); err != nil {
			return err
		}
	case Int:
		if _, err := strconv.Atoi(value); err != nil && value != "" {
			return fmt.Errorf("must be a number, got %q", value)
		}
	case Duration:
		if _, err := parseDuration(value); err != nil {
			return err
		}
	}

	if len(spec.Values) > 0 && value != "" {
		var elements = []string{value}
		if spec.Type == List {
			elements = splitList(value)
		}
		for _, element := range elements {
			if !containsFold(spec.Values, element) {
				return fmt.Errorf("must be one of %s, got %q", strings.Join(spec.Values, ", "), element)
			}
		}
	}

	if spec.Validate != nil {
		if err := spec.Validate(value); err != nil {
			return err
		}
	}
	return nil
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

// argUsage renders an argument like ip=<list> or detail
func argUsage(spec Arg) string {
	if spec.Type == Bool {
		return spec.Name + "[=yes|no]"
	}
	if len(spec.Values) > 0 && len(spec.Values) <= 6 {
		return spec.Name + "=" + strings.Join(spec.Values, "|")
	}
	return fmt.Sprintf("%s=<%s>", spec.Name, spec.Type)
}
