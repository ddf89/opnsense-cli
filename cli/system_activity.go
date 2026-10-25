package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"os"
	"time"

	"golang.org/x/term"
)

// /system/activity: the system activity like top (Diagnostics > Activity, api/diagnostics/activity/get_activity).
// Also home of the polling helpers shared with /tool torch

func init() {
	var menu = Root.Menu("system/activity")
	menu.Help = "system activity: load, CPU, memory and the busiest threads (top)"
	menu.Add(&Command{
		Name: "print",
		Help: "show the system activity like top, follow refreshes it until Ctrl-C",
		Long: `Shows the load, CPU and memory summary and the busiest threads like top. Every query takes about 2
seconds (top measures for that long).

follow repeats the query every interval until Ctrl-C, on a terminal the screen is redrawn, otherwise a
"--- time" line separates the refreshes. json prints the raw answers, one JSON object per line.

  print lines=10 follow interval=5s`,
		Args: []Arg{
			{Name: "lines", Type: Int, Default: "20", Help: "number of threads to show, 0 for all", Validate: ValidateRange(0, 1000000)},
			{Name: "follow", Type: Bool, Help: "refresh until Ctrl-C"},
			{Name: "interval", Type: Duration, Default: "2s", Help: "pause between two refreshes of follow", Validate: systemActivityValidateInterval},
			{Name: "json", Type: Bool, Help: "print the raw answer as JSON, one object per line"},
		},
		Run: systemActivityPrint,
	})
}

func systemActivityPrint(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var lines = args.Int("lines")
	var asJSON = args.Bool("json")
	var refresh = systemActivityNewRefresher(c, args.Bool("follow") && !asJSON)

	return systemActivityPoll(c, args.Bool("follow"), args.Duration("interval"), func() error {
		var activity, getErr = systemActivityAwait(c, api.ActivityGet)
		if getErr != nil {
			return getErr
		}
		if asJSON {
			return c.JSON(activity.Raw)
		}
		refresh()
		systemActivityShow(c, activity, lines)
		return nil
	})
}

func systemActivityShow(c *Context, activity *diagnostics.Activity, lines int) {
	for _, header := range activity.Headers {
		c.Println(header)
	}
	c.Println()

	var threads = activity.Threads
	if lines > 0 && len(threads) > lines {
		threads = threads[:lines]
	}
	var rows = make([][]string, 0, len(threads))
	for _, t := range threads {
		rows = append(rows, []string{t.Pid, t.Thread, t.User, t.Priority, t.Nice, t.Size, t.Resident, t.State, t.Cpu, t.Time, t.CpuUsage, t.Command})
	}
	c.Table([]string{"PID", "THR", "USERNAME", "PRI", "NICE", "SIZE", "RES", "STATE", "C", "TIME", "WCPU", "COMMAND"}, rows)
}

// --- helpers shared with /tool torch

func systemActivityValidateInterval(value string) error {
	var interval, err = parseDuration(value)
	if err == nil && interval <= 0 {
		return fmt.Errorf("must be a positive duration like 2s, got %q", value)
	}
	return err
}

// systemActivityPoll calls fn once, or with follow repeatedly with a pause of interval in between until Ctrl-C.
// A query interrupted by Ctrl-C ends the command without error
func systemActivityPoll(c *Context, follow bool, interval time.Duration, fn func() error) error {
	for {
		if err := fn(); err != nil {
			if c.Err() != nil {
				return nil
			}
			return err
		}
		if !follow {
			return nil
		}
		var timer = time.NewTimer(interval)
		select {
		case <-c.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// systemActivityAwait runs a request that cannot be cancelled in the background and returns its result, or the
// context error as soon as Ctrl-C was pressed (the request finishes unobserved)
func systemActivityAwait[T any](c *Context, request func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	var done = make(chan result, 1)
	go func() {
		var value, err = request()
		done <- result{value, err}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-c.Done():
		var zero T
		return zero, c.Err()
	}
}

// systemActivityNewRefresher returns what to call before every refresh of a followed view: on a terminal the screen
// is cleared, otherwise a "--- time" line separates the refreshes. Without follow it does nothing
func systemActivityNewRefresher(c *Context, follow bool) func() {
	if !follow {
		return func() {}
	}
	var clear = systemActivityIsTerminal(c)
	var first = true
	return func() {
		if clear {
			c.Printf("\033[H\033[2J")
			return
		}
		if !first {
			c.Println()
		}
		first = false
		c.Printf("--- %s\n", time.Now().Format(time.DateTime))
	}
}

// systemActivityIsTerminal tells whether the output is a terminal (the interactive shell or a one-shot command on a
// terminal), where a view can be redrawn
func systemActivityIsTerminal(c *Context) bool {
	if c.Interactive() {
		return true
	}
	var file, isFile = c.Out.(*os.File)
	return isFile && term.IsTerminal(int(file.Fd()))
}
