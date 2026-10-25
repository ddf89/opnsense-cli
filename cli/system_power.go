package cli

import (
	"errors"
	"opnsense-cli/opnsense/api/system"
	"time"
)

// /system reboot and /system shutdown (Power > Reboot / Power Off of the web UI)

const (
	systemPowerRebootWarning = "This reboots the firewall: all routing, VPN and services (and this API) are interrupted until it is back."
	systemPowerOffWarning    = "This powers off the firewall: all routing, VPN and services stop and it does NOT come back by itself, " +
		"powering it on again needs physical or console (IPMI, hypervisor) access."
)

func init() {
	var menu = Root.Sub("system", "system settings, configuration and power")
	menu.Add(
		&Command{
			Name: "reboot",
			Help: "reboot the firewall",
			Long: `With wait the command waits until the firewall went down and answers the API again (polling the
read-only api/core/system/status) and fails when that does not happen within timeout. Ctrl-C stops waiting,
not the reboot.`,
			Args: []Arg{
				{Name: "wait", Type: Bool, Help: "wait until the firewall is back up"},
				{Name: "timeout", Type: Duration, Default: system.PowerDefaultWaitTimeout.String(), Validate: systemPowerPositive,
					Help: "how long wait waits for the firewall to go down and come back"},
				{Name: "poll-interval", Type: Duration, Default: system.PowerDefaultPollInterval.String(), Validate: systemPowerPositive,
					Help: "time between two status checks of wait"},
			},
			Check:   systemPowerRebootCheck,
			Confirm: systemPowerRebootWarning,
			Run:     systemPowerReboot,
		},
		&Command{
			Name:    "shutdown",
			Aliases: []string{"poweroff", "halt"},
			Help:    "power off the firewall",
			Confirm: systemPowerOffWarning,
			Run:     systemPowerShutdown,
		},
	)
}

func systemPowerPositive(value string) error {
	if duration, err := parseDuration(value); err == nil && duration <= 0 {
		return errors.New("must be positive")
	}
	return nil
}

// systemPowerClock replaces the clock of the reboot wait in tests, nil fields use the real clock
type systemPowerClock struct {
	Now   func() time.Time
	Sleep func(time.Duration)
}

// systemPowerRebootCheck runs before the confirmation question
func systemPowerRebootCheck(args *Args) error {
	if !args.Bool("wait") && (args.Has("timeout") || args.Has("poll-interval")) {
		return errors.New("timeout and poll-interval are only used together with wait")
	}
	return nil
}

func systemPowerReboot(c *Context, args *Args) error {
	var opn, err = c.Api()
	if err != nil {
		return err
	}
	var options = system.PowerWaitOptions{Timeout: args.Duration("timeout"), PollInterval: args.Duration("poll-interval")}
	return systemPowerRebootExecute(c, &system.SystemApi{OPNsense: opn}, args.Bool("wait"), options, systemPowerClock{})
}

// systemPowerRebootExecute reboots and optionally waits for the firewall to come back, progress goes to c.ErrOut.
// Ctrl-C (c.Done) ends the wait without an error
func systemPowerRebootExecute(c *Context, api *system.SystemApi, wait bool, options system.PowerWaitOptions, clock systemPowerClock) error {
	if err := api.PowerReboot(); err != nil {
		return err
	}
	c.Infof("reboot of %s initiated", api.BaseUrl.Host)
	if !wait {
		return nil
	}

	if options.Timeout <= 0 {
		options.Timeout = system.PowerDefaultWaitTimeout
	}
	var now = clock.Now
	if now == nil {
		now = time.Now
	}
	// a cancelled wait jumps past the deadline, so PowerWaitUntilUp returns at once
	options.Now = func() time.Time {
		if c.Err() != nil {
			return now().Add(options.Timeout + time.Hour)
		}
		return now()
	}
	options.Sleep = func(d time.Duration) {
		if clock.Sleep != nil {
			clock.Sleep(d)
			return
		}
		var timer = time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-c.Done():
		case <-timer.C:
		}
	}
	options.Progress = func(event system.PowerWaitEvent) {
		if c.Err() != nil {
			return
		}
		switch event.State {
		case system.PowerStateDown:
			c.Infof("firewall went down after %s, waiting for it to come back", event.Elapsed.Round(time.Second))
		case system.PowerStateUp:
			c.Infof("firewall is back up after %s", event.Elapsed.Round(time.Second))
		}
	}

	c.Infof("waiting up to %s for the firewall to go down and come back up", options.Timeout)
	var err = api.PowerWaitUntilUp(options)
	if c.Err() != nil {
		c.Infof("stopped waiting, the reboot goes on")
		return nil
	}
	return err
}

func systemPowerShutdown(c *Context, _ *Args) error {
	var opn, err = c.Api()
	if err != nil {
		return err
	}
	var api = &system.SystemApi{OPNsense: opn}
	if err := api.PowerOff(); err != nil {
		return err
	}
	c.Infof("power off of %s initiated, it will not come back without physical or console access", api.BaseUrl.Host)
	return nil
}
