package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

// Shared parts of the /captive-portal menus (Services > Captive Portal): zone, template, session, voucher and
// service

const captivePortalApplyHint = `Changes are only saved, run "/captive-portal/service reconfigure" to apply them.`

func init() {
	Root.Menu("captive-portal").Help = "captive portal zones, templates, sessions, vouchers and service (Services > Captive Portal)"

	var service = Root.Menu("captive-portal/service")
	service.Help = "the captive portal service"
	service.Add(
		&Command{Name: "status", Help: "show whether the captive portal runs (disabled: no zone is enabled)", Run: captivePortalServiceStatus},
		&Command{Name: "reconfigure", Aliases: []string{"apply"},
			Help: "apply the saved zones and templates: reload the ipfw rules and (re)start the portal, stop it without enabled zones",
			Long: `Enabled zones take effect: the clients on their interfaces are redirected to the portal until they log in.
The ipfw rules are reloaded completely, also those of the traffic shaper.`,
			Run: captivePortalServiceAction("reconfigure")},
		&Command{Name: "start", Help: "start the captive portal service", Run: captivePortalServiceAction("start")},
		&Command{Name: "stop", Help: "stop the captive portal service (until the next start or reconfigure)",
			Confirm: "This stops the captive portal, clients of its zones can not log in until it is started again.",
			Run:     captivePortalServiceAction("stop")},
		&Command{Name: "restart", Help: "restart the captive portal service",
			Confirm: "This restarts the captive portal, logins are briefly not possible.",
			Run:     captivePortalServiceAction("restart")},
	)
}

// captivePortalApi returns the captive portal API on the session's connection
func captivePortalApi(c *Context) (*captiveportal.CaptivePortalApi, error) {
	var opn, err = c.Api()
	if err != nil {
		return nil, err
	}
	return &captiveportal.CaptivePortalApi{OPNsense: opn}, nil
}

// --- service

func captivePortalServiceStatus(c *Context, _ *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	status, err := api.ServiceStatus()
	if err != nil {
		return err
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func captivePortalServiceAction(action string) func(c *Context, _ *Args) error {
	return func(c *Context, _ *Args) error {
		var api, err = captivePortalApi(c)
		if err != nil {
			return err
		}
		switch action {
		case "start":
			return api.ServiceStart()
		case "stop":
			return api.ServiceStop()
		case "restart":
			return api.ServiceRestart()
		case "reconfigure":
			return api.ServiceReconfigure()
		}
		return fmt.Errorf("unknown action %s", action)
	}
}

// --- shared helpers

// captivePortalResolveOption maps an option given by key or description (case-insensitive) to its key, "" is ""
func captivePortalResolveOption(options []captiveportal.Option, argName string, value string) (string, error) {
	if value = strings.TrimSpace(value); value == "" {
		return "", nil
	}
	var matches []string
	for _, option := range options {
		if option.Key == "" {
			continue
		}
		if strings.EqualFold(option.Key, value) {
			return option.Key, nil
		}
		if strings.EqualFold(strings.TrimSpace(option.Description), value) {
			matches = append(matches, option.Key)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		var names []string
		for _, option := range options {
			if option.Key != "" {
				names = append(names, fmt.Sprintf("%q", option.Description))
			}
		}
		if len(names) == 0 {
			return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, there is nothing to choose from", argName, value)}
		}
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("%s %q, valid are: %s", argName, value, strings.Join(names, ", "))}
	default:
		return "", &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s %q matches %s, give the key instead", argName, value, strings.Join(matches, ", "))}
	}
}

// captivePortalOptionText renders comma separated option keys by their descriptions
func captivePortalOptionText(options []captiveportal.Option, keys string) string {
	var texts []string
	for _, key := range splitList(keys) {
		var text = key
		for _, option := range options {
			if option.Key == key && strings.TrimSpace(option.Description) != "" {
				text = strings.TrimSpace(option.Description)
				break
			}
		}
		texts = append(texts, text)
	}
	return strings.Join(texts, ",")
}

// captivePortalWriteOutput writes content to stdout (output "-") or to a file with mode 0600 (output, else
// defaultName); an existing file is only replaced with overwrite
func captivePortalWriteOutput(c *Context, output string, defaultName string, content []byte, overwrite bool) error {
	if output == "-" {
		_, err := c.Out.Write(content)
		return err
	}
	var filename = defaultName
	if output != "" {
		filename = output
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	var file, err = os.OpenFile(filename, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(content))
	return nil
}

// captivePortalCheckOutput fails early when the output file exists and overwrite is not given
func captivePortalCheckOutput(output string, defaultName string, overwrite bool) error {
	if output == "-" || overwrite {
		return nil
	}
	var filename = defaultName
	if output != "" {
		filename = output
	}
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func captivePortalCheckFileArgs(args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}
