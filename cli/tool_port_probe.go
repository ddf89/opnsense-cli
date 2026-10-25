package cli

import (
	"fmt"
	"opnsense-cli/opnsense/api/diagnostics"
	"strings"
)

// /tool port-probe: Interfaces > Diagnostics > Port Probe (api/diagnostics/portprobe/set runs "nc -z" on the
// firewall, 10 seconds timeout)

func init() {
	Root.Menu("tool").Add(&Command{
		Name: "port-probe",
		Help: "test whether the firewall can open a TCP connection to a host and port",
		Long: `Connects from the firewall with netcat (10 seconds timeout) and prints its message. A connection that
could not be established is an error (exit code 1). show-text reads what the remote end sends after
connecting (e.g. an SSH or SMTP banner) and prints it.

  port-probe 192.168.1.10 port=443
  port-probe mail.example.com port=25 show-text`,
		Args: []Arg{
			toolDiagAddressArg("host name or address to connect to"),
			{Name: "port", Type: Int, Required: true, Help: "TCP port to connect to", Validate: ValidatePort},
			toolDiagSourceArg,
			{Name: "source-port", Type: Int, Help: "the local port to connect from", Validate: ValidatePort},
			toolDiagFamilyArg,
			{Name: "show-text", Type: Bool, Help: "print what the remote end sends"},
			{Name: "json", Type: Bool, Help: "print the raw result as one JSON object"},
		},
		Check: toolDiagCheckFamily,
		Run:   toolPortProbeRun,
	})
}

func toolPortProbeRun(c *Context, args *Args) error {
	var api, err = ifaceDiagnostics(c)
	if err != nil {
		return err
	}
	var options = diagnostics.PortProbeOptions{
		Hostname:      args.String("address"),
		Port:          args.Int("port"),
		Family:        toolDiagInet(toolDiagFamily(args)),
		SourceAddress: args.String("source"),
		SourcePort:    args.Int("source-port"),
		ShowText:      args.Bool("show-text"),
	}
	result, err := systemActivityAwait(c, func() (diagnostics.PortProbeResult, error) { return api.PortProbe(options) })
	if c.Err() != nil {
		return nil // Ctrl-C
	}
	if err != nil {
		return err
	}
	if args.Bool("json") {
		if err := c.JSON(result.Raw); err != nil {
			return err
		}
	} else {
		if result.Succeeded() {
			c.Println(result.Message)
		}
		if result.Payload != "" {
			c.Println(strings.TrimRight(result.Payload, "\r\n"))
		}
	}
	if !result.Succeeded() {
		var message = strings.TrimPrefix(result.Message, "nc: ")
		if message == "" {
			message = "no answer from netcat"
		}
		return fmt.Errorf("port-probe %s port %d: %s", options.Hostname, options.Port, message)
	}
	return nil
}
