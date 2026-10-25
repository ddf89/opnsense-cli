package cli

import (
	"fmt"
	"strings"
	"time"
)

// /check: one authenticated read-only API call to see whether OPNsense is reachable and accepts the credentials,
// like a ping for the API. Exit code 0 when it works, 1 with the failed step and a hint otherwise

func init() {
	Root.Add(&Command{
		Name: "check",
		Help: "check the connection to the OPNsense API (reachability, TLS, credentials)",
		Long: `Makes one read-only API call with the configured OPN_URL, OPN_APIKEY and OPN_APISECRET and prints the
firewall's host name and versions. When it fails, the error names the step (dns, connect, tls, auth, api)
and how to fix it. The exit code is 0 only when the API works, so scripts can use "opn /check".`,
		Args: []Arg{
			{Name: "timeout", Type: Duration, Default: "10s", Help: "give up after this long", Validate: checkValidateTimeout},
			{Name: "json", Type: Bool, Help: "print the result as one JSON object"},
		},
		Run: func(c *Context, args *Args) error {
			var opn, err = c.Api()
			if err != nil {
				return err
			}
			result, err := opn.Check(c, args.Duration("timeout"))
			if err != nil {
				return err
			}
			var latency = result.Latency.Round(time.Millisecond)
			if args.Bool("json") {
				return c.JSON(map[string]any{
					"url": result.Url, "status": "ok", "hostname": result.Hostname, "versions": result.Versions,
					"tls": result.Tls, "protocol": result.Protocol, "latency_ms": latency.Milliseconds(),
				})
			}
			var tls = result.Tls
			if tls == "not verified" {
				tls += " (OPN_NOSSLVERIFY=1)"
			}
			c.Fields([][2]string{
				{"url", result.Url},
				{"status", "ok"},
				{"hostname", result.Hostname},
				{"versions", strings.Join(result.Versions, ", ")},
				{"tls", tls},
				{"protocol", result.Protocol},
				{"latency", latency.String()},
			})
			return nil
		},
	})
}

func checkValidateTimeout(value string) error {
	var duration, err = parseDuration(value)
	if err != nil {
		return err
	}
	if duration < time.Second || duration > 10*time.Minute {
		return fmt.Errorf("must be between 1s and 10m, got %s", value)
	}
	return nil
}
