package cli

import (
	"runtime"
	"runtime/debug"
)

// Version is the release version, set at build time (Makefile, release workflow) with
// -ldflags "-X opnsense-cli/cli.Version=<tag>"
var Version = "dev"

// /version: the version of opn itself, needs no configuration and sends nothing to the firewall

func init() {
	Root.Add(&Command{
		Name: "version",
		Help: "show the version of opn",
		Long: `Prints the version of opn (the release tag it was built from, "dev" for other builds) and nothing
else, so scripts can use "opn version". detail adds the Go version and the platform. Needs no
configuration and contacts no firewall, "opn --version" is the same.`,
		Args: []Arg{{Name: "detail", Type: Bool, Help: "also show the Go version and the platform"}},
		Run: func(c *Context, args *Args) error {
			if !args.Bool("detail") {
				c.Println(versionString())
				return nil
			}
			c.Fields([][2]string{
				{"version", versionString()},
				{"go", runtime.Version()},
				{"platform", runtime.GOOS + "/" + runtime.GOARCH},
			})
			return nil
		},
	})
}

// versionString is Version, for builds without one "dev" plus the git revision when go build recorded it
func versionString() string {
	if Version != "dev" {
		return Version
	}
	var info, ok = debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision == "" {
		return Version
	}
	var version = Version + "-" + revision[:min(12, len(revision))]
	if modified == "true" {
		version += "-dirty"
	}
	return version
}
