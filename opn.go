package main

import (
	"opnsense-cli/cli"
	"os"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
