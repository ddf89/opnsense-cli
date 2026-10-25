package cli

import (
	"strconv"
	"strings"

	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/migration: the legacy firewall rules and outbound NAT rules of config.xml that are migrated to the
// current rule pages (Firewall > Rules > Migration assistant, api/firewall/migration)

var firewallMigrationTypes = []string{string(firewall.MigrationFilter), string(firewall.MigrationOutbound)}

var firewallMigrationWhat = map[firewall.MigrationKind]string{
	firewall.MigrationFilter:   "legacy firewall rules",
	firewall.MigrationOutbound: "legacy outbound NAT rules",
}

func init() {
	var menu = Root.Menu("firewall/migration")
	menu.Help = "migrate the legacy firewall and outbound NAT rules to the current rules"
	var kind = Arg{Name: "type", Positional: true, Required: true, Values: firewallMigrationTypes,
		Help: "filter (legacy firewall rules) or outbound (legacy outbound NAT rules)"}
	menu.Add(
		&Command{Name: "print", Help: "show how many legacy rules are left to migrate",
			Args: []Arg{{Name: "json", Type: Bool, Help: "one JSON object per type"}},
			Run:  firewallMigrationPrint},
		&Command{Name: "export", Help: "save the legacy rules as CSV in the import format of the current rules",
			Long: `Writes the legacy rules of type (filter or outbound) to file=, - for stdout; an existing file is only replaced
with overwrite. Check the file, then import it: filter rules with "/firewall/rule import", outbound rules with
"/firewall/nat/source import". Without legacy rules nothing is written.`,
			Args: []Arg{kind,
				{Name: "file", Required: true, Help: "the CSV file to write, - for stdout"},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			},
			Check: firewallRuleTransferCheckOutput,
			Run:   firewallMigrationExport},
		&Command{Name: "flush", Help: "delete all legacy rules of a type from the configuration",
			Long: `Run it after the migrated rules work: the legacy rules are removed from config.xml (the running ruleset
changes with the next filter reload). Export them first, only a configuration backup brings them back.`,
			Args:    []Arg{kind},
			Confirm: "This deletes all legacy rules of this type from the configuration, only a configuration backup brings them back.",
			Run:     firewallMigrationFlush},
	)
}

func firewallMigrationPrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, kind := range firewall.MigrationKinds {
		var count, countErr = api.MigrationCount(kind)
		if countErr != nil {
			return countErr
		}
		if args.Bool("json") {
			if err := c.JSON(map[string]any{"type": string(kind), "count": count}); err != nil {
				return err
			}
			continue
		}
		rows = append(rows, []string{string(kind), strconv.Itoa(count), firewallMigrationWhat[kind]})
	}
	if !args.Bool("json") {
		c.Table([]string{"TYPE", "COUNT", "DESCRIPTION"}, rows)
	}
	return nil
}

// firewallMigrationKind returns the type argument (checked against firewallMigrationTypes, case-insensitive)
func firewallMigrationKind(args *Args) firewall.MigrationKind {
	return firewall.MigrationKind(strings.ToLower(args.String("type")))
}

func firewallMigrationExport(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var kind = firewallMigrationKind(args)
	var content, exportErr = api.MigrationExport(kind)
	if exportErr != nil {
		return exportErr
	}
	return firewallRuleTransferSave(c, content, args.String("file"), args.Bool("overwrite"), firewallMigrationWhat[kind])
}

func firewallMigrationFlush(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var kind = firewallMigrationKind(args)
	var count, countErr = api.MigrationCount(kind)
	if countErr != nil {
		return countErr
	}
	if count == 0 {
		c.Infof("there are no %s, nothing to flush", firewallMigrationWhat[kind])
		return nil
	}
	return api.MigrationFlush(kind)
}
