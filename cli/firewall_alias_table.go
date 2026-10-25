package cli

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// /firewall/alias/table: the live pf tables behind the aliases (Firewall > Diagnostics > Aliases). Changes here
// act on pf directly; they last until the alias is reloaded (apply), except for host and network aliases, where
// OPNsense also saves the address in the alias content

const firewallAliasTableHelp = "the alias (pf table), see print"

func init() {
	var menu = Root.Menu("firewall/alias/table")
	menu.Help = "the live pf tables of the aliases: show, add and remove addresses (Firewall > Diagnostics > Aliases)"
	var alias = func(required bool) Arg {
		return Arg{Name: "alias", Positional: true, Required: required, Help: firewallAliasTableHelp, Complete: firewallAliasTableComplete}
	}
	var address = Arg{Name: "address", Required: true, Validate: firewallAliasTableValidateAddress,
		Help: "an IP address or network (CIDR)"}
	const savedNote = `For host and network aliases OPNsense also saves the change in the alias content, for the other
types it lasts until the alias is reloaded (apply).`

	menu.Add(
		&Command{
			Name: "print",
			Help: "list the pf tables with their number of entries, or the addresses in one table",
			Args: []Arg{alias(false), {Name: "json", Type: Bool, Help: "one JSON object per line"}},
			Run:  firewallAliasTablePrint,
		},
		&Command{Name: "add", Help: "add an address to the live table of an alias", Long: savedNote,
			Args: []Arg{alias(true), address}, Run: firewallAliasTableAdd},
		&Command{Name: "remove", Help: "remove an address from the live table of an alias", Long: savedNote,
			Args: []Arg{alias(true), address}, Run: firewallAliasTableRemove},
		&Command{
			Name:    "flush",
			Help:    "remove all addresses from the live table of an alias",
			Long:    `The table is filled again when the alias is reloaded (apply).`,
			Args:    []Arg{alias(true)},
			Confirm: "This empties the live pf table of the alias: rules using it stop matching its addresses until it is reloaded.",
			Run:     firewallAliasTableFlush,
		},
		&Command{
			Name: "find",
			Help: "list the aliases whose table contains an address",
			Args: []Arg{{Name: "address", Positional: true, Required: true, Validate: firewallAliasTableValidateAddress,
				Help: "the IP address (or network) to look for"}},
			Run: firewallAliasTableFind,
		},
		&Command{
			Name: "update-bogons",
			Help: "download the current bogon networks and reload the bogons tables",
			Run:  firewallAliasTableUpdateBogons,
		},
	)
}

// firewallAliasTableValidateAddress accepts an IP address or network; OPNsense only accepts lower case
func firewallAliasTableValidateAddress(value string) error {
	if _, err := netip.ParseAddr(value); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return nil
	}
	return fmt.Errorf("must be an IP address or network like 10.0.0.0/8, got %q", value)
}

func firewallAliasTablePrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	if name := args.String("alias"); name != "" {
		var entries, entriesErr = api.AliasTableEntries(name)
		if entriesErr != nil {
			return entriesErr
		}
		if args.Bool("json") {
			for _, entry := range entries {
				if err := c.JSON(map[string]string{"ip": entry}); err != nil {
					return err
				}
			}
			return nil
		}
		var rows = make([][]string, 0, len(entries))
		for _, entry := range entries {
			rows = append(rows, []string{entry})
		}
		c.Table([]string{"ADDRESS"}, rows)
		return nil
	}

	tables, err := api.AliasTables()
	if err != nil {
		return err
	}
	sizes, err := api.AliasTableSize()
	if err != nil {
		return err
	}
	if args.Bool("json") {
		for _, table := range tables {
			var stat, known = sizes.Details[table]
			var object = map[string]any{"name": table, "entries": nil, "updated": stat.Updated}
			if known {
				object["entries"] = stat.Count
			}
			if err := c.JSON(object); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, 0, len(tables))
	for _, table := range tables {
		var entries string
		var stat, known = sizes.Details[table]
		if known {
			entries = strconv.Itoa(stat.Count)
		}
		rows = append(rows, []string{table, entries, strings.Replace(strings.SplitN(stat.Updated, ".", 2)[0], "T", " ", 1)})
	}
	c.Table([]string{"NAME", "ENTRIES", "UPDATED"}, rows)
	c.Infof("%d of %d table entries in use", sizes.Used, sizes.Size)
	return nil
}

func firewallAliasTableAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasTableAdd(args.String("alias"), strings.ToLower(args.String("address")))
}

func firewallAliasTableRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasTableDelete(args.String("alias"), strings.ToLower(args.String("address")))
}

func firewallAliasTableFlush(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasTableFlush(args.String("alias"))
}

func firewallAliasTableFind(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var address = strings.ToLower(args.String("address"))
	matches, err := api.AliasFindReferences(address)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		c.Infof("no alias table contains %s", address)
		return nil
	}
	for _, match := range matches {
		c.Println(match)
	}
	return nil
}

func firewallAliasTableUpdateBogons(c *Context, _ *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	return api.AliasUpdateTables("bogons")
}

func firewallAliasTableComplete(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var tables, listErr = api.AliasTables()
	if listErr != nil {
		return nil
	}
	return tables
}
