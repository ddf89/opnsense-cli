package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"opnsense-cli/opnsense/api/firewall"
)

// /firewall/rule export and import: the CSV format of the GUI's "Export as csv" / "Import csv" of Firewall > Rules
// (api/firewall/filter/download_rules, upload_rules). The rest of /firewall/rule lives in firewall_rule.go

const firewallRuleTransferImportHelp = `The file is a CSV like export writes (separated by ; or , with a header row). The import adds and
updates, it never removes: a row whose @uuid is an existing rule overwrites that rule's fields given in the file,
every other row (empty or unknown @uuid) adds a rule. Categories and the overload alias are given by name, the
order columns sort_order and prio_group are ignored. The file is checked before anything is sent (CSV syntax, the
same number of columns in every row, @uuid format, known column names).
When OPNsense rejects rows it tries again without them and saves the others if they are valid on their own, so
check the rules after an error. The rules are saved, they take effect when the firewall rules are applied.`

func init() {
	var menu = Root.Menu("firewall/rule")
	menu.Add(
		&Command{Name: "export", Help: "save the firewall rules as CSV, the format of the GUI export",
			Long: `Writes the rules (all fields, "@uuid" first, ; separated) to file=, - for stdout. An existing file is only
replaced with overwrite. Without rules nothing is written.`,
			Args: []Arg{
				{Name: "file", Positional: true, Required: true, Help: "the CSV file to write, - for stdout"},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			},
			Check: firewallRuleTransferCheckOutput,
			Run:   firewallRuleExport},
		&Command{Name: "import", Help: "add and update firewall rules from a CSV file (like the GUI import)",
			Long: firewallRuleTransferImportHelp,
			Args: []Arg{
				{Name: "file", Positional: true, Required: true, Help: "the CSV file to import"},
			},
			Confirm: "This adds firewall rules and overwrites the rules whose @uuid is in the file (no rule is removed).",
			Check:   firewallRuleImportCheck,
			Run:     firewallRuleImport},
	)
}

// firewallRuleTransferCheckOutput rejects overwrite with stdout
func firewallRuleTransferCheckOutput(args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}

// firewallRuleTransferSave writes a CSV export to file (- for stdout). Existing files are only replaced with
// overwrite. An empty export (nothing to export) writes nothing
func firewallRuleTransferSave(c *Context, content []byte, file string, overwrite bool, what string) error {
	if len(content) == 0 {
		c.Infof("there are no %s, nothing exported", what)
		return nil
	}
	if file == "-" {
		_, err := c.Out.Write(content)
		return err
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	var handle, err = os.OpenFile(file, flags, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", file)
		}
		return err
	}
	if _, err := handle.Write(content); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	if parsed, parseErr := firewall.FilterRulesParseCsv(content); parseErr == nil {
		c.Infof("saved %d %s to %s", len(parsed.Rows), what, file)
	} else {
		c.Infof("saved %s (%d bytes)", file, len(content))
	}
	return nil
}

func firewallRuleExport(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var content, exportErr = api.FilterRulesExport()
	if exportErr != nil {
		return exportErr
	}
	return firewallRuleTransferSave(c, content, args.String("file"), args.Bool("overwrite"), "firewall rules")
}

// firewallRuleImportRead reads and checks the CSV file
func firewallRuleImportRead(file string) ([]byte, firewall.FilterRulesCsv, error) {
	if file == "-" {
		return nil, firewall.FilterRulesCsv{}, errors.New("file: reading stdin is not supported, give a file name")
	}
	var content, err = os.ReadFile(file)
	if err != nil {
		return nil, firewall.FilterRulesCsv{}, fmt.Errorf("file: %w", err)
	}
	parsed, err := firewall.FilterRulesParseCsv(content)
	if err != nil {
		return nil, parsed, fmt.Errorf("%s: %w", file, err)
	}
	return content, parsed, nil
}

func firewallRuleImportCheck(args *Args) error {
	var _, _, err = firewallRuleImportRead(args.String("file"))
	return err
}

func firewallRuleImport(c *Context, args *Args) error {
	var file = args.String("file")
	var content, parsed, err = firewallRuleImportRead(file)
	if err != nil {
		return err
	}
	api, err := firewallApi(c)
	if err != nil {
		return err
	}

	// OPNsense silently ignores unknown columns, a misspelled column would quietly import nothing for it
	columns, err := api.FilterRulesColumns()
	if err != nil {
		return err
	}
	var unknown []string
	for _, name := range parsed.Header {
		if !slices.Contains(columns, name) && name != "sort_order" && name != "prio_group" {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s: unknown columns %s, valid are: %s", file, strings.Join(unknown, ", "), strings.Join(columns, ", "))
	}

	result, err := api.FilterRulesImport(content, filepath.Base(file))
	if err != nil {
		return err
	}
	if len(result.Validations) == 0 {
		c.Infof("imported %s: %d rules added, %d updated", file, result.Inserted, result.Updated)
		return nil
	}
	var lines []string
	for _, validation := range result.Validations {
		var where = "file"
		if validation.Row >= 0 {
			where = fmt.Sprintf("line %d", validation.Row+2)
		}
		var field = ""
		if validation.Field != "" {
			field = validation.Field + ": "
		}
		lines = append(lines, fmt.Sprintf("  %s: %s%s", where, field, validation.Message))
	}
	return fmt.Errorf("OPNsense rejected rows of %s:\n%s\nthe other rows were saved if they are valid without the rejected ones, check the rules",
		file, strings.Join(lines, "\n"))
}
