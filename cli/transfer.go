package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// export and import commands for the CSV download_* / upload_* endpoints of OPNsense's grids (the GUI's
// "Export as csv" / "Import csv"). A menu describes its transfer with a CsvTransfer and adds
// transfer.ExportCommand() and transfer.ImportCommand(); the library side is coreapi.DownloadCsv / UploadCsv

// CsvTransfer describes the CSV export / import of one menu
type CsvTransfer struct {
	// What names the records in messages, plural ("hosts", "reservations")
	What string
	// Export returns the CSV (empty when there is nothing to export)
	Export func(c *Context) ([]byte, error)
	// Import uploads the CSV; filename is informative
	Import func(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error)
	// Columns returns the columns the import understands (optional); a file with other columns is refused before
	// anything is sent, because OPNsense silently ignores unknown columns
	Columns func(c *Context) ([]string, error)
	// Key describes how the import matches existing records, e.g. "host, domain and ip" (shown in the help)
	Key string
	// Note is added to both helps, e.g. what the export leaves out or how to apply the import
	Note string
}

// ExportCommand returns the export command: file= (positional, - for stdout) and overwrite
func (t CsvTransfer) ExportCommand() *Command {
	return &Command{Name: "export", Help: "save the " + t.What + " as CSV, the format of the GUI export",
		Long: strings.TrimSpace(fmt.Sprintf(`Writes the %s (';' separated, with a header row) to file=, - for stdout. An existing file is only replaced
with overwrite. Without %s nothing is written.
%s`, t.What, t.What, t.Note)),
		Args: []Arg{
			{Name: "file", Positional: true, Required: true, Help: "the CSV file to write, - for stdout"},
			{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
		},
		Check: transferCheckOutput,
		Run: func(c *Context, args *Args) error {
			var content, err = t.Export(c)
			if err != nil {
				return err
			}
			return transferSave(c, content, args.String("file"), args.Bool("overwrite"), t.What)
		},
	}
}

// ImportCommand returns the import command: file= (positional), asks for confirmation
func (t CsvTransfer) ImportCommand() *Command {
	return &Command{Name: "import", Help: "add and update " + t.What + " from a CSV file (like the GUI import)",
		Long: strings.TrimSpace(fmt.Sprintf(`The file is a CSV like export writes (separated by ; or , with a header row). The import adds and updates,
it never removes: a row matching an existing record by %s overwrites that record's fields given in the file,
every other row adds a record. The file is checked before anything is sent (CSV syntax, the same number of
columns in every row, known column names).
When OPNsense rejects rows it tries again without them and saves the others if they are valid on their own, so
check the %s after an error.
%s`, t.Key, t.What, t.Note)),
		Args:    []Arg{{Name: "file", Positional: true, Required: true, Help: "the CSV file to import"}},
		Confirm: fmt.Sprintf("This adds %s and overwrites those matching by %s (nothing is removed).", t.What, t.Key),
		Check: func(args *Args) error {
			var _, _, err = transferRead(args.String("file"), t.What)
			return err
		},
		Run: t.runImport,
	}
}

func (t CsvTransfer) runImport(c *Context, args *Args) error {
	var file = args.String("file")
	var content, parsed, err = transferRead(file, t.What)
	if err != nil {
		return err
	}
	if t.Columns != nil {
		var columns, columnsErr = t.Columns(c)
		if columnsErr != nil {
			return columnsErr
		}
		var unknown []string
		for _, name := range parsed.Header {
			if !slices.Contains(columns, name) {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			return fmt.Errorf("%s: unknown columns %s, valid are: %s", file, strings.Join(unknown, ", "), strings.Join(columns, ", "))
		}
	}
	result, err := t.Import(c, content, filepath.Base(file))
	if err != nil {
		return err
	}
	return transferReport(c, file, t.What, result)
}

// transferCheckOutput rejects overwrite with stdout
func transferCheckOutput(args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}

// transferSave writes a CSV export to file (- for stdout), mode 0600 because exports can hold secrets. Existing
// files are only replaced with overwrite. An empty export (nothing to export) writes nothing
func transferSave(c *Context, content []byte, file string, overwrite bool, what string) error {
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
	if parsed, parseErr := coreapi.ParseCsv(content, what); parseErr == nil {
		c.Infof("saved %d %s to %s", len(parsed.Rows), what, file)
	} else {
		c.Infof("saved %s (%d bytes)", file, len(content))
	}
	return nil
}

// transferRead reads and checks an import file
func transferRead(file string, what string) ([]byte, coreapi.Csv, error) {
	if file == "-" {
		return nil, coreapi.Csv{}, errors.New("file: reading stdin is not supported, give a file name")
	}
	var content, err = os.ReadFile(file)
	if err != nil {
		return nil, coreapi.Csv{}, fmt.Errorf("file: %w", err)
	}
	parsed, err := coreapi.ParseCsv(content, what)
	if err != nil {
		return nil, parsed, fmt.Errorf("%s: %w", file, err)
	}
	return content, parsed, nil
}

// transferReport prints the counts of an import, or fails with the rejected rows
func transferReport(c *Context, file string, what string, result coreapi.CsvImportResult) error {
	if len(result.Validations) == 0 {
		c.Infof("imported %s: %d %s added, %d updated", file, result.Inserted, what, result.Updated)
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
	return fmt.Errorf("OPNsense rejected rows of %s:\n%s\nthe other rows were saved if they are valid without the rejected ones, check the %s",
		file, strings.Join(lines, "\n"), what)
}
