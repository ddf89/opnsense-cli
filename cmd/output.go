package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// printTable prints rows as aligned columns, empty cells are shown as "-"
func printTable(headers []string, rows [][]string) {
	var writer = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		var cells = make([]string, len(row))
		for i, cell := range row {
			if cell == "" {
				cell = "-"
			}
			cells[i] = cell
		}
		_, _ = fmt.Fprintln(writer, strings.Join(cells, "\t"))
	}
	_ = writer.Flush()
}

// printFields prints a single record as "key: value" lines, in the given order
func printFields(fields [][2]string) {
	var writer = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, field := range fields {
		_, _ = fmt.Fprintf(writer, "%s:\t%s\n", field[0], field[1])
	}
	_ = writer.Flush()
}
