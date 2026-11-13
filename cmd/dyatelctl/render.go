package main

import (
	"fmt"
	"io"
	"strings"
)

// Human output helpers. Everything goes to stdout as plain aligned text so
// it pipes cleanly (grep, cut, column); --json switches to raw passthrough.

// kv is one key/value row for printKV; order matters, so rows stay a slice.
type kv struct{ key, val string }

func printKV(w io.Writer, rows []kv) {
	width := 0
	for _, r := range rows {
		if len(r.key) > width {
			width = len(r.key)
		}
	}
	for _, r := range rows {
		fmt.Fprintf(w, "%-*s  %s\n", width, r.key, r.val)
	}
}

func printTable(w io.Writer, headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	for i, h := range headers {
		fmt.Fprintf(w, "%-*s  ", widths[i], h)
	}
	fmt.Fprintln(w)
	for i := range headers {
		fmt.Fprint(w, strings.Repeat("-", widths[i]), "  ")
	}
	fmt.Fprintln(w)
	for _, row := range rows {
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Fprintf(w, "%-*s  ", widths[i], cell)
		}
		fmt.Fprintln(w)
	}
}

// dash renders an empty string or a nil pointer as '-': missing consumer
// fields (before key registration) must not print as blank cells.
func dash[T string | *string](v T) string {
	switch s := any(v).(type) {
	case string:
		if s == "" {
			return "-"
		}
		return s
	case *string:
		if s == nil {
			return "-"
		}
		return *s
	}
	return "-"
}
