// Package migrations embeds the SQL migration files.
package migrations

import "embed"

// FS holds all *.sql migrations (up and down).
//
//go:embed *.sql
var FS embed.FS
