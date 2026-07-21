// Package migrations embeds the server's append-only Postgres migrations.
package migrations

import "embed"

// FS contains every goose migration shipped by the server.
//
//go:embed *.sql
var FS embed.FS
