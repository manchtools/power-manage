package dynamicsql

import "context"

type DB interface {
	Exec(context.Context, string, ...any) error
}

func update(ctx context.Context, db DB, statement string) error {
	return db.Exec(ctx, statement)
}
