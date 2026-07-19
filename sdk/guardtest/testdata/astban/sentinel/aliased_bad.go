package sentinel

import (
	dbsql "database/sql"
	"errors"
)

// Planted violation: the import alias must not hide the sentinel.
func isMissingAliased(err error) bool { return errors.Is(err, dbsql.ErrNoRows) }
