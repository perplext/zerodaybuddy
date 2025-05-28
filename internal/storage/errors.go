package storage

import (
	"database/sql"
	"errors"
)

// wrapSQLError converts sql.ErrNoRows to ErrNotFound
func wrapSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}