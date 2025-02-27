package db

import (
	"database/sql"
	"fmt"

	// SQLite driver

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// Init initializes the database connection. If inMemoryOptional is provided
// and true, the on-disk database is copied into an in-memory database.
func Init(databasePath string) error {

	// Open the SQLite database with additional parameters.
	diskDB, err := sql.Open("sqlite", databasePath+"?mode=roc&cache=shared&_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("failed to open disk DB: %w", err)
	}

	// Verify the connection.
	if err := diskDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping disk DB: %w", err)
	}

	// Assign the global DB variable.
	DB = diskDB
	return nil
}

// Get returns the initialized database connection.
func Get() *sql.DB {
	return DB
}
