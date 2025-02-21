package db

import (
	"database/sql"
	"fmt"
	"log"

	// SQLite driver

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// EnsureDBFileExists checks if the local DB file (databasePath) is present.
// If not, it downloads it using your existing DownloadAndUpdateDB function.
func EnsureDBFileExists(databasePath, fromURL string) error {
	if err := validateDB(databasePath); err == nil {
		return nil
	}

	// If we're here, the file does NOT exist. Let's download it.
	url := fromURL
	if url == "" {
		url = "https://api.vulnerawise.ai/vulnerabilities.db"
	}

	fmt.Printf("Local DB file not found or not valid. Downloading latest database\n")

	// Call the DownloadAndUpdateDB function (same db package) to download the file.
	if err := DownloadAndUpdateDB(url); err != nil {
		log.Printf("Error updating database: %v", err)
		return fmt.Errorf("database download failed: %w", err)
	}

	fmt.Println("Database download process completed.")
	return nil
}

// Init initializes the database connection. If inMemoryOptional is provided
// and true, the on-disk database is copied into an in-memory database.
func Init(databasePath string) error {

	// -------------------------------------------------------------
	// 1) Ensure the DB file exists for either mode (disk or memory).
	//    We only call EnsureDBFileExists once, so no duplication!
	// -------------------------------------------------------------
	if err := EnsureDBFileExists(databasePath, ""); err != nil {
		return err
	}

	// Open the SQLite database.
	diskDB, err := sql.Open("sqlite3", databasePath)
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
