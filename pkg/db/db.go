package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	// SQLite driver
	_ "github.com/mattn/go-sqlite3"
	"github.com/mattn/go-sqlite3"
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
func Init(databasePath string, inMemoryOptional ...bool) error {
	inMemory := false
	if len(inMemoryOptional) > 0 {
		inMemory = inMemoryOptional[0]
	}

	// -------------------------------------------------------------
	// 1) Ensure the DB file exists for either mode (disk or memory).
	//    We only call EnsureDBFileExists once, so no duplication!
	// -------------------------------------------------------------
	if err := EnsureDBFileExists(databasePath, ""); err != nil {
		return err
	}

	if !inMemory {
		// --- Normal on-disk mode ---
		diskDB, err := sql.Open("sqlite3", databasePath)
		if err != nil {
			return fmt.Errorf("failed to open disk DB: %w", err)
		}
		if err := diskDB.Ping(); err != nil {
			return fmt.Errorf("failed to ping disk DB: %w", err)
		}
		DB = diskDB
		return nil
	}

	// --- In-memory mode (copy disk -> mem) ---

	// 2) Open the in-memory DB.
	memDB, err := sql.Open("sqlite3", "file:memdb?mode=memory&cache=shared")
	if err != nil {
		return fmt.Errorf("failed to open in-memory DB: %w", err)
	}

	// 3) Open the disk DB to copy its data.
	diskDB, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		_ = memDB.Close()
		return fmt.Errorf("failed to open disk DB: %w", err)
	}
	defer diskDB.Close()

	// 4) Copy data from disk to memory using the driver's Backup function.
	if err := copyDatabase(diskDB, memDB); err != nil {
		_ = memDB.Close()
		return fmt.Errorf("failed to copy disk DB into memory: %w", err)
	}

	// 5) Ensure the in-memory DB is responsive.
	if err := memDB.Ping(); err != nil {
		_ = memDB.Close()
		return fmt.Errorf("failed to ping in-memory DB: %w", err)
	}

	DB = memDB
	log.Printf("[Init] Loaded DB from %s into memory.", databasePath)
	return nil
}

// copyDatabase uses the raw SQLiteConn.Backup() API to copy all data
// from src (disk) to dst (memory).
func copyDatabase(src, dst *sql.DB) error {
	// Get a connection handle to the source database.
	srcConn, err := src.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get src connection: %w", err)
	}
	defer srcConn.Close()

	// Get a connection handle to the destination database.
	dstConn, err := dst.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get dst connection: %w", err)
	}
	defer dstConn.Close()

	// Convert the connections to driver-specific SQLiteConn.
	var dconnSrc *sqlite3.SQLiteConn
	if err := srcConn.Raw(func(driverConn interface{}) error {
		var ok bool
		dconnSrc, ok = driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("source connection is not a *sqlite3.SQLiteConn")
		}
		return nil
	}); err != nil {
		return err
	}

	var dconnDst *sqlite3.SQLiteConn
	if err := dstConn.Raw(func(driverConn interface{}) error {
		var ok bool
		dconnDst, ok = driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("destination connection is not a *sqlite3.SQLiteConn")
		}
		return nil
	}); err != nil {
		return err
	}

	// Create the backup handle.
	backup, err := dconnDst.Backup("main", dconnSrc, "main")
	if err != nil {
		return fmt.Errorf("backup creation error: %w", err)
	}

	// Perform the backup (copy all pages).
	_, err = backup.Step(-1)
	if err != nil {
		_ = backup.Finish() // Ensure the backup is finalized on error.
		return fmt.Errorf("backup step error: %w", err)
	}

	// Finalize the backup process.
	if err := backup.Finish(); err != nil {
		return fmt.Errorf("backup finish error: %w", err)
	}

	return nil
}

// Get returns the initialized database connection.
func Get() *sql.DB {
	return DB
}
