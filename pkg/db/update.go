package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/schollz/progressbar/v3"

	_ "github.com/mattn/go-sqlite3"
)

// DownloadAndUpdateDB downloads the database from the given URL,
// validates it using a simple query, and overwrites the existing vuln.db.
// The file is stored in the user's config directory under "vulnerawise/vuln.db".
func DownloadAndUpdateDB(dbURL string) error {
	// Get the user's config directory.
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}

	// Create a subdirectory for your application.
	appDir := filepath.Join(configDir, "vulnerawise")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return fmt.Errorf("failed to create app directory: %w", err)
	}

	// Full path to the target database file.
	targetPath := filepath.Join(appDir, "vuln.db")

	// Download the DB to a temporary file.
	tmpFile, err := os.CreateTemp("", "vuln-*.db")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	// Ensure the temp file is closed and removed.
	defer tmpFile.Close()
	tmpFileName := tmpFile.Name()
	defer os.Remove(tmpFileName)

	// Create a context with timeout for the HTTP request.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dbURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download DB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// If Content-Length is provided, set up a progress bar.
	if resp.ContentLength > 0 {
		bar := progressbar.DefaultBytes(
			resp.ContentLength,
			"downloading",
		)
		// Use TeeReader to update the progress bar while writing to file.
		if _, err = io.Copy(tmpFile, io.TeeReader(resp.Body, bar)); err != nil {
			return fmt.Errorf("failed to write to temporary file: %w", err)
		}
	} else {
		// Otherwise, just copy without a progress bar.
		if _, err = io.Copy(tmpFile, resp.Body); err != nil {
			return fmt.Errorf("failed to write to temporary file: %w", err)
		}
	}

	// Ensure all data is flushed to disk.
	if err = tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	// Close is already deferred.

	// Validate the downloaded database with a simple query.
	if err := validateDB(tmpFileName); err != nil {
		return fmt.Errorf("downloaded DB validation failed: %w", err)
	}

	// Overwrite the existing database file.
	if err := replaceFile(tmpFileName, targetPath); err != nil {
		return fmt.Errorf("failed to replace database file: %w", err)
	}

	log.Printf("Database successfully downloaded and updated at %s", targetPath)
	return nil
}

// validateDB opens the database file and runs a simple query to validate it.
func validateDB(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded DB: %w", err)
	}
	defer db.Close()

	// Simple validation query: count the number of tables in the database.
	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if err != nil {
		return fmt.Errorf("validation query failed: %w", err)
	}
	if count == 0 {
		return errors.New("downloaded database is empty or invalid")
	}
	return nil
}

// replaceFile attempts to rename src to dst; if that fails (e.g., due to cross-device link),
// it falls back to copying the file.
// It uses a named return variable so that errors captured in deferred functions propagate.
func replaceFile(src, dst string) (err error) {
	// Attempt to rename first.
	if err = os.Rename(src, dst); err == nil {
		return nil
	}

	// Fallback: copy the file content.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	// Use a named return to capture error from deferred closure.
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
