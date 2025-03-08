package db

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	_ "modernc.org/sqlite"

	db "vulnerawise/pkg/models/database"
)

const (
	// DefaultAPIBaseURL is the default API endpoint for vulnerawise
	DefaultAPIBaseURL = "https://api.vulnerawise.ai"
)

// DownloadAndUpdateDB downloads and updates the database if needed
func DownloadAndUpdateDB(baseURL string) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}

	appDir := filepath.Join(configDir, "vulnerawise")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return fmt.Errorf("failed to create app directory: %w", err)
	}

	dbPath := filepath.Join(appDir, "vuln.db")
	metadataURL := baseURL + "/metadata.json"

	// Fetch metadata
	metadata, err := fetchMetadata(metadataURL)
	if err != nil {
		return fmt.Errorf("failed to fetch metadata: %w", err)
	}

	// Check if update is needed
	needsUpdate, err := shouldUpdateDB(dbPath, metadata)
	if err != nil {
		return fmt.Errorf("failed to check update status: %w", err)
	}

	if !needsUpdate {
		log.Println("Database is up to date")
		return nil
	}

	log.Println("Updating database...")
	return downloadAndProcessDB(baseURL, metadata, dbPath)

}

func fetchMetadata(url string) (*db.MetadataInfo, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch failed with status: %s", resp.Status)
	}

	var metadata db.MetadataInfo
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func shouldUpdateDB(dbPath string, metadata *db.MetadataInfo) (bool, error) {
	// Check if the file exists.
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist; update needed.
			return true, nil
		}
		return false, err
	}

	// File exists - validate its content.
	if err := validateDB(dbPath); err != nil {
		// Validation failed -- update needed.
		return true, nil
	}

	// Check modification time.
	if time.Since(fileInfo.ModTime()) > 24*time.Hour {
		return true, nil
	}

	// Check file hash.
	currentHash, err := calculateRecentEntriesHash(dbPath)
	if err != nil {
		return false, err
	}

	return currentHash != metadata.Hash, nil
}

func downloadAndProcessDB(baseURL string, metadata *db.MetadataInfo, targetPath string) error {
	tmpFile, err := os.CreateTemp("", "vuln-*.db.tgz")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	dbURL := fmt.Sprintf("%s/%s.tgz", baseURL, metadata.File)
	if err := downloadWithProgress(dbURL, tmpFile); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Decompress database
	decompressedPath := tmpFile.Name() + ".db"
	defer os.Remove(decompressedPath)

	if err := decompressDatabaseGzip(tmpFile.Name(), decompressedPath); err != nil {
		return fmt.Errorf("decompression failed: %w", err)
	}

	// Verify hash
	if err := verifyDatabaseHash(decompressedPath, metadata.Hash); err != nil {
		return fmt.Errorf("database integrity check failed: %w", err)
	}

	// Validate decompressed database
	if err := validateDB(decompressedPath); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Swap databases
	return atomicSwapDB(decompressedPath, targetPath)
}

func downloadWithProgress(url string, out *os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	bar := progressbar.NewOptions64(
		resp.ContentLength,
		progressbar.OptionSetDescription("Downloading database..."),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	_, err = io.Copy(io.MultiWriter(out, bar), resp.Body)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	return nil
}

// validateDB opens the database file and runs a simple query to validate it.
func validateDB(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open downloaded DB: %w", err)
	}
	defer db.Close()

	// Simple validation query: check if the DB has tables
	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if err != nil {
		return fmt.Errorf("validation query failed: %w", err)
	}
	if count == 0 {
		return errors.New("downloaded database is empty or invalid")
	} else {
		err = ValidateFTSTable(dbPath)
		if err != nil {
			return fmt.Errorf("validation query failed: %w", err)
		}
	}

	return nil
}

// Function to calculate hash of last 10 CVE entries
func calculateRecentEntriesHash(dbPath string) (string, error) {

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT cve_id, published_date, last_modified_date, epss_score
		FROM cve ORDER BY published_date DESC LIMIT 10;
	`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	hasher := sha256.New()
	for rows.Next() {
		var cveID, publishedDate, lastModifiedDate string
		var epssScore float64
		if err := rows.Scan(&cveID, &publishedDate, &lastModifiedDate, &epssScore); err != nil {
			return "", err
		}

		data := fmt.Sprintf("%s|%s|%s|%f", cveID, publishedDate, lastModifiedDate, epssScore)
		hasher.Write([]byte(data))
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// atomicSwapDB safely replaces the database file while ensuring existing connections continue to work.
func atomicSwapDB(newDB, liveDB string) error {
	backupDB := liveDB + ".backup"

	// Ensure new DB exists before replacing.
	if _, err := os.Stat(newDB); os.IsNotExist(err) {
		return fmt.Errorf("new database does not exist")
	}

	// Backup the current database (if it exists).
	if _, err := os.Stat(liveDB); err == nil {
		if err := os.Rename(liveDB, backupDB); err != nil {
			return fmt.Errorf("failed to backup old database: %w", err)
		}
	}

	// Windows requires ensuring file handles are closed before renaming.
	if runtime.GOOS == "windows" {
		log.Println("Waiting for SQLite file locks to release...")
		time.Sleep(2 * time.Second)
	}

	// Try renaming multiple times in case of a lock issue or cross-device link error.
	maxRetries := 5
	var err error

	for i := 0; i < maxRetries; i++ {
		err = os.Rename(newDB, liveDB)
		if err == nil {
			break
		}
		// If error indicates a cross-device link, attempt to copy instead.
		if strings.Contains(err.Error(), "invalid cross-device link") {
			if copyErr := copyFile(newDB, liveDB); copyErr != nil {
				err = copyErr
			} else {
				// Remove the source after successful copy.
				err = os.Remove(newDB)
				if err != nil {
					log.Printf("Warning: copied file but failed to remove the source: %v", err)
				}
				err = nil
				break
			}
		}
		log.Printf("Attempt %d/%d: Failed to rename DB: %v", i+1, maxRetries, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("database swap failed after retries: %w", err)
	}

	// Cleanup old backup file if it exists.
	if _, err := os.Stat(backupDB); err == nil {
		_ = os.Remove(backupDB)
	}

	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for copying: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file for copying: %w", err)
	}
	defer func() {
		_ = destFile.Close()
	}()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("error copying file contents: %w", err)
	}

	// Ensure the destination file has the same permissions.
	if info, err := os.Stat(src); err == nil {
		if err := os.Chmod(dst, info.Mode()); err != nil {
			return fmt.Errorf("failed to set file permissions: %w", err)
		}
	}

	return nil
}

func decompressDatabaseGzip(inputPath, outputPath string) error {
	// Open the compressed file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open compressed file: %v", err)
	}
	defer inFile.Close()

	// Create a gzip reader
	gzReader, err := gzip.NewReader(inFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	// Create a tar reader
	tarReader := tar.NewReader(gzReader)

	// Iterate through the files in the archive
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return fmt.Errorf("database file not found in archive")
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %v", err)
		}

		// Skip if not a regular file
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Check if this is the database file (should end with .db)
		if filepath.Ext(header.Name) == ".db" {
			// Create the output file
			outFile, err := os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			defer outFile.Close()

			// Copy the file contents
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("failed to extract database: %v", err)
			}
			return nil
		}
	}
}

func verifyDatabaseHash(dbPath string, expectedHash string) error {
	actualHash, err := calculateRecentEntriesHash(dbPath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash of extracted database: %w", err)
	}

	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch after decompression:\nExpected: %s\nGot: %s",
			expectedHash, actualHash)
	}
	return nil
}

func CheckAndUpdateIfNeeded(baseURL string) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get user config directory: %w", err)
	}

	dbPath := filepath.Join(configDir, "vulnerawise", "vuln.db")

	// Check DB file modification time before fetching metadata
	if fileInfo, err := os.Stat(dbPath); err == nil {
		if time.Since(fileInfo.ModTime()) < 24*time.Hour {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat database file: %w", err)
	}

	metadataURL := baseURL + "/metadata.json"
	metadata, err := fetchMetadata(metadataURL)
	if err != nil {
		// Optionally, ignore error if metadata fetch fails
		return nil
	}

	needsUpdate, err := shouldUpdateDB(dbPath, metadata)
	if err != nil {
		return fmt.Errorf("failed to check update status: %w", err)
	}

	if needsUpdate {
		log.Println("Database update available. Updating...")
		return DownloadAndUpdateDB(baseURL)
	}

	return nil
}
