package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Check if the FTS table exists and is populated
func ValidateFTSTable(dbPath string) error {

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// First check if the FTS table exists
	var tableExists int
	err = db.QueryRowContext(
		context.Background(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cve_description_fts'",
	).Scan(&tableExists)
	if err != nil {
		return fmt.Errorf("failed to query sqlite_master: %v", err)
	}

	if tableExists == 0 {
		// FTS table doesn't exist, initialize it
		return initializeFTS(db)
	}

	// Now check if it has data by running a test query
	var testCveID string
	err = db.QueryRowContext(
		context.Background(),
		"SELECT cve.cve_id FROM cve JOIN cve_description_fts ON cve.cve_id = cve_description_fts.cve_id WHERE cve_description_fts MATCH 'vulnerability' LIMIT 1",
	).Scan(&testCveID)

	if err != nil {
		if err == sql.ErrNoRows {
			return initializeFTS(db)
		}
		return fmt.Errorf("failed to run test FTS query: %w", err)
	}

	return nil
}

func initializeFTS(db *sql.DB) error {
	_, err := db.Exec(`PRAGMA foreign_keys = ON;`)
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	// Create the FTS5 virtual table
	_, err = db.Exec(`
	CREATE VIRTUAL TABLE IF NOT EXISTS cve_description_fts USING fts5(cve_id, description);
	`)
	if err != nil {
		return fmt.Errorf("failed to create FTS5 table: %v", err)
	}

	// **Delete & Insert instead of UPSERT**
	_, err = db.Exec(`
	DELETE FROM cve_description_fts WHERE cve_id IN (SELECT cve_id FROM cve WHERE description IS NOT NULL);
	INSERT INTO cve_description_fts (cve_id, description)
	SELECT cve_id, description FROM cve WHERE description IS NOT NULL;
	`)
	if err != nil {
		return fmt.Errorf("failed to sync descriptions: %v", err)
	}

	// Create trigger to sync FTS5 table on updates
	_, err = db.Exec(`
	CREATE TRIGGER IF NOT EXISTS cve_au AFTER UPDATE ON cve BEGIN
		DELETE FROM cve_description_fts WHERE cve_id = old.cve_id;
		INSERT INTO cve_description_fts (cve_id, description)
		VALUES (new.cve_id, new.description);
	END;
	`)
	if err != nil {
		return fmt.Errorf("failed to create update trigger: %v", err)
	}
	return nil
}

// Column to remove (set dynamically)
const columnToRemove = "description"

// Function to get column names (excluding the one to remove)
func getTableColumns(db *sql.DB, tableName, excludeColumn string) ([]string, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s);", tableName)
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get table schema: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dfltValue sql.NullString

		if err := rows.Scan(&cid, &name, &dtype, &notnull, &dfltValue, &pk); err != nil {
			return nil, fmt.Errorf("failed to read schema: %v", err)
		}

		if name != excludeColumn {
			columns = append(columns, name)
		}
	}

	return columns, nil
}

// Function to remove a column dynamically
func removeColumn(dbPath string, tableName, columnToRemove string) error {

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Get all columns except the one to remove
	columns, err := getTableColumns(db, tableName, columnToRemove)
	if err != nil {
		return err
	}

	// Step 1: Create a new table without the column to remove
	columnsSQL := strings.Join(columns, ", ")
	createTableQuery := fmt.Sprintf("CREATE TABLE %s_new AS SELECT %s FROM %s;", tableName, columnsSQL, tableName)
	_, err = db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}

	// Step 2: Rename old table for backup
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s_old;", tableName, tableName))
	if err != nil {
		return fmt.Errorf("failed to update database")
	}

	// Step 3: Rename the new table to replace the old table
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s_new RENAME TO %s;", tableName, tableName))
	if err != nil {
		return fmt.Errorf("failed to update database")
	}

	// Step 4: Drop the old table
	_, err = db.Exec(fmt.Sprintf("DROP TABLE %s_old;", tableName))
	if err != nil {
		return fmt.Errorf("failed to update database")
	}

	// Step 5: Optimize storage
	_, err = db.Exec("VACUUM;")
	if err != nil {
		return fmt.Errorf("failed to update database")
	}

	return nil
}
