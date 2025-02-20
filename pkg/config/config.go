package config

import (
	"os"
	"path/filepath"
)

// GetDBPath returns the database path, using an environment variable if set,
// or falling back to a default location in the user configuration directory.
func GetDBPath() string {
	// Allow overriding via an environment variable.
	if path, ok := os.LookupEnv("VULN_DB_PATH"); ok {
		return path
	}

	// Otherwise, determine a default based on the OS.
	// os.UserConfigDir returns something like:
	// - Windows: C:\Users\<user>\AppData\Roaming
	// - macOS:   /Users/<user>/Library/Application Support
	// - Linux:   /home/<user>/.config
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback to the current directory if unable to get the config dir.
		configDir = "."
	}

	// Create a subdirectory for your application.
	appDir := filepath.Join(configDir, "vulnerawise")
	// Ensure the directory exists.
	_ = os.MkdirAll(appDir, 0755)

	// Return the full path to the database file.
	return filepath.Join(appDir, "vuln.db")
}
