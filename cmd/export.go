package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"vulnerawise/pkg/config"
	"vulnerawise/pkg/db"
	"vulnerawise/pkg/search"
)

var (
	outputFile    string
	outputDir     string
	exportCVEList string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export exploitation intelligence data in JSON format",
	Long:  "Export exploitation intelligence data in JSON format into a single file or a directory organized by year.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Ensure either --output-file or --output-dir is specified
		if outputFile == "" && outputDir == "" {
			cmd.Help()
			return fmt.Errorf("\nError: You must specify either --output-file or --output-dir")
		}

		// Initialize the database
		if err := db.Init(config.GetDBPath()); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		sqlDB := db.Get()

		// Parse CVE IDs (if provided)
		var cveIDs []string
		if exportCVEList != "" {
			for _, id := range strings.Split(exportCVEList, ",") {
				cveIDs = append(cveIDs, strings.TrimSpace(id))
			}
		}

		// Prepare search options
		opts := &search.SearchOptions{
			CVEIds: cveIDs, // If empty, retrieves ALL CVEs
			Limit:  0,      // 0 means no limit (return all results)
		}

		// Retrieve CVE data
		results, err := search.SearchCVEs(sqlDB, opts)
		if err != nil {
			return fmt.Errorf("search query failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No CVE records found for export.")
			return nil
		}

		// Format the results into the proper JSON structure
		jsonOutput, err := search.FormatOutput(results)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Export JSON data and return the number of exported CVEs
		exportedCount, err := exportJSON(jsonOutput, results)
		if err != nil {
			return err
		}

		// Print summary of exported CVEs
		fmt.Printf("✅ Export completed: %d CVEs exported.\n", exportedCount)

		return nil
	},
}

// Export JSON data correctly per file
func exportJSON(jsonData []byte, results []search.Vulnerability) (int, error) {
	// Unmarshal to ensure structured OrderedOutput format
	var orderedOutput search.OrderedOutput
	if err := json.Unmarshal(jsonData, &orderedOutput); err != nil {
		return 0, fmt.Errorf("failed to unmarshal structured output: %w", err)
	}

	// Add timestamp metadata
	orderedOutput.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Marshal again to ensure correct indentation
	finalJSON, err := json.MarshalIndent(orderedOutput, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("failed to marshal final JSON: %w", err)
	}

	exportedCount := len(orderedOutput.Data) // Number of exported CVEs

	// Handle output based on provided flags
	if outputFile != "" {
		// Single JSON file output (entire dataset)
		err = os.WriteFile(outputFile, finalJSON, 0644)
		if err != nil {
			return 0, fmt.Errorf("failed to write JSON file: %w", err)
		}
		fmt.Printf("Exported JSON to %s\n", outputFile)
	} else if outputDir != "" {
		// Directory-based JSON output, organized by year
		for _, entry := range orderedOutput.Data {
			year := extractYearFromCVE(entry.CVE.ID)
			if year == "" {
				log.Printf("Skipping CVE with invalid ID format: %s\n", entry.CVE.ID)
				continue
			}

			// Ensure directory exists
			dirPath := filepath.Join(outputDir, year)
			if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
				return 0, fmt.Errorf("failed to create directory: %w", err)
			}

			// Wrap each CVE inside `OrderedOutput` structure
			singleCVEOutput := search.OrderedOutput{
				Metadata: orderedOutput.Metadata, // Include timestamp
				Data:     []search.CVEEntry{entry},
			}

			// Generate JSON for the individual CVE entry
			cveJSON, err := json.MarshalIndent(singleCVEOutput, "", "  ")
			if err != nil {
				return 0, fmt.Errorf("failed to marshal CVE JSON: %w", err)
			}

			// Write each CVE to its own file
			filePath := filepath.Join(dirPath, entry.CVE.ID+".json")
			err = os.WriteFile(filePath, cveJSON, 0644)
			if err != nil {
				return 0, fmt.Errorf("failed to write JSON file for %s: %w", entry.CVE.ID, err)
			}
		}
		fmt.Printf("Exported JSON files to %s\n", outputDir)
	}

	return exportedCount, nil
}

// Extracts year from CVE ID (e.g., CVE-2024-1234 -> "2024")
func extractYearFromCVE(cveID string) string {
	parts := strings.Split(cveID, "-")
	if len(parts) >= 2 {
		return parts[1] // Return year part
	}
	return ""
}

func init() {
	exportCmd.Flags().StringVar(&outputFile, "output-file", "", "File to export all results into")
	exportCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to export results organized by year")
	exportCmd.Flags().StringVar(&exportCVEList, "cve", "", "Comma-separated list of CVE IDs to export")
}
