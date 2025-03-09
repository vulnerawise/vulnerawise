package cmd

import (
	"fmt"
	"strings"

	"vulnerawise/pkg/db"
	"vulnerawise/pkg/export"
	models_search "vulnerawise/pkg/models/search"
	"vulnerawise/pkg/search"

	"github.com/spf13/cobra"
)

var (
	outputFile    string
	outputDir     string
	exportCVEList string
	batchSize     int // Add this variable
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
		if err := db.Init(db.GetDBPath()); err != nil {
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
		opts := &models_search.SearchOptions{
			CVEIds: cveIDs, // If empty, retrieves ALL CVEs
			Limit:  0,      // 0 means no limit (return all results)
		}

		// Retrieve CVE data
		results, _, err := search.SearchCVEs(sqlDB, opts)
		if err != nil {
			return fmt.Errorf("search query failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No CVE records found for export.")
			return nil
		}

		// Format the results into the proper JSON structure.
		// Since this is an export (no pagination), we set total as len(results), offset = 0, and limit = len(results)
		jsonOutput, err := search.FormatOutput(results, len(results), 0, len(results))
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Export JSON data and return the number of exported CVEs
		exportedCount, err := export.ExportJSON(jsonOutput, outputFile, outputDir, batchSize)
		if err != nil {
			return err
		}

		// Print summary of exported CVEs
		fmt.Printf("✅ Export completed: %d CVEs exported.\n", exportedCount)

		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&outputFile, "output-file", "", "File to export all results into")
	exportCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to export results organized by year")
	exportCmd.Flags().StringVar(&exportCVEList, "cve", "", "Comma-separated list of CVE IDs to export")
	exportCmd.Flags().IntVar(&batchSize, "batch-size", 0, "Size of batches for processing (0 for no batching)") // Add this flag
}
