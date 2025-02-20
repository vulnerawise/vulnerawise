package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"vulnerawise/pkg/config"
	"vulnerawise/pkg/db"
	"vulnerawise/pkg/search"
)

var (
	cveFilter              string
	outputFormat           string
	publishedDateRange     string
	publishedFilter        string
	lastModifiedFilter     string
	maturityFilter         string
	severityFilter         string
	feed 				   string
	exploitPublishedFilter string // New flag for exploit published date filter
	descriptionFilter      string // New flag for description substring search
	limit                  int    // New flag for limiting the number of results (default 10)
	offset                 int    // New flag for pagination offset (default 0)
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for CVEs using various filters",
	Long: `Search for CVEs using filters such as:
  --cve                  Search by specific CVE IDs (comma-separated)
  --published-date-range Search within a date range (YYYY-MM-DD:YYYY-MM-DD)
  --published            Search for CVEs published in the last X days/hours (e.g., "last 7 days", "last 24 hours")
  --last-modified        Search by last modified date (e.g., "last 7 days" or "YYYY-MM-DD:YYYY-MM-DD")
  --maturity             Filter by exploit maturity (comma-separated, e.g., active,weaponized,poc,none)
  --severity             Filter by severity (comma-separated, e.g., low,medium,high)
  --exploit-published    Filter by the published date of associated exploit data (e.g., "last 7 days", "last 24 hours")
  --description          Filter by description substring (e.g., "microsoft")
  --limit                Maximum number of results to return (default 10)
  --offset               Pagination offset (default 0)`,
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if cveFilter == "" && publishedDateRange == "" && publishedFilter == "" &&
			exploitPublishedFilter == "" && lastModifiedFilter == "" &&
			maturityFilter == "" && severityFilter == "" && descriptionFilter == "" &&
			feed == "" {
			return fmt.Errorf("Error: You must specify at least one filter (e.g., --cve, --published, --severity, --feed)")
		}


		// Initialize the database.
		if err := db.Init(config.GetDBPath()); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		sqlDB := db.Get()

		// Parse comma-separated CVE IDs.
		var cveIDs []string
		if cveFilter != "" {
			for _, id := range strings.Split(cveFilter, ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					cveIDs = append(cveIDs, id)
				}
			}
		}

		// Parse comma-separated maturity filters.
		var maturityFilters []string
		if maturityFilter != "" {
			for _, m := range strings.Split(maturityFilter, ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					maturityFilters = append(maturityFilters, strings.ToLower(m))
				}
			}
		}

		// Parse comma-separated severity filters.
		var severityFilters []string
		if severityFilter != "" {
			for _, s := range strings.Split(severityFilter, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					severityFilters = append(severityFilters, strings.ToLower(s))
				}
			}
		}

		// Prepare search options.
		opts := &search.SearchOptions{
			CVEIds:                 cveIDs,
			PublishedDateRange:     publishedDateRange,
			PublishedFilter:        publishedFilter,
			LastModified:           lastModifiedFilter,
			ExploitPublishedFilter: exploitPublishedFilter,
			// New options.
			ExploitMaturity: strings.Join(maturityFilters, ","),
			Severity:        strings.Join(severityFilters, ","),
			DescriptionLike: descriptionFilter,
			Limit:           limit,
			Offset:          offset,
		}

		// Execute the search query.
		results, err := search.SearchCVEs(sqlDB, opts)
		if err != nil {
			return fmt.Errorf("search query failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No CVE records found.")
			return nil
		}

		// Generate structured JSON output.
		jsonOutput, err := search.FormatOutput(results)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Unmarshal into structured OrderedOutput.
		var orderedOutput search.OrderedOutput
		if err := json.Unmarshal(jsonOutput, &orderedOutput); err != nil {
			return fmt.Errorf("failed to unmarshal structured output: %w", err)
		}

		// If maturity, severity or description filters are provided, further filter the final JSON output.
		if len(maturityFilters) > 0 || len(severityFilters) > 0 || descriptionFilter != "" {
			filteredData := []search.CVEEntry{}
			for _, entry := range orderedOutput.Data {
				cve := entry.CVE
				// Apply maturity filters.
				if len(maturityFilters) > 0 {
					match := false
					currentMaturity := strings.ToLower(cve.Impact.ExploitMaturity)
					for _, filter := range maturityFilters {
						if currentMaturity == filter {
							match = true
							break
						}
					}
					if !match {
						continue
					}
				}
				// Apply severity filters.
				if len(severityFilters) > 0 {
					match := false
					currentSeverity := strings.ToLower(cve.Metadata.Severity)
					for _, filter := range severityFilters {
						if currentSeverity == filter {
							match = true
							break
						}
					}
					if !match {
						continue
					}
				}
				// Apply description substring filter.
				if descriptionFilter != "" {
					if !strings.Contains(strings.ToLower(cve.Description), strings.ToLower(descriptionFilter)) {
						continue
					}
				}
				filteredData = append(filteredData, entry)
			}
			orderedOutput.Data = filteredData
		}

		// Re-marshal the structured output for final print.
		finalJSON, err := json.MarshalIndent(orderedOutput, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal final output: %w", err)
		}

		// Output the result.
		if strings.ToLower(outputFormat) == "json" {
			fmt.Println(string(finalJSON))
		} else {
			if err := search.PrintTableFromJSON(finalJSON); err != nil {
				return fmt.Errorf("failed to print table: %w", err)
			}
		}

		return nil
	},
}

func init() {
	searchCmd.Flags().StringVar(&cveFilter, "cve", "", "Comma-separated list of CVE IDs (e.g., CVE-2024-51567,CVE-2024-43093)")
	searchCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table or json")
	searchCmd.Flags().StringVar(&publishedDateRange, "published-date-range", "", "Filter by published date range (e.g., 2024-01-01:2024-01-31)")
	searchCmd.Flags().StringVar(&publishedFilter, "published", "", "Filter by CVEs published in the last X days/hours (e.g., 'last 7 days', 'last 24 hours')")
	searchCmd.Flags().StringVar(&lastModifiedFilter, "last-modified", "", "Filter by last modified date (e.g., 'last 7 days' or 'YYYY-MM-DD:YYYY-MM-DD')")
	searchCmd.Flags().StringVar(&maturityFilter, "maturity", "", "Filter by exploit maturity (comma-separated, e.g., active,weaponized,poc,none)")
	searchCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity (comma-separated, e.g., low,medium,high)")
	searchCmd.Flags().StringVar(&exploitPublishedFilter, "exploit-published", "", "Filter CVEs by the published date of associated exploit data (e.g., 'last 7 days', 'last 24 hours')")
	searchCmd.Flags().StringVar(&descriptionFilter, "description", "", "Filter by description substring (e.g., 'microsoft')")
	searchCmd.Flags().StringVar(&feed, "feed", "", "Filter by timeline reference source (e.g., 'metasploit')")
	searchCmd.Flags().IntVar(&limit, "limit", 10, "Maximum number of results to return (default 10)")
	searchCmd.Flags().IntVar(&offset, "offset", 0, "Pagination offset (default 0)")
}
