package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"vulnerawise/pkg/db"
	models_search "vulnerawise/pkg/models/search"
	"vulnerawise/pkg/search"

	"github.com/spf13/cobra"
)

var (
	cveFilter              string
	outputFormat           string
	publishedDateRange     string
	publishedFilter        string
	lastModifiedFilter     string
	maturityFilter         string
	severityFilter         string
	feed                   string
	exploitPublishedFilter string // New flag for exploit published date filter
	descriptionFilter      string // New flag for description substring search
	limit                  int    // New flag for limiting the number of results (default 10)
	offset                 int    // New flag for pagination offset (default 0)
	epssScoreFilter        string
	epssOperator           string
	epssValue              float64
	printExploitOnly       bool
)

var searchCmd = &cobra.Command{
	Use:           "search",
	Short:         "Search for CVEs using various filters",
	Long:          `Search for CVEs using filters such as:`,
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if cveFilter == "" && publishedDateRange == "" && publishedFilter == "" &&
			exploitPublishedFilter == "" && lastModifiedFilter == "" &&
			maturityFilter == "" && severityFilter == "" && descriptionFilter == "" &&
			feed == "" && epssScoreFilter == "" {
			return fmt.Errorf("error: you must specify at least one filter (e.g., --cve, --published, --severity, --feed)")
		}

		// Initialize the database.
		if err := db.Init(db.GetDBPath()); err != nil {
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

		if epssScoreFilter != "" {
			// Extract operator and value (e.g., ">=50", "<30")
			if len(epssScoreFilter) >= 2 && (epssScoreFilter[:2] == ">=" || epssScoreFilter[:2] == "<=") {
				epssOperator = epssScoreFilter[:2]
				scoreStr := epssScoreFilter[2:]
				var err error
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return fmt.Errorf("invalid EPSS score value: %s", scoreStr)
				}
				// Convert from percentage (0-100) to decimal (0-1)
				epssValue = score / 100.0
			} else if len(epssScoreFilter) >= 1 && (epssScoreFilter[0] == '>' || epssScoreFilter[0] == '<' || epssScoreFilter[0] == '=') {
				epssOperator = epssScoreFilter[:1]
				scoreStr := epssScoreFilter[1:]
				var err error
				score, err := strconv.ParseFloat(scoreStr, 64)
				if err != nil {
					return fmt.Errorf("invalid EPSS score value: %s", scoreStr)
				}
				// Convert from percentage (0-100) to decimal (0-1)
				epssValue = score / 100.0
			} else {
				return fmt.Errorf("invalid EPSS filter format: use >=, <=, >, <, or = followed by a percentage (0-100)")
			}
		}

		// Prepare search options.
		opts := models_search.SearchOptions{
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
			EPSSOperator:    epssOperator,
			EPSSValue:       epssValue,
		}

		// Execute the search query.
		results, totalRecords, err := search.SearchCVEs(sqlDB, &opts)
		if err != nil {
			return fmt.Errorf("search query failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No CVE records found.")
			return nil
		}

		// Generate structured JSON output.
		finalJSON, err := search.FormatOutput(results, len(results), offset, limit)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Output the result.
		if strings.ToLower(outputFormat) == "json" {
			fmt.Println(string(finalJSON))
		} else {
			if printExploitOnly {
				if err := search.PrintExploitTableFromJSON(finalJSON); err != nil {
					return fmt.Errorf("failed to print exploit table: %w", err)
				}
			} else {
				if err := search.PrintTableFromJSON(finalJSON); err != nil {
					return fmt.Errorf("failed to print table: %w", err)
				}
			}
		}

		return nil
	},
}

func init() {
	searchCmd.Flags().StringVar(&cveFilter, "cve", "", "Comma-separated list of CVE IDs (e.g., CVE-2024-51567,CVE-2024-43093)")
	searchCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table or json")
	searchCmd.Flags().BoolVar(&printExploitOnly, "print-exploit-only", false, "Print only exploit URLs")
	searchCmd.Flags().StringVar(&publishedDateRange, "published-date-range", "", "Filter by published date range (e.g., 2024-01-01:2024-01-31)")
	searchCmd.Flags().StringVar(&publishedFilter, "published", "", "Filter by CVEs published in the last X days/hours (e.g., 'last 7 days', 'last 24 hours')")
	searchCmd.Flags().StringVar(&lastModifiedFilter, "last-modified", "", "Filter by last modified date (e.g., 'last 7 days' or 'YYYY-MM-DD:YYYY-MM-DD')")
	searchCmd.Flags().StringVar(&maturityFilter, "maturity", "", "Filter by exploit maturity (comma-separated, e.g., active,weaponized,poc,none)")
	searchCmd.Flags().StringVar(&severityFilter, "severity", "", "Filter by severity (comma-separated, e.g., low,medium,high)")
	searchCmd.Flags().StringVar(&exploitPublishedFilter, "exploit-published", "", "Filter CVEs by the published date of associated exploit data (e.g., 'last 7 days', 'last 24 hours')")
	searchCmd.Flags().StringVar(&descriptionFilter, "description", "", "Filter by description substring (e.g., 'microsoft')")
	searchCmd.Flags().StringVar(&epssScoreFilter, "epss", "", "Filter by EPSS score percentage (e.g., '>=50', '<30', '=70')")
	searchCmd.Flags().IntVar(&limit, "limit", 10, "Maximum number of results to return (default 10)")
	searchCmd.Flags().IntVar(&offset, "offset", 0, "Pagination offset (default 0)")
}
