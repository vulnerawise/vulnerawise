package cmd

import (
	"fmt"
	"strings"

	"vulnerawise/pkg/db"
	"vulnerawise/pkg/search"
	"vulnerawise/pkg/trending"

	"github.com/spf13/cobra"
)

var (
	trendingLimit  int
	trendingOffset int
)

var trendingCmd = &cobra.Command{
	Use:   "trending",
	Short: "Show trending CVEs ordered by trending score",
	Long:  `Display trending CVEs ordered by trending_score in descending order.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize database.
		if err := db.Init(db.GetDBPath()); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		sqlDB := db.Get()

		results, err := trending.TrendingCVEs(sqlDB, trendingLimit, trendingOffset)
		if err != nil {
			return fmt.Errorf("trending query failed: %w", err)
		}
		if len(results) == 0 {
			fmt.Println("No trending CVEs found.")
			return nil
		}

		// Generate structured JSON output with proper pagination parameters
		jsonOutput, err := search.FormatOutput(results, len(results), trendingOffset, trendingLimit)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Print output.
		if strings.ToLower(outputFormat) == "json" {
			fmt.Println(string(jsonOutput))
		} else {
			if err := search.PrintTableFromJSON(jsonOutput); err != nil {
				return fmt.Errorf("failed to print table: %w", err)
			}
		}

		return nil
	},
}

func init() {
	trendingCmd.Flags().IntVar(&trendingLimit, "limit", 10, "Maximum number of trending results to return (default 10)")
	trendingCmd.Flags().IntVar(&trendingOffset, "offset", 0, "Pagination offset for trending results (default 0)")
	trendingCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table or json")
}
