package trending

import (
	"database/sql"
	"fmt"
	"vulnerawise/pkg/search"
)

// TrendingCVEs queries CVEs ordered by trending_score DESC.
// It reuses search.SearchCVEs by setting opts.Trending = true.
func TrendingCVEs(db *sql.DB, limit, offset int) ([]search.Vulnerability, error) {
	// Create options with Trending flag set and no additional filters.
	opts := &search.SearchOptions{
		Limit:    limit,
		Offset:   offset,
		Trending: true,
	}
	results, err := search.SearchCVEs(db, opts)
	if err != nil {
		return nil, fmt.Errorf("trending query failed: %w", err)
	}
	return results, nil
}
