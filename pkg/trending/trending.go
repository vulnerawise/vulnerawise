package trending

import (
	"database/sql"
	"fmt"
	models_search "vulnerawise/pkg/models/search"
	"vulnerawise/pkg/models/vulnerability"
	"vulnerawise/pkg/search"
)

// TrendingCVEs queries CVEs ordered by trending_score DESC.
func TrendingCVEs(db *sql.DB, limit, offset int) ([]vulnerability.Record, error) {
	// Create options with Trending flag set and no additional filters.
	opts := &models_search.SearchOptions{
		Limit:    limit,
		Offset:   offset,
		Trending: true,
	}

	records, _, err := search.SearchCVEs(db, opts)
	if err != nil {
		return nil, fmt.Errorf("trending query failed: %w", err)
	}

	return records, nil
}
