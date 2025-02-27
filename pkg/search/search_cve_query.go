package search

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"vulnerawise/pkg/models/search"
	"vulnerawise/pkg/models/vulnerability"
)

// SearchCVEs executes a query that retrieves CVE records along with associated metrics, timeline, and severity,
// using dynamic search options while employing your fixed query.
func SearchCVEs(db *sql.DB, opts *search.SearchOptions) ([]vulnerability.Record, error) {
	if opts == nil {
		return nil, fmt.Errorf("search options cannot be nil")
	}

	// Build two sets of filtering conditions.
	var baseConditions []string  // Conditions on base table columns (from "c")
	var outerConditions []string // Conditions on computed columns (e.g. severity, exploit_maturity)
	args := []interface{}{}

	// --- Base Conditions ---

	// Filter by specific CVE IDs.
	if len(opts.CVEIds) > 0 {
		placeholders := []string{}
		for _, id := range opts.CVEIds {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		baseConditions = append(baseConditions, fmt.Sprintf("c.cve_id IN (%s)", strings.Join(placeholders, ",")))
	}

	// Filter by Published Date Range.
	if opts.PublishedDateRange != "" {
		parts := strings.Split(opts.PublishedDateRange, ":")
		if len(parts) == 2 {
			baseConditions = append(baseConditions, "c.published_date BETWEEN ? AND ?")
			args = append(args, parts[0], parts[1])
		}
	}

	// Inside the WHERE clause building in SearchCVEs
	if opts.EPSSOperator != "" {
		baseConditions = append(baseConditions, fmt.Sprintf("epss_score %s ?", opts.EPSSOperator))
		args = append(args, opts.EPSSValue)
	}

	// Filter by Exploit Published Date (references or repositories).
	if opts.ExploitPublishedFilter != "" && strings.HasPrefix(strings.ToLower(opts.ExploitPublishedFilter), "last ") {
		parts := strings.Split(opts.ExploitPublishedFilter, " ")
		if len(parts) == 3 {
			quantity, err := strconv.Atoi(parts[1])
			if err == nil {
				unit := strings.ToLower(parts[2])
				if strings.HasPrefix(unit, "day") {
					timeThreshold := time.Now().AddDate(0, 0, -quantity)
					baseConditions = append(baseConditions, `
						(
							EXISTS (
								SELECT 1 FROM cve_references cr
								WHERE cr.cve_id = c.cve_id AND cr.published_date >= ?
							)
							OR
							EXISTS (
								SELECT 1 FROM cve_repositories r
								WHERE r.cve_id = c.cve_id AND r.published_date >= ?
							)
						)
					`)
					thresholdStr := timeThreshold.Format("2006-01-02 15:04:05")
					args = append(args, thresholdStr, thresholdStr)
				} else if strings.HasPrefix(unit, "hour") {
					timeThreshold := time.Now().Add(-time.Duration(quantity) * time.Hour)
					baseConditions = append(baseConditions, `
						(
							EXISTS (
								SELECT 1 FROM cve_references cr
								WHERE cr.cve_id = c.cve_id AND cr.published_date >= ?
							)
							OR
							EXISTS (
								SELECT 1 FROM cve_repositories r
								WHERE r.cve_id = c.cve_id AND r.published_date >= ?
							)
						)
					`)
					thresholdStr := timeThreshold.Format("2006-01-02 15:04:05")
					args = append(args, thresholdStr, thresholdStr)
				}
			}
		}
	}

	// Filter by "Published in the last X days/hours".
	if opts.PublishedFilter != "" && strings.HasPrefix(strings.ToLower(opts.PublishedFilter), "last ") {
		parts := strings.Split(opts.PublishedFilter, " ")
		if len(parts) == 3 {
			quantity, err := strconv.Atoi(parts[1])
			if err == nil {
				unit := strings.ToLower(parts[2])
				if strings.HasPrefix(unit, "day") {
					timeFilter := time.Now().AddDate(0, 0, -quantity)
					baseConditions = append(baseConditions, "c.published_date >= ?")
					args = append(args, timeFilter.Format("2006-01-02 15:04:05"))
				} else if strings.HasPrefix(unit, "hour") {
					timeFilter := time.Now().Add(-time.Duration(quantity) * time.Hour)
					baseConditions = append(baseConditions, "c.published_date >= ?")
					args = append(args, timeFilter.Format("2006-01-02 15:04:05"))
				}
			}
		}
	}

	// Filter by Last Modified.
	if opts.LastModified != "" {
		if strings.HasPrefix(strings.ToLower(opts.LastModified), "last ") {
			parts := strings.Split(opts.LastModified, " ")
			if len(parts) == 3 {
				days, err := strconv.Atoi(parts[1])
				if err == nil {
					t := time.Now().AddDate(0, 0, -days)
					baseConditions = append(baseConditions, "c.last_modified_date >= ?")
					args = append(args, t.Format("2006-01-02"))
				}
			}
		} else {
			parts := strings.Split(opts.LastModified, ":")
			if len(parts) == 2 {
				baseConditions = append(baseConditions, "c.last_modified_date BETWEEN ? AND ?")
				args = append(args, parts[0], parts[1])
			}
		}
	}

	// Filter by Description substring.
	if opts.DescriptionLike != "" {
		baseConditions = append(baseConditions, "c.description LIKE ?")
		args = append(args, "%"+opts.DescriptionLike+"%")
	}

	// --- Outer Conditions (for computed columns) ---

	// Filter by Exploit Maturity.
	if opts.ExploitMaturity != "" {
		// Expect comma-separated values.
		maturityVals := []string{}
		for _, m := range strings.Split(opts.ExploitMaturity, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				maturityVals = append(maturityVals, strings.ToLower(m))
			}
		}
		if len(maturityVals) > 0 {
			placeholders := strings.Repeat("?,", len(maturityVals))
			placeholders = strings.TrimSuffix(placeholders, ",")
			outerConditions = append(outerConditions, "LOWER(exploit_maturity) IN ("+placeholders+")")
			for _, m := range maturityVals {
				args = append(args, m)
			}
		}
	}

	// Filter by Severity.
	if opts.Severity != "" {
		severityVals := []string{}
		for _, s := range strings.Split(opts.Severity, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				severityVals = append(severityVals, strings.ToLower(s))
			}
		}
		if len(severityVals) > 0 {
			placeholders := strings.Repeat("?,", len(severityVals))
			placeholders = strings.TrimSuffix(placeholders, ",")
			outerConditions = append(outerConditions, "LOWER(severity) IN ("+placeholders+")")
			for _, s := range severityVals {
				args = append(args, s)
			}
		}
	}

	// --- New Filter: Timeline "feed" ---
	// This condition will filter rows where the timeline's references contain a source equal to opts.Feed.
	if opts.Feed != "" {
		// Use the JSON functions available in SQLite.
		// We assume opts.Feed is provided in lower case if you want case-insensitive matching.
		outerConditions = append(outerConditions, `
			EXISTS (
				SELECT 1
				FROM json_each(json_extract(timeline, '$.references')) AS ref
				WHERE LOWER(json_extract(ref.value, '$.source')) = ?
			)
		`)
		args = append(args, strings.ToLower(opts.Feed))
	}

	// Combine base conditions into a WHERE clause.
	baseWhereClause := ""
	if len(baseConditions) > 0 {
		baseWhereClause = "WHERE " + strings.Join(baseConditions, " AND ")
	}

	// Combine outer conditions into a WHERE clause.
	outerWhereClause := ""
	if len(outerConditions) > 0 {
		outerWhereClause = "WHERE " + strings.Join(outerConditions, " AND ")
	}

	// Build the final query using your fixed query in the BaseQuery CTE.
	// Inject the baseWhereClause into the RecentActivity CTE and append the outerWhereClause after BaseQuery.
	queryTemplate := `
WITH BaseQuery AS (
  WITH RecentActivity AS (
    SELECT
      c.cve_id,
      c.description,
      c.published_date,
      c.last_modified_date,
      c.epss_score,
      c.epss_percentile
    FROM cve c
    %s
  ),
  weighted_refs AS (
    SELECT
      r.cve_id,
      SUM(
        CASE
          WHEN r.source_type = 'exploited' THEN 5.0
		  WHEN r.source_type = 'weapon' THEN 2.0
		  WHEN r.source_type = 'poc' THEN 1.0
          ELSE 0.0
        END
      ) AS exploit_weight,
      MAX(CASE WHEN r.source_type = 'exploited' THEN 1 ELSE 0 END) AS has_exploited,
      MAX(CASE WHEN r.source_type = 'weapon' THEN 1 ELSE 0 END) AS has_weapon,
      MAX(CASE WHEN r.source_type = 'poc' THEN 1 ELSE 0 END) AS has_poc
    FROM cve_references r
    GROUP BY r.cve_id
  ),
  repo_flags AS (
    SELECT cve_id, 1 AS has_repo FROM cve_repositories GROUP BY cve_id
  ),
  ref_scores AS (
    SELECT
      cve_id,
      COUNT(*) AS total_refs,
      SUM(
        CASE
          WHEN source_type = 'weapon' THEN 5.0/(julianday('now')-julianday(published_date)+1)
          WHEN source_type = 'poc' THEN 3.0/(julianday('now')-julianday(published_date)+1)
          WHEN source_type = 'exploited' THEN 4.0/(julianday('now')-julianday(published_date)+1)
          ELSE 1.0/(julianday('now')-julianday(published_date)+1)
        END
      ) AS ref_score
    FROM cve_references
    GROUP BY cve_id
  ),
  repo_scores AS (
    SELECT
      cve_id,
      COUNT(*) AS total_repos,
      SUM(COALESCE(stars, 0)) AS total_stars,
      SUM(COALESCE(forks, 0)) AS total_forks,
      SUM(
	    ((COALESCE(stars, 0) * 0.5) + (COALESCE(forks, 0) * 1.0))
	    / (julianday('now') - julianday(published_date) + 2)
	  ) AS repo_score
    FROM cve_repositories
    GROUP BY cve_id
  )
  SELECT
    ra.cve_id,
    ra.published_date,
    ra.last_modified_date,
    ra.description,
    ra.epss_score,
    ra.epss_percentile,
    (
      SELECT json_group_array(
        json_object(
          'source', cm.source,
          'type', cm.type,
          'cvss_version', cm.cvss_version,
          'vector_string', cm.vector_string,
          'attack_vector', cm.attack_vector,
          'base_score', cm.base_score,
          'severity', cm.severity
        )
      )
      FROM cve_metrics cm
      WHERE cm.cve_id = ra.cve_id
    ) AS metrics,
    (
      SELECT severity
      FROM cve_metrics
      WHERE cve_id = ra.cve_id
      ORDER BY CAST(cvss_version AS INTEGER) DESC
      LIMIT 1
    ) AS severity,
    json_object(
      'references', (
        SELECT json_group_array(
          json_object(
            'type', cr.type,
            'url', cr.url,
            'source_type', cr.source_type,
            'source', cr.source,
            'description', cr.description,
            'published', cr.published_date
          )
        )
        FROM cve_references cr
        WHERE cr.cve_id = ra.cve_id
      ),
      'repositories', (
        SELECT json_group_array(
          json_object(
            'type', 'repository',
            'url', r.url,
            'repo_name', r.repo_name,
            'description', r.description,
            'forks', r.forks,
            'stars', r.stars,
            'published', r.published_date,
            'created', r.created_date,
            'last_modified', r.last_modified_date
          )
        )
        FROM cve_repositories r
        WHERE r.cve_id = ra.cve_id
      )
    ) AS timeline,
    CASE
      WHEN wr.has_exploited = 1 THEN 'active'
      WHEN wr.has_weapon = 1 THEN 'weaponized'
      WHEN wr.has_poc = 1 OR rf_repo.has_repo = 1 THEN 'poc'
      ELSE 'none'
    END AS exploit_maturity,
    CASE
      WHEN EXISTS (
        SELECT 1 FROM cve_references r2
        WHERE r2.cve_id = ra.cve_id AND (r2.source_type = 'exploited' OR r2.source = 'cisa')
      ) THEN 1
      ELSE 0
    END AS cisa_kev,
	CASE
	WHEN EXISTS (
		SELECT 1 FROM cve_references r2
		WHERE r2.cve_id = ra.cve_id
		AND (r2.source_type = 'exploited' OR r2.source = 'cisa')
	) THEN 'high'
	WHEN (COALESCE(rf.ref_score, 0) + COALESCE(rs.repo_score, 0) + COALESCE(wr.exploit_weight, 0)) >= 5 THEN 'high'
    WHEN (COALESCE(rf.ref_score, 0) + COALESCE(rs.repo_score, 0) + COALESCE(wr.exploit_weight, 0)) >= 2 THEN 'medium'
	ELSE 'low'
	END AS confidence_level,

    ((COALESCE(rf.ref_score, 0) + COALESCE(rs.repo_score, 0) + COALESCE(wr.exploit_weight, 0)) * (1.0 / (julianday('now') - julianday(ra.published_date) + 1))) AS trending_score

  FROM RecentActivity ra
  LEFT JOIN weighted_refs wr ON ra.cve_id = wr.cve_id
  LEFT JOIN ref_scores rf ON ra.cve_id = rf.cve_id
  LEFT JOIN repo_scores rs ON ra.cve_id = rs.cve_id
  LEFT JOIN repo_flags rf_repo ON ra.cve_id = rf_repo.cve_id
)
SELECT *
FROM BaseQuery
%s
`

	// Inject the outer WHERE clause after BaseQuery.
	finalQuery := fmt.Sprintf(queryTemplate, baseWhereClause, outerWhereClause)

	// Then conditionally add the ORDER BY clause:
	if opts.Trending {
		finalQuery += " ORDER BY trending_score DESC"
	} else {
		finalQuery += " ORDER BY published_date DESC"
	}

	// Append LIMIT and OFFSET.
	// Use default limit 10 if not provided.
	limit := opts.Limit
	if limit <= 0 {
		limit = 10
	}
	// Append LIMIT and OFFSET if a limit is set.
	if opts.Limit > 0 {
		finalQuery += " LIMIT ?"
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			finalQuery += " OFFSET ?"
			args = append(args, opts.Offset)
		}
	}

	rows, err := db.Query(finalQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	var results []vulnerability.Record
	for rows.Next() {
		var v vulnerability.Record
		var metrics sql.NullString
		var severity sql.NullString
		var timeline sql.NullString
		var exploitMaturity sql.NullString
		var cisaKevInt sql.NullInt64
		var confidenceLevel sql.NullString
		var trendingScore sql.NullFloat64

		err := rows.Scan(
			&v.CVEID,
			&v.Published,
			&v.LastModified,
			&v.Description,
			&v.EPSSScore,
			&v.EPSSPercentile,
			&metrics,
			&severity,
			&timeline,
			&exploitMaturity,
			&cisaKevInt,
			&confidenceLevel,
			&trendingScore,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if metrics.Valid {
			v.Metrics = metrics.String
		}
		if timeline.Valid {
			v.Timeline = timeline.String
		} else {
			v.Timeline = `{"references": null, "repositories": []}`
		}
		if severity.Valid {
			v.BestSeverity = severity.String
		}
		if cisaKevInt.Valid && cisaKevInt.Int64 != 0 {
			v.CisaKEV = true
		} else {
			v.CisaKEV = false
		}
		if confidenceLevel.Valid {
			v.ConfidenceLevel = confidenceLevel.String
		}

		// Compute timeline-based fields inline.
		v.ReportedExploited = false
		v.PublicExploitCount = 0

		// Parse timeline to set exploit-related fields
		var timelineData struct {
			References []struct {
				Source     string `json:"source"`
				SourceType string `json:"source_type"`
			} `json:"references"`
			Repositories []interface{} `json:"repositories"`
		}

		if err := json.Unmarshal([]byte(v.Timeline), &timelineData); err == nil {
			for _, ref := range timelineData.References {
				if ref.Source == "cisa" || ref.SourceType == "exploited" {
					v.ReportedExploited = true
				}
				if ref.SourceType == "exploited" ||
					ref.SourceType == "weapon" ||
					ref.SourceType == "poc" {
					v.PublicExploitCount++
				}
			}

			// Count all repositories (they're all exploit-related)
			if timelineData.Repositories != nil {
				v.PublicExploitCount += len(timelineData.Repositories)
			}

			results = append(results, v)
		}

		if err = rows.Err(); err != nil {
			return nil, fmt.Errorf("rows error: %w", err)
		}
	}

	return results, nil
}
