package search

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"vulnerawise/pkg/models/search"
	"vulnerawise/pkg/models/vulnerability"
)

// parseDescriptionQuery parses a GitHub-like search syntax into an FTS5 query string.
// It supports:
// - Space-separated terms are treated as AND by default
// - Quoted phrases ("foo bar") are treated as a single term
// - "term1 AND term2" for explicit AND (the default between terms)
// - "term1 OR term2" for OR conditions
// - Special handling for versions and numbers to make them work with FTS5
// parseDescriptionQuery parses a search query into an FTS5 query string
// parseDescriptionQuery parses a search query into an FTS5 query string
func parseDescriptionQuery(query string) (string, []interface{}) {
	// For FTS5, pass the query to the MATCH operator after preparing it
	ftsQuery, err := prepareFTS5Query(query)
	if err != nil {
		// Return a special condition that will match nothing but provide a clear error message
		return "1=0", []interface{}{} // This condition will never match any records
	}

	return "fts.description MATCH ?", []interface{}{ftsQuery}
}

// prepareFTS5Query prepares a user query for use with FTS5
// It handles quoted phrases, normalizes operators, and properly wraps terms
func prepareFTS5Query(query string) (string, error) {
	// Step 1: Normalize operators to uppercase for consistency
	query = strings.ReplaceAll(query, " and ", " AND ")
	query = strings.ReplaceAll(query, " or ", " OR ")
	query = strings.ReplaceAll(query, " not ", " NOT ")
	query = strings.ReplaceAll(query, " near ", " NEAR ")
	query = strings.ReplaceAll(query, " near/", " NEAR/")

	// Step 2: Check for problematic patterns before processing
	// FTS5 doesn't handle wildcards with dots well (e.g., "2.4.*")
	problematicRegex := regexp.MustCompile(`"\d+(\.\d+)*\*"`)
	if problematicRegex.MatchString(query) {
		return "", fmt.Errorf("wildcards in version numbers (like '2.4.*') are not directly supported. Please use a specific version number or try a more general search term")
	}

	// Step 3: Identify and handle version numbers with dots
	// Create a regex to match version-like patterns (e.g., 2.4.49, 1.0, etc.)
	versionRegex := regexp.MustCompile(`\b\d+(\.\d+)+\b`)

	// Replace version numbers with quoted versions
	query = versionRegex.ReplaceAllStringFunc(query, func(match string) string {
		return `"` + match + `"`
	})

	// Step 4: Pre-quote any hyphenated terms or terms with special characters
	parts := strings.Fields(query)
	for i, part := range parts {
		// Skip already quoted parts or operators
		if strings.HasPrefix(part, `"`) && strings.HasSuffix(part, `"`) {
			continue
		}
		if isOperator(part) || part == "(" || part == ")" {
			continue
		}

		// If the term contains a hyphen or other special character, quote it
		if strings.ContainsAny(part, "-/+:;") && !isNumeric(part) {
			parts[i] = `"` + part + `"`
		}
	}
	query = strings.Join(parts, " ")

	// Step 5: Parse the query to handle quoted phrases and wrap terms appropriately
	var result strings.Builder
	inQuotes := false
	inWord := false
	wordStart := 0

	for i := 0; i < len(query); i++ {
		c := query[i]

		// Track whether we're inside quotes
		if c == '"' {
			// If starting a quote, end any current word
			if !inQuotes && inWord {
				word := query[wordStart:i]
				if isOperator(word) || isNumeric(word) {
					result.WriteString(word)
				} else {
					result.WriteString(`"` + word + `"`)
				}
				inWord = false
			}

			inQuotes = !inQuotes
			result.WriteByte(c)
			continue
		}

		// If we're in quotes, add the character as-is
		if inQuotes {
			result.WriteByte(c)
			continue
		}

		// Handle word boundaries and operators
		if isAlpha(c) || c == '-' || c == '+' || c == ':' { // Include hyphen in word characters
			if !inWord {
				inWord = true
				wordStart = i
			}
		} else if c == '(' || c == ')' {
			// End current word if any
			if inWord {
				word := query[wordStart:i]
				// Don't quote operators or numbers
				if isOperator(word) || isNumeric(word) {
					result.WriteString(word)
				} else {
					// Wrap non-operator words in quotes
					result.WriteString(`"` + word + `"`)
				}
				inWord = false
			}

			// Add space before parenthesis if needed
			if result.Len() > 0 && !isWhitespace(result.String()[result.Len()-1]) {
				result.WriteByte(' ')
			}
			result.WriteByte(c)
			// Add space after parenthesis if needed
			if i < len(query)-1 && !isWhitespace(query[i+1]) {
				result.WriteByte(' ')
			}
		} else if isWhitespace(c) {
			// End current word if any
			if inWord {
				word := query[wordStart:i]
				// Don't quote operators or numbers
				if isOperator(word) || isNumeric(word) {
					result.WriteString(word)
				} else {
					// Wrap non-operator words in quotes
					result.WriteString(`"` + word + `"`)
				}
				inWord = false
			}
			result.WriteByte(c)
		} else {
			// Other characters (likely punctuation)
			if inWord {
				// End the current word if punctuation breaks it
				word := query[wordStart:i]
				if isOperator(word) || isNumeric(word) {
					result.WriteString(word)
				} else {
					result.WriteString(`"` + word + `"`)
				}
				inWord = false
			}
			result.WriteByte(c)
		}
	}

	// Handle the last word if there is one
	if inWord {
		word := query[wordStart:]
		if isOperator(word) || isNumeric(word) {
			result.WriteString(word)
		} else {
			result.WriteString(`"` + word + `"`)
		}
	}

	// Step 6: Replace any SQLite special tokens that might cause injection
	sanitized := result.String()
	sanitized = strings.ReplaceAll(sanitized, "MATCH", "")
	sanitized = strings.ReplaceAll(sanitized, "NEAR/0", "NEAR/1") // NEAR/0 can cause issues

	// Step 7: Check result again for problematic patterns that might have been created
	// during processing
	if problematicRegex.MatchString(sanitized) {
		return "", fmt.Errorf("wildcards in version numbers (like '2.4.*') are not directly supported. Please use a specific version number or try a more general search term")
	}

	// For troubleshooting, add logging here to see the final query
	// log.Printf("Original query: %s\nSanitized query: %s", query, sanitized)

	// Ensure valid query by checking for SQL comment indicators
	if strings.Contains(sanitized, "--") || strings.Contains(sanitized, "/*") {
		return "", fmt.Errorf("invalid search query: contains SQL comment indicators")
	}

	return sanitized, nil
}

// Helper functions for prepareFTS5Query

// isAlpha checks if a character is alphabetic or numeric
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
}

// isWhitespace checks if a character is whitespace
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isOperator checks if a word is a FTS operator
func isOperator(word string) bool {
	word = strings.ToUpper(word)
	return word == "AND" || word == "OR" || word == "NOT" ||
		strings.HasPrefix(word, "NEAR") || word == "NEAR"
}

// isNumeric checks if a string is purely numeric (including dots for version numbers)
func isNumeric(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	// At least one digit
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// SearchCVEs executes a query that retrieves CVE records along with associated metrics, timeline, and severity,
// using dynamic search options while employing your fixed query.
func SearchCVEs(db *sql.DB, opts *search.SearchOptions) ([]vulnerability.Record, int, error) {
	if opts == nil {
		return nil, 0, fmt.Errorf("search options cannot be nil")
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
		whereClause, clauseArgs := parseDescriptionQuery(opts.DescriptionLike)
		if whereClause != "" {
			baseConditions = append(baseConditions, whereClause)
			args = append(args, clauseArgs...)
		}
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
      fts.description,
      c.published_date,
      c.last_modified_date,
      c.epss_score,
      c.epss_percentile
    FROM cve c
	JOIN cve_description_fts fts ON c.cve_id = fts.cve_id
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
            'name', r.repo_name,
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
SELECT bq.*, COUNT(*) OVER () AS total_records
FROM BaseQuery bq
%s
`

	// Inject the outer WHERE clause after BaseQuery.
	finalQuery := fmt.Sprintf(queryTemplate, baseWhereClause, outerWhereClause)

	// Then conditionally add the ORDER BY clause:
	if opts.Trending {
		// For trending CVEs, add a filter for last 3 months
		timeThreshold := time.Now().AddDate(0, -12, 0).Format("2006-01-02 15:04:05")

		// Check if we need to add WHERE or AND
		if outerWhereClause == "" {
			finalQuery += " WHERE bq.published_date >= ?"
		}
		args = append(args, timeThreshold)

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
		return nil, 0, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	var results []vulnerability.Record
	var totalCount int

	for rows.Next() {
		var v vulnerability.Record
		var metrics sql.NullString
		var severity sql.NullString
		var timeline sql.NullString
		var exploitMaturity sql.NullString
		var cisaKevInt sql.NullInt64
		var confidenceLevel sql.NullString
		var trendingScore sql.NullFloat64
		var totalRecords sql.NullInt64

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
			&totalRecords,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan row: %w", err)
		}

		// In your row scanning loop, store the first total_records value you see
		if totalRecords.Valid && totalCount == 0 {
			totalCount = int(totalRecords.Int64)
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
			return nil, 0, fmt.Errorf("rows error: %w", err)
		}
	}

	return results, totalCount, nil
}
