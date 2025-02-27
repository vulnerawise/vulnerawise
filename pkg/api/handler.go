package api

import (
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"vulnerawise/pkg/db"
	models_search "vulnerawise/pkg/models/search"
	"vulnerawise/pkg/search"
)

// Precompile a regex to validate CVE IDs (e.g. CVE-2024-1234 or CVE-2024-12345)
var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// getClientIP extracts the client's IP address from the request.
func getClientIP(r *http.Request) net.IP {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ipStr := strings.TrimSpace(parts[0])
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// VulnHandler processes requests to the /v1/vuln endpoint without caching.
// It uses SQL-level pagination with a human-friendly "page" parameter and a maximum limit of 100.
func VulnHandler(w http.ResponseWriter, r *http.Request) {
	// ====== Rate Limiting ======
	clientIP := getClientIP(r)
	if clientIP == nil {
		http.Error(w, "Unable to determine client IP", http.StatusBadRequest)
		return
	}
	if !IsExcluded(clientIP) {
		limiter := GetLimiterForIP(clientIP.String())
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}
	// ====== End Rate Limiting ======

	// Retrieve query parameters.
	cveParam := r.URL.Query().Get("cve")
	publishedRange := r.URL.Query().Get("published_date_range")
	publishedFilter := r.URL.Query().Get("published")  // e.g., "last 10 day"
	lastModified := r.URL.Query().Get("last_modified") // e.g., "last 30 day"
	maturity := r.URL.Query().Get("maturity")
	severity := r.URL.Query().Get("severity")
	exploitPublished := r.URL.Query().Get("exploit_published") // e.g., "last 7 days"
	description := r.URL.Query().Get("description")            // New: Filter by description substring
	feed := r.URL.Query().Get("feed")                          // New: Filter by timeline reference source
	epssFilter := r.URL.Query().Get("epss")

	// Validate publishedFilter format.
	if publishedFilter != "" && strings.HasPrefix(strings.ToLower(publishedFilter), "last ") {
		parts := strings.Split(publishedFilter, " ")
		if len(parts) != 3 {
			http.Error(w, "Invalid published filter format", http.StatusBadRequest)
			return
		}
		quantity, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "Invalid published filter value", http.StatusBadRequest)
			return
		}
		lowerUnit := strings.ToLower(parts[2])
		if strings.Contains(lowerUnit, "day") && quantity > 365 {
			http.Error(w, "Published filter exceeds maximum allowed of 365 days", http.StatusBadRequest)
			return
		} else if strings.Contains(lowerUnit, "hour") && quantity > 8760 {
			http.Error(w, "Published filter exceeds maximum allowed of 8760 hours", http.StatusBadRequest)
			return
		}
	}

	// Validate lastModified filter.
	if lastModified != "" && strings.HasPrefix(strings.ToLower(lastModified), "last ") {
		parts := strings.Split(lastModified, " ")
		if len(parts) != 3 {
			http.Error(w, "Invalid last_modified filter format", http.StatusBadRequest)
			return
		}
		days, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "Invalid last_modified filter value", http.StatusBadRequest)
			return
		}
		if days > 365 {
			http.Error(w, "Last modified filter exceeds maximum allowed of 365 days", http.StatusBadRequest)
			return
		}
	}

	// Validate exploitPublished filter.
	if exploitPublished != "" && strings.HasPrefix(strings.ToLower(exploitPublished), "last ") {
		parts := strings.Split(exploitPublished, " ")
		if len(parts) != 3 {
			http.Error(w, "Invalid exploit_published filter format", http.StatusBadRequest)
			return
		}
		quantity, err := strconv.Atoi(parts[1])
		if err != nil {
			http.Error(w, "Invalid exploit_published filter value", http.StatusBadRequest)
			return
		}
		lowerUnit := strings.ToLower(parts[2])
		if strings.Contains(lowerUnit, "day") && quantity > 365 {
			http.Error(w, "Exploit published filter exceeds maximum allowed of 365 days", http.StatusBadRequest)
			return
		} else if strings.Contains(lowerUnit, "hour") && quantity > 8760 {
			http.Error(w, "Exploit published filter exceeds maximum allowed of 8760 hours", http.StatusBadRequest)
			return
		}
	}

	// Parse comma-separated CVE IDs and validate their format.
	var cveIDs []string
	if cveParam != "" {
		for _, id := range strings.Split(cveParam, ",") {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" {
				if !cveRegex.MatchString(trimmed) {
					http.Error(w, "Invalid CVE ID format: "+trimmed, http.StatusBadRequest)
					return
				}
				cveIDs = append(cveIDs, trimmed)
			}
		}
	}

	// Parse and validate EPSS filter format
	var epssOperator string
	var epssValue float64
	if epssFilter != "" {
		// Extract operator and value (e.g., ">=50", "<30")
		if len(epssFilter) >= 2 && (epssFilter[:2] == ">=" || epssFilter[:2] == "<=") {
			epssOperator = epssFilter[:2]
			scoreStr := epssFilter[2:]
			var err error
			score, err := strconv.ParseFloat(scoreStr, 64)
			if err != nil {
				http.Error(w, "Invalid EPSS score value: "+scoreStr, http.StatusBadRequest)
				return
			}
			// Convert from percentage (0-100) to decimal (0-1)
			epssValue = score / 100.0
		} else if len(epssFilter) >= 1 && (epssFilter[0] == '>' || epssFilter[0] == '<' || epssFilter[0] == '=') {
			epssOperator = epssFilter[:1]
			scoreStr := epssFilter[1:]
			var err error
			score, err := strconv.ParseFloat(scoreStr, 64)
			if err != nil {
				http.Error(w, "Invalid EPSS score value: "+scoreStr, http.StatusBadRequest)
				return
			}
			// Convert from percentage (0-100) to decimal (0-1)
			epssValue = score / 100.0
		} else {
			http.Error(w, "Invalid EPSS filter format: use >=, <=, >, <, or = followed by a percentage (0-100)", http.StatusBadRequest)
			return
		}

		// Validate the score range
		if epssValue < 0 || epssValue > 1 {
			http.Error(w, "EPSS score percentage must be between 0 and 100", http.StatusBadRequest)
			return
		}
	}

	// Retrieve pagination parameters: page and limit.
	// Default values: page = 1, limit = 100.
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	pageNum := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			pageNum = p
		}
	}
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			if l > 100 {
				http.Error(w, "limit parameter cannot exceed 100", http.StatusBadRequest)
				return
			}
			limit = l
		}
	}
	offset := (pageNum - 1) * limit

	// Build search options using SQL-level pagination.
	opts := &models_search.SearchOptions{
		CVEIds:                 cveIDs,
		PublishedDateRange:     publishedRange,
		PublishedFilter:        publishedFilter,
		LastModified:           lastModified,
		ExploitPublishedFilter: exploitPublished,
		ExploitMaturity:        maturity,
		Severity:               severity,
		DescriptionLike:        description,
		Feed:                   feed,
		Limit:                  limit,
		Offset:                 offset,
		EPSSOperator:           epssOperator,
		EPSSValue:              epssValue,
	}

	// Initialize the database.
	if err := db.Init(db.GetDBPath()); err != nil {
		http.Error(w, "Database initialization failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sqlDB := db.Get()

	// Execute the search query (no caching) with SQL-level pagination.
	results, err := search.SearchCVEs(sqlDB, opts)
	if err != nil {
		log.Println("Error executing search query:", err)
		http.Error(w, "Search error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	finalJSON, err := search.FormatOutput(results, len(results), offset, limit)
	if err != nil {
		log.Println("Error marshaling final output:", err)
		http.Error(w, "Final output error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(finalJSON)
}
