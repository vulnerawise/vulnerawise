package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"vulnerawise/pkg/search"
)

// getClientIP extracts the client's IP address from the request.
// It first checks the X-Forwarded-For header (if behind a trusted proxy) and falls back to r.RemoteAddr.
func getClientIP(r *http.Request) net.IP {
	// Check the X-Forwarded-For header.
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For may contain a comma-separated list; use the first IP.
		parts := strings.Split(xff, ",")
		ipStr := strings.TrimSpace(parts[0])
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip
		}
	}
	// Fallback to r.RemoteAddr.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// VulnHandler processes requests to the /v1/vuln endpoint.
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

	log.Println("Received search request:", r.URL.RawQuery)

	// Retrieve and sanitize query parameters.
	cveParam := r.URL.Query().Get("cve")
	publishedRange := r.URL.Query().Get("published_date_range")
	publishedFilter := r.URL.Query().Get("published")       // e.g., "last 10 day"
	lastModified := r.URL.Query().Get("last_modified")        // e.g., "last 30 day"
	maturity := r.URL.Query().Get("maturity")
	severity := r.URL.Query().Get("severity")
	exploitPublished := r.URL.Query().Get("exploit_published") // e.g., "last 7 days"

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

	// Parse comma-separated CVE IDs.
	var cveIDs []string
	if cveParam != "" {
		for _, id := range strings.Split(cveParam, ",") {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" {
				cveIDs = append(cveIDs, trimmed)
			}
		}
	}

	// Build search options.
	opts := &search.SearchOptions{
		CVEIds:                cveIDs,
		PublishedDateRange:    publishedRange,
		PublishedFilter:       publishedFilter,
		LastModified:          lastModified,
		ExploitPublishedFilter: exploitPublished, // New option passed to search logic.
	}

	// --------- Caching Logic ---------
	// Build a raw cache key based on query parameters.
	rawCacheKey := fmt.Sprintf("cve=%s|published_date_range=%s|published=%s|last_modified=%s|exploit_published=%s",
		cveParam, publishedRange, publishedFilter, lastModified, exploitPublished)
	orderedOutput, err := GetCachedResult(rawCacheKey, opts)
	if err != nil {
		log.Println("Error getting cached result:", err)
		http.Error(w, "Search error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// --------- End Caching ---------

	// In-memory filtering by maturity and severity.
	if maturity != "" || severity != "" {
		filteredData := []search.CVEEntry{}
		for _, entry := range orderedOutput.Data {
			cve := entry.CVE
			if maturity != "" && strings.ToLower(cve.Impact.ExploitMaturity) != strings.ToLower(maturity) {
				continue
			}
			if severity != "" && strings.ToLower(cve.Metadata.Severity) != strings.ToLower(severity) {
				continue
			}
			filteredData = append(filteredData, entry)
		}
		orderedOutput.Data = filteredData
	}

	// ====== Pagination ======
	pageStr := r.URL.Query().Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	pageSize := 200 // Fixed page size
	offset := (page - 1) * pageSize
	totalRecords := len(orderedOutput.Data)
	if offset > totalRecords {
		offset = totalRecords
	}
	endIndex := offset + pageSize
	if endIndex > totalRecords {
		endIndex = totalRecords
	}
	paginatedData := orderedOutput.Data[offset:endIndex]
	orderedOutput.Data = paginatedData
	totalPages := 0
	if pageSize > 0 {
		totalPages = (totalRecords + pageSize - 1) / pageSize
	}
	// ====== End Pagination ======

	type PaginatedResponse struct {
		Data         []search.CVEEntry `json:"data"`
		TotalRecords int               `json:"total_records"`
		Page         int               `json:"page"`
		PageSize     int               `json:"page_size"`
		TotalPages   int               `json:"total_pages"`
	}
	response := PaginatedResponse{
		Data:         orderedOutput.Data,
		TotalRecords: totalRecords,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	}
	finalJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Println("Error marshaling final output:", err)
		http.Error(w, "Final output error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// ====== End Pagination ======

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(finalJSON)
}
