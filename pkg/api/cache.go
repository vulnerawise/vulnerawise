package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http" // <-- Added this import
	"sync"
	"time"

	"vulnerawise/pkg/db"
	"vulnerawise/pkg/search"
)

// CacheEntry holds cached search results along with their expiration time.
type CacheEntry struct {
	Data   search.OrderedOutput
	Expiry time.Time
}

var (
	// cache stores cached results by cache key.
	cache   = make(map[string]CacheEntry)
	cacheMu sync.RWMutex
)

// generateCacheKey creates a SHA256 hash based key from the input string.
func generateCacheKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

// GetCachedResult returns the cached OrderedOutput if available;
// otherwise it executes the heavy query, caches the result for 4 hours,
// and returns the data.
func GetCachedResult(rawCacheKey string, opts *search.SearchOptions) (search.OrderedOutput, error) {
	// Generate a fixed-length cache key using SHA256.
	cacheKey := generateCacheKey(rawCacheKey)

	cacheMu.RLock()
	entry, found := cache[cacheKey]
	cacheMu.RUnlock()
	if found && time.Now().Before(entry.Expiry) {
		log.Println("Cache hit for key:", cacheKey)
		return entry.Data, nil
	}

	log.Println("Cache miss for key:", cacheKey, "- querying data...")
	results, err := search.SearchCVEs(db.Get(), opts)
	if err != nil {
		return search.OrderedOutput{}, fmt.Errorf("error executing search: %w", err)
	}
	jsonOutput, err := search.FormatOutput(results)
	if err != nil {
		return search.OrderedOutput{}, fmt.Errorf("error formatting output: %w", err)
	}
	var orderedOutput search.OrderedOutput
	if err := json.Unmarshal(jsonOutput, &orderedOutput); err != nil {
		return search.OrderedOutput{}, fmt.Errorf("error unmarshaling output: %w", err)
	}
	newEntry := CacheEntry{
		Data:   orderedOutput,
		Expiry: time.Now().Add(4 * time.Hour),
	}
	cacheMu.Lock()
	cache[cacheKey] = newEntry
	cacheMu.Unlock()

	return orderedOutput, nil
}

// PreGenerateCache pre-populates the cache by issuing HTTP GET requests for common queries.
func PreGenerateCache(port int) {
	queries := []string{
		"", // Global query (no heavy filters)
		"?published=last%2010%20day&page=1",
		"?published=last%2090%20day&page=1",
		"?published=last%20120%20day&page=1",
		"?published=last%20365%20day&page=1",
		"?published=last%2024%20hour&page=1",
		"?published=last%2048%20hour&page=1",
		"?last_modified=last%2030%20day&page=1",
		"?last_modified=last%2060%20day&page=1",
		"?last_modified=last%20365%20day&page=1",
		"?exploit_published=last%201%20days",
		"?exploit_published=last%207%20days",
		"?exploit_published=last%215%20days",
		"?exploit_published=last%230%20days",
		// Combined filters:
		"?published=last%2010%20day&last_modified=last%2030%20day&page=1",
		"?maturity=poc&page=1",
		"?severity=high&page=1",
		"?published=last%2010%20day&last_modified=last%2030%20day&maturity=poc&severity=high&page=1",
		// Additional queries for triage/prioritization:
		"?published=last%207%20day&severity=critical&page=1",
		"?last_modified=last%2030%20day&maturity=poc&page=1",
		"?last_modified=last%207%20day&page=1",
		"?last_modified=last%2060%20day&severity=high&page=1",
		"?published=last%2010%20day&last_modified=last%2030%20day&maturity=poc&severity=critical&page=1",
	}
	for _, q := range queries {
		url := fmt.Sprintf("http://localhost:%d/v1/vuln%s", port, q)
		log.Printf("Initiating cache for query: %s", url)
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Error initiating cache for query %s: %v", url, err)
			continue
		}
		log.Printf("Cache initiated for query %s, status code: %d", url, resp.StatusCode)
		resp.Body.Close()
	}
}
