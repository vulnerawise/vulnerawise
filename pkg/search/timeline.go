package search

import (
	"encoding/json"
	"log"
	"sort"
	"time"
)

// structureTimeline organizes, deduplicates, and sorts timeline entries.
// It returns a cleaned JSON representation of the structured timeline.
func structureTimeline(timelineRaw json.RawMessage) json.RawMessage {
	var timeline []TimelineEntry
	if err := json.Unmarshal(timelineRaw, &timeline); err != nil {
		log.Printf("Error unmarshaling timeline: %v", err)
		// Return the original raw timeline on error.
		return timelineRaw
	}

	// Use maps to deduplicate entries based on URL.
	referenceMap := make(map[string]TimelineEntry)
	repositoryMap := make(map[string]TimelineEntry)

	for _, entry := range timeline {
		switch entry.Type {
		case "reference":
			if _, exists := referenceMap[entry.URL]; !exists {
				referenceMap[entry.URL] = entry
			}
		case "repository":
			if _, exists := repositoryMap[entry.URL]; !exists {
				repositoryMap[entry.URL] = entry
			}
		}
	}

	// Convert maps to slices.
	var references []TimelineEntry
	for _, ref := range referenceMap {
		references = append(references, ref)
	}
	var repositories []TimelineEntry
	for _, repo := range repositoryMap {
		repositories = append(repositories, repo)
	}

	// Helper function to parse date strings.
	parseDate := func(dateStr string) time.Time {
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return time.Time{}
		}
		return t
	}

	// Sort references and repositories by published date (most recent first).
	sort.SliceStable(references, func(i, j int) bool {
		return parseDate(references[i].Published).After(parseDate(references[j].Published))
	})
	sort.SliceStable(repositories, func(i, j int) bool {
		return parseDate(repositories[i].Published).After(parseDate(repositories[j].Published))
	})

	structured := StructuredTimeline{
		References:   references,
		Repositories: repositories,
	}
	cleanedJSON, err := json.Marshal(structured)
	if err != nil {
		log.Printf("Error marshaling structured timeline: %v", err)
		return timelineRaw
	}

	return json.RawMessage(cleanedJSON)
}

// determineExploitMaturity computes the exploit maturity for a given vulnerability
// using timeline data. It checks references (and optionally repositories) for exploit signals.
func determineExploitMaturity(v Vulnerability) string {
	var timeline StructuredTimeline
	if err := json.Unmarshal([]byte(v.Timeline), &timeline); err != nil {
		log.Printf("Error unmarshaling timeline for CVE %s: %v", v.CVEID, err)
		return "none"
	}

	var foundActive, foundWeaponized, foundPoC bool

	// Check references for signals.
	for _, ref := range timeline.References {
		switch ref.SourceType {
		case "exploited":
			foundActive = true
		case "weapon":
			foundWeaponized = true
		case "poc":
			foundPoC = true
		}
	}

	// Optionally, check repositories for additional PoC signals.
	for _, repo := range timeline.Repositories {
		if repo.Type == "repository" {
			foundPoC = true
		}
	}

	switch {
	case foundActive:
		return "active"
	case foundWeaponized:
		return "weaponized"
	case foundPoC:
		return "poc"
	default:
		return "none"
	}
}
