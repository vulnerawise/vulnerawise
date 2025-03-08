package search

import (
	"encoding/json"
	"reflect"
	"time"

	"vulnerawise/pkg/models/vulnerability"
)

// FormatOutput converts a slice of database records (vulnerability.Record)
// into the final JSON structure with controlled field ordering.
func FormatOutput(records []vulnerability.Record, total, offset, limit int) ([]byte, error) {
	// Define our output structure with fields in exactly the desired order
	type OrderedCVE struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Metadata    struct {
			PublishedDate    string  `json:"published_date"`
			LastModifiedDate string  `json:"last_modified_date"`
			ConfidenceLevel  string  `json:"confidence_level"`
			Severity         *string `json:"severity,omitempty"`
		} `json:"metadata"`
		Impact struct {
			CisaKev           bool   `json:"cisa_kev"`
			ReportedExploited bool   `json:"reported_exploited"`
			ExploitMaturity   string `json:"exploit_maturity"`
			Automatable       bool   `json:"automatable"`
		} `json:"impact"`
		Counts struct {
			PublicExploitCount int `json:"public_exploit_count"`
		} `json:"counts"`
		EPSS struct {
			Score      float64 `json:"score"`
			Percentile float64 `json:"percentile"`
		} `json:"epss"`
		Metrics  []interface{} `json:"metrics,omitempty"`
		Timeline struct {
			References   []interface{} `json:"references,omitempty"`
			Repositories []interface{} `json:"repositories,omitempty"`
		} `json:"timeline"`
	}

	type OrderedOutput struct {
		Metadata struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
		Data []struct {
			CVE OrderedCVE `json:"cve"`
		} `json:"data"`
	}

	// Initialize output structure
	output := OrderedOutput{
		Metadata: struct {
			Timestamp string `json:"timestamp"`
		}{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
		Data: []struct {
			CVE OrderedCVE `json:"cve"`
		}{},
	}

	// Process each record
	for _, rec := range records {
		// Get the data from original CVE
		cve, err := rec.ToDetailedJson()
		if err != nil {
			continue // Skip invalid records
		}

		// Create our ordered structure
		var severityPtr *string
		if cve.Metadata.Severity != "" {
			severityValue := cve.Metadata.Severity
			severityPtr = &severityValue
		}

		orderedCVE := OrderedCVE{
			ID:          cve.ID,
			Description: cve.Description,
			Metadata: struct {
				PublishedDate    string  `json:"published_date"`
				LastModifiedDate string  `json:"last_modified_date"`
				ConfidenceLevel  string  `json:"confidence_level"`
				Severity         *string `json:"severity,omitempty"`
			}{
				PublishedDate:    cve.Metadata.Published,    // Corrected field name
				LastModifiedDate: cve.Metadata.LastModified, // Corrected field name
				ConfidenceLevel:  cve.Metadata.ConfidenceLevel,
				Severity:         severityPtr,
			},
			Impact: struct {
				CisaKev           bool   `json:"cisa_kev"`
				ReportedExploited bool   `json:"reported_exploited"`
				ExploitMaturity   string `json:"exploit_maturity"`
				Automatable       bool   `json:"automatable"`
			}{
				CisaKev:           cve.Impact.CisaKEV, // Corrected field name capitalization
				ReportedExploited: cve.Impact.ReportedExploited,
				ExploitMaturity:   cve.Impact.ExploitMaturity,
				Automatable:       cve.Impact.Automatable,
			},
			Counts: struct {
				PublicExploitCount int `json:"public_exploit_count"`
			}{
				PublicExploitCount: cve.Counts.PublicExploitCount,
			},
			EPSS: struct {
				Score      float64 `json:"score"`
				Percentile float64 `json:"percentile"`
			}{
				Score:      cve.EPSS.Score,
				Percentile: cve.EPSS.Percentile,
			},
			// Convert specific types to interface{} arrays
			Metrics: interfaceSlice(cve.Metrics),
			Timeline: struct {
				References   []interface{} `json:"references,omitempty"`
				Repositories []interface{} `json:"repositories,omitempty"`
			}{
				References:   interfaceSlice(cve.Timeline.References),
				Repositories: interfaceSlice(cve.Timeline.Repositories),
			},
		}

		// Add to output data
		output.Data = append(output.Data, struct {
			CVE OrderedCVE `json:"cve"`
		}{
			CVE: orderedCVE,
		})
	}

	return json.MarshalIndent(output, "", "  ")
}

// Helper function to convert any slice to []interface{}
func interfaceSlice(slice interface{}) []interface{} {
	// Import the "reflect" package at the top of your file
	s := reflect.ValueOf(slice)

	// If it's not a slice, return nil
	if s.Kind() != reflect.Slice {
		return nil
	}

	// Create a new []interface{} slice with the same length
	result := make([]interface{}, s.Len())

	// Copy each element from the original slice to the new one
	for i := 0; i < s.Len(); i++ {
		result[i] = s.Index(i).Interface()
	}

	return result
}
