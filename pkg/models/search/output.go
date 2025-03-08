package search

import (
	"vulnerawise/pkg/models/vulnerability"
)

// OrderedOutput represents the structured JSON output
type OrderedOutput struct {
	Metadata Metadata   `json:"metadata"`
	Data     []CVEEntry `json:"data"`
}

// Metadata stores the timestamp of the output
type Metadata struct {
	Timestamp string `json:"timestamp"`
}

// CVEEntry represents a single CVE entry.
// (Changed field type from vulnerability.Record to vulnerability.CVE.)
type CVEEntry struct {
	CVE vulnerability.CVE `json:"cve"`
}
