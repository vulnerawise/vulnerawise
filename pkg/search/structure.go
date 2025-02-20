package search

import "encoding/json"


// Vulnerability represents a full CVE record.
type Vulnerability struct {
	CVEID          string  `json:"cve_id"`
	Source         string  `json:"cve_source"`
	Published      string  `json:"cve_published"`
	LastModified   string  `json:"cve_last_modified"`
	VulnStatus     string  `json:"vuln_status"`
	Description    string  `json:"cve_description"`
	EPSSScore      float64 `json:"epss_score"`
	EPSSPercentile float64 `json:"epss_percentile"`
	Metrics        string  `json:"metrics"`  // JSON string (array)
	Timeline       string  `json:"timeline"` // JSON string (object with "references" and "repositories")
	// Fields computed from timeline analysis:
	BestSeverity      string  // <-- Add this field
	ConfidenceLevel    string `json:"confidence_level"`
	CisaKEV            bool   `json:"cisa_kev"`
	ReportedExploited  bool   `json:"reported_exploited"`
	PublicExploitCount int    `json:"public_exploit_count"`
}

// SearchOptions holds additional filters.
type SearchOptions struct {
	CVEIds               []string // List of CVE IDs.
	PublishedDateRange   string   // e.g. "YYYY-MM-DD:YYYY-MM-DD"
	ExploitPublishedFilter string // e.g. "last 7 days" or "last 24 hours"
	PublishedFilter      string   // e.g. "last 7 days" or "last 24 hours"
	LastModified         string   // e.g. "last 30 days" or "YYYY-MM-DD:YYYY-MM-DD"
	ExploitMaturity      string   // e.g. "active", "weaponized", "poc", "none"
	Severity             string   // e.g. "low", "medium", "high"
	DescriptionLike      string   // substring to search for in description
	Feed                string // Pass the feed flag
	Limit  int // Max results per query (optional)
	Offset int // Pagination offset (optional)
	Trending               bool  // New: when true, order by trending_score DESC
}

// OrderedOutput represents the structured JSON output.
type OrderedOutput struct {
	Metadata Metadata   `json:"metadata"`
	Data     []CVEEntry `json:"data"`
}

// Metadata stores the timestamp of the output.
type Metadata struct {
	Timestamp string `json:"timestamp"`
}

// CVEEntry represents a single CVE entry.
type CVEEntry struct {
	CVE CVE `json:"cve"`
}

// CVE represents the details of a CVE.
type CVE struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Metadata    CVEMeta  `json:"metadata"`
	Impact      Impact   `json:"impact"`
	Counts      Counts   `json:"counts"`
	EPSS        EPSS     `json:"epss"`
	Metrics     []Metric `json:"metrics"`
	Timeline    Timeline `json:"timeline"`
}

// CVEMeta stores metadata about a CVE.
type CVEMeta struct {
	PublishedDate    string `json:"published_date"`
	LastModifiedDate string `json:"last_modified_date"`
	ConfidenceLevel  string `json:"confidence_level"`
	Severity         string `json:"severity"`
}

// Impact represents how a CVE is assessed in terms of exploitation.
type Impact struct {
	CisaKEV           bool   `json:"cisa_kev"`
	ReportedExploited bool   `json:"reported_exploited"`
	ExploitMaturity   string `json:"exploit_maturity"`
	Automatable       bool   `json:"automatable"`
}

// Counts represents various numerical indicators of a CVE.
type Counts struct {
	PublicExploitCount int `json:"public_exploit_count"`
}

// EPSS represents the Exploit Prediction Scoring System data.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// Metric defines one CVSS metric entry.
type Metric struct {
	Source       string  `json:"source"`
	Type         string  `json:"type"`
	CvssVersion  string  `json:"cvss_version"`
	VectorString string  `json:"vector_string"`
	AttackVector string  `json:"attack_vector"`
	BaseScore    float64 `json:"base_score"`
}

// Timeline holds references and repositories related to a CVE.
type Timeline struct {
	References   []Reference  `json:"references"`
	Repositories []Repository `json:"repositories"`
}

// Reference provides external links to CVE details.
type Reference struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	SourceType  string `json:"source_type"`
	Source      string `json:"source"`
	Description string `json:"description"`
	Published   string `json:"published"`
}

// Repository contains repository information related to a CVE.
type Repository struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	Description  string `json:"description"`
	Published    string `json:"published"`
	Created      string `json:"created"`
	LastModified string `json:"last_modified"`
	RepoName     string `json:"repo_name"`
	Name         string `json:"name"`
	Stars        int    `json:"stars"`
	Forks        int    `json:"forks"`
}

// CVEOut is used for output formatting.
type CVEOut struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Metadata    CVEMeta         `json:"metadata"`
	Impact      Impact          `json:"impact"`
	Counts      Counts          `json:"counts"`
	Epss        EPSS            `json:"epss"`
	Metrics     []Metric        `json:"metrics"`
	Timeline    json.RawMessage `json:"timeline"`
}

// DataEntry represents an entry in the final output.
type DataEntry struct {
	Cve CVEOut `json:"cve"`
}

// Output represents the final JSON output structure.
type Output struct {
	Metadata Metadata    `json:"metadata"`
	Data     []DataEntry `json:"data"`
}

// TimelineEntry represents one timeline entry.
type TimelineEntry struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	SourceType   string `json:"source_type,omitempty"`
	Source       string `json:"source,omitempty"`
	Description  string `json:"description,omitempty"`
	Published    string `json:"published,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	RepoName     string `json:"repo_name,omitempty"`
	Name         string `json:"name,omitempty"`
	Stars        int    `json:"stars,omitempty"`
	Forks        int    `json:"forks,omitempty"`
}

// StructuredTimeline holds separate arrays for references and repositories.
type StructuredTimeline struct {
	References   []TimelineEntry `json:"references"`
	Repositories []TimelineEntry `json:"repositories"`
}
