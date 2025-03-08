package timeline

// Timeline holds references and repositories related to a CVE.
type Timeline struct {
	References   []Reference  `json:"references"`
	Repositories []Repository `json:"repositories"`
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
	RepoName     string `json:"name,omitempty"`
	Stars        int    `json:"stars,omitempty"`
	Forks        int    `json:"forks,omitempty"`
}

// StructuredTimeline holds separate arrays for references and repositories.
type StructuredTimeline struct {
	References   []TimelineEntry `json:"references"`
	Repositories []TimelineEntry `json:"repositories"`
}
