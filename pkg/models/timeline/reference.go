package timeline

// Reference provides external links to CVE details
type Reference struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	SourceType  string `json:"source_type"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
	Published   string `json:"published"`
}
