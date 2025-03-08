package timeline

// Repository contains repository information related to a CVE
type Repository struct {
	Type         string `json:"type"`
	URL          string `json:"url"`
	Description  string `json:"description,omitempty"`
	Published    string `json:"published"`
	Created      string `json:"created"`
	LastModified string `json:"last_modified"`
	RepoName     string `json:"name"`
	Stars        int    `json:"stars"`
	Forks        int    `json:"forks"`
}
