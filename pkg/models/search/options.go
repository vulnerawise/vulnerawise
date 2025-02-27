package search

// SearchOptions holds search filters and parameters
type SearchOptions struct {
	CVEIds                 []string
	PublishedDateRange     string
	ExploitPublishedFilter string
	PublishedFilter        string
	LastModified           string
	ExploitMaturity        string
	Severity               string
	DescriptionLike        string
	Feed                   string
	Limit                  int
	Offset                 int
	Trending               bool
	EPSSOperator           string  // New field for EPSS comparison operator
	EPSSValue              float64 // New field for EPSS value to compare against
}
