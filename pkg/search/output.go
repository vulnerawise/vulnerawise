package search

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

// FormatOutput converts the raw Vulnerability slice into the final JSON structure.
func FormatOutput(vulns []Vulnerability) ([]byte, error) {
	out := Output{
		Metadata: Metadata{
			Timestamp: time.Now().Format(time.RFC3339),
		},
	}

	for _, v := range vulns {
		var entry DataEntry
		entry.Cve.ID = v.CVEID
		entry.Cve.Description = v.Description
		// Note: Published and LastModified are preserved in the JSON output,
		// even if not shown in the table.
		entry.Cve.Metadata.PublishedDate = v.Published
		entry.Cve.Metadata.LastModifiedDate = v.LastModified
		entry.Cve.Metadata.ConfidenceLevel = v.ConfidenceLevel

		// Unmarshal metrics only once.
		var metrics []Metric
		if err := json.Unmarshal([]byte(v.Metrics), &metrics); err != nil {
			log.Printf("Error unmarshaling metrics for CVE %s: %v", v.CVEID, err)
		}
		if v.BestSeverity != "" {
			entry.Cve.Metadata.Severity = v.BestSeverity
		} else {
			entry.Cve.Metadata.Severity = "n/a"
		}

		// Determine if this CVE is automatable.
		automatable := false
		for _, m := range metrics {
			if isAuto, _ := IsAutomatable(m.VectorString); isAuto {
				automatable = true
				break
			}
		}
		entry.Cve.Impact.CisaKEV = v.CisaKEV
		entry.Cve.Impact.ReportedExploited = v.ReportedExploited
		entry.Cve.Impact.ExploitMaturity = determineExploitMaturity(v)
		entry.Cve.Impact.Automatable = automatable

		entry.Cve.Counts.PublicExploitCount = v.PublicExploitCount
		entry.Cve.Epss.Score = v.EPSSScore
		entry.Cve.Epss.Percentile = v.EPSSPercentile

		// Reuse the already unmarshaled metrics for output.
		entry.Cve.Metrics = metrics
		entry.Cve.Timeline = json.RawMessage(v.Timeline)

		out.Data = append(out.Data, entry)
	}

	return json.MarshalIndent(out, "", "  ")
}

// PrintTableFromJSON_old is the legacy version of table printing.
// (It is kept here for reference and is not used in production.)
func PrintTableFromJSON_old(jsonData []byte) error {
	// Define minimal structs to parse the JSON output.
	type DataEntry struct {
		Cve struct {
			ID       string `json:"id"`
			Metadata struct {
				PublishedDate    string `json:"published_date"`
				LastModifiedDate string `json:"last_modified_date"`
				ConfidenceLevel  string `json:"confidence_level"`
				Severity         string `json:"severity"`
			} `json:"metadata"`
			Impact struct {
				ExploitMaturity string `json:"exploit_maturity"`
			} `json:"impact"`
		} `json:"cve"`
	}
	type Output struct {
		Metadata Metadata    `json:"metadata"`
		Data     []DataEntry `json:"data"`
	}

	// Unmarshal the JSON.
	var out Output
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return fmt.Errorf("failed to unmarshal JSON for table: %w", err)
	}

	// Create a new table writer using os.Stdout.
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"CVE ID", "Published", "Modified", "Severity", "Exploit Maturity"})
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetAutoWrapText(false)

	// Append rows from the parsed JSON.
	for _, d := range out.Data {
		row := []string{
			d.Cve.ID,
			d.Cve.Metadata.PublishedDate,
			d.Cve.Metadata.LastModifiedDate,
			d.Cve.Metadata.Severity,
			d.Cve.Impact.ExploitMaturity,
		}
		table.Append(row)
	}

	// Render the table.
	table.Render()
	return nil
}


// PrintTableFromJSON unmarshals the final JSON output and prints a table.
// The table uses an effective width (e.g., 90% of the terminal width) and
// draws a horizontal separator between each CVE.
func PrintTableFromJSON(jsonData []byte) error {
	// Define minimal structs to parse the JSON output.
	type DataEntry struct {
		Cve struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Metadata    struct {
				// "Published" and "Modified" have been removed for a cleaner output.
				ConfidenceLevel string `json:"confidence_level"`
				Severity        string `json:"severity"`
			} `json:"metadata"`
			Impact struct {
				ExploitMaturity string `json:"exploit_maturity"`
			} `json:"impact"`
		} `json:"cve"`
	}
	type Output struct {
		Metadata Metadata    `json:"metadata"`
		Data     []DataEntry `json:"data"`
	}

	// Unmarshal the JSON.
	var out Output
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return fmt.Errorf("failed to unmarshal JSON for table: %w", err)
	}

	// Determine terminal width.
	termWidth, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		termWidth = 100 // Fallback default width.
	}

	// Use 90% of the terminal width as the effective width for the table.
	effectiveWidth := int(float64(termWidth) * 0.9)

	// Define fixed widths for non-description columns.
	const cveIDWidth = 12
	const severityWidth = 10
	const maturityWidth = 15
	const confidenceWidth = 10

	// Calculate the total fixed width (plus extra for borders/separators).
	fixedWidth := cveIDWidth + severityWidth + maturityWidth + confidenceWidth + 12
	// The remaining width is allocated for the DESCRIPTION column.
	descWidth := effectiveWidth - fixedWidth
	if descWidth > 80 {
		descWidth = 80
	}
	if descWidth < 20 {
		descWidth = 20
	}

	// Create a new table writer.
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"CVE ID", "DESCRIPTION", "SEVERITY", "EXPLOIT MATURITY", "CONFIDENCE"})
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	// Disable auto-wrap because we handle wrapping manually.
	table.SetAutoWrapText(false)
	// Enable horizontal separator lines between rows.
	table.SetRowLine(true)

	// Process each CVE entry.
	for _, d := range out.Data {
		// Manually wrap the DESCRIPTION text using the capped width.
		wrappedLines := wrapText(d.Cve.Description, descWidth)
		descCell := strings.Join(wrappedLines, "\n")

		row := []string{
			d.Cve.ID,
			descCell,
			d.Cve.Metadata.Severity,
			d.Cve.Impact.ExploitMaturity,
			d.Cve.Metadata.ConfidenceLevel,
		}
		table.Append(row)
	}

	table.Render()
	return nil
}


// wrapText splits a string into lines with a maximum width.
// It first limits the total number of characters to 500, appending "..." if truncated.
func wrapText(text string, width int) []string {
	// Truncate text to a maximum of 500 characters.
	if len(text) > 500 {
		// Try to avoid cutting a word in half: find the last space before the limit.
		cutoff := 500
		if idx := strings.LastIndex(text[:500], " "); idx != -1 {
			cutoff = idx
		}
		text = text[:cutoff] + "..."
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}

	var lines []string
	currentLine := words[0]
	for _, word := range words[1:] {
		// +1 accounts for the space.
		if len(currentLine)+1+len(word) > width {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			currentLine += " " + word
		}
	}
	lines = append(lines, currentLine)
	return lines
}
