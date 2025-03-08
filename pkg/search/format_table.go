package search

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"vulnerawise/pkg/models/search"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

// PrintTableFromJSON prints CVE data in a paginated table.
func PrintTableFromJSON(jsonData []byte) error {
	type DataEntry struct {
		Cve struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Metadata    struct {
				ConfidenceLevel string `json:"confidence_level"`
				Severity        string `json:"severity"`
				Published       string `json:"published"`
			} `json:"metadata"`
			Impact struct {
				ExploitMaturity string `json:"exploit_maturity"`
			} `json:"impact"`
			EPSS struct {
				Score float64 `json:"score"`
			} `json:"epss"`
		} `json:"cve"`
	}
	type Output struct {
		Metadata search.Metadata `json:"metadata"`
		Data     []DataEntry     `json:"data"`
	}

	var out Output
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return fmt.Errorf("failed to unmarshal JSON for table: %w", err)
	}

	// Get terminal width
	var termWidth int = 100
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		termWidth = w
	}
	effectiveWidth := int(float64(termWidth) * 0.95) // Use more of the terminal width

	// Define column widths more effectively
	const cveIDWidth = 15
	const severityWidth = 10
	const maturityWidth = 15
	const confidenceWidth = 10
	const epssWidth = 10

	fixedWidth := cveIDWidth + severityWidth + maturityWidth + confidenceWidth + epssWidth + 15
	descWidth := effectiveWidth - fixedWidth
	if descWidth > 120 {
		descWidth = 120 // Cap at reasonable max
	}
	if descWidth < 30 {
		descWidth = 30 // Ensure minimum width
	}

	// Create table writer
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"CVE ID", "DESCRIPTION", "SEVERITY", "EXPLOIT MATURITY", "CONFIDENCE", "EPSS"})
	table.SetBorder(true)
	table.SetCenterSeparator("|")
	table.SetAutoWrapText(false)
	table.SetRowLine(true) // Add line separators between CVEs
	table.SetColWidth(descWidth)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_LEFT,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
		tablewriter.ALIGN_CENTER,
	})

	// Set colors based on severity and exploitation status
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
		tablewriter.Colors{tablewriter.Bold},
	)

	const maxRowsPerPage = 20 // Reduced for better readability
	for i, d := range out.Data {
		// Truncate description with smart summary
		description := smartTruncate(d.Cve.Description, 200)
		wrappedLines := wrapText(description, descWidth)
		descCell := strings.Join(wrappedLines, "\n")

		// Format EPSS score
		epssScore := fmt.Sprintf("%.1f%%", d.Cve.EPSS.Score*100)
		if d.Cve.EPSS.Score == 0 {
			epssScore = "0.0"
		}

		if d.Cve.Metadata.Severity == "" {
			d.Cve.Metadata.Severity = "n/a"
		}

		row := []string{
			d.Cve.ID,
			descCell,
			d.Cve.Metadata.Severity,
			d.Cve.Impact.ExploitMaturity,
			d.Cve.Metadata.ConfidenceLevel,
			epssScore,
		}

		// Set color based on severity and exploit
		colors := []tablewriter.Colors{
			{tablewriter.Bold}, // CVE ID
			{},                 // Description
			getSeverityColor(d.Cve.Metadata.Severity),     // Severity
			getExploitColor(d.Cve.Impact.ExploitMaturity), // Exploit Maturity
			{},                             // Confidence
			getEPSSColor(d.Cve.EPSS.Score), // EPSS
		}
		table.Rich(row, colors)

		if (i+1)%maxRowsPerPage == 0 && i < len(out.Data)-1 {
			table.Render()
			fmt.Print("\nPress Enter to continue...")
			fmt.Scanln()
			table.ClearRows()
		}
	}

	if len(out.Data)%maxRowsPerPage != 0 {
		table.Render()
	}

	return nil
}

// PrintExploitPlain prints exploit details in a plain text format.
// It prints the CVE ID once and then each associated URL on separate lines,
// with a clear separator between URL entries.
func PrintExploitTableFromJSON(jsonData []byte) error {
	// Define only the fields we care about.
	type DataEntry struct {
		Cve struct {
			ID       string `json:"id"`
			Timeline struct {
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
				Repositories []struct {
					URL string `json:"url"`
				} `json:"repositories"`
			} `json:"timeline"`
		} `json:"cve"`
	}
	type Output struct {
		Data []DataEntry `json:"data"`
	}
	var out Output
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return fmt.Errorf("failed to unmarshal JSON for plain output: %w", err)
	}

	separator := strings.Repeat("-", 80)
	for _, entry := range out.Data {
		var urls []string
		// Collect URLs from timeline references.
		for _, ref := range entry.Cve.Timeline.References {
			if ref.URL != "" {
				urls = append(urls, ref.URL)
			}
		}
		// Collect URLs from repository entries.
		for _, repo := range entry.Cve.Timeline.Repositories {
			if repo.URL != "" {
				urls = append(urls, repo.URL)
			}
		}
		// Skip entries with no URLs.
		if len(urls) == 0 {
			continue
		}

		// Print the CVE ID once.
		fmt.Printf("CVE ID: %s\n", entry.Cve.ID)
		fmt.Println("Exploit URLs:")
		// Print each URL on a separate line.
		for _, url := range urls {
			fmt.Printf("  - %s\n", url)
		}
		// Print a separator line between CVE entries.
		fmt.Println(separator)
	}
	return nil
}

// Helper functions for colors
func getSeverityColor(severity string) tablewriter.Colors {
	switch strings.ToLower(severity) {
	case "critical":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor}
	case "high":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}
	case "medium":
		return tablewriter.Colors{tablewriter.FgYellowColor}
	case "low":
		return tablewriter.Colors{tablewriter.FgGreenColor}
	default:
		return tablewriter.Colors{}
	}
}

func getExploitColor(exploit string) tablewriter.Colors {
	switch strings.ToLower(exploit) {
	case "active":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor}
	case "weaponized":
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgRedColor}
	case "poc":
		return tablewriter.Colors{tablewriter.FgYellowColor}
	default:
		return tablewriter.Colors{tablewriter.FgHiBlackColor}
	}
}

func getEPSSColor(score float64) tablewriter.Colors {
	if score >= 0.5 {
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor}
	} else if score >= 0.2 {
		return tablewriter.Colors{tablewriter.FgRedColor}
	} else if score >= 0.1 {
		return tablewriter.Colors{tablewriter.FgYellowColor}
	}
	return tablewriter.Colors{}
}

// smartTruncate creates a more intelligent summary of text
func smartTruncate(text string, maxLen int) string {
	text = removeURLs(text)
	text = strings.TrimSpace(text)

	if len(text) <= maxLen {
		return text
	}

	// Try to find a period or other sentence-ending punctuation
	for i := maxLen - 1; i >= maxLen/2; i-- {
		if text[i] == '.' || text[i] == '!' || text[i] == '?' {
			return text[:i+1]
		}
	}

	// If no good breakpoint, look for last space
	for i := maxLen - 1; i >= 0; i-- {
		if text[i] == ' ' {
			return text[:i] + "..."
		}
	}

	return text[:maxLen-3] + "..."
}

// removeURLs and wrapText helper functions remain unchanged.
func removeURLs(text string) string {
	re := regexp.MustCompile(`https?://\S+`)
	return re.ReplaceAllString(text, "")
}

func wrapText(text string, width int) []string {
	text = removeURLs(text)
	text = strings.TrimSpace(text)

	const maxTotalChars = 500
	if len(text) > maxTotalChars {
		text = text[:maxTotalChars-3] + "..."
	}

	var lines []string
	words := strings.Fields(text)
	var currentLine strings.Builder

	for _, word := range words {
		if len(word) > width {
			for i := 0; i < len(word); i += width {
				end := i + width
				if end > len(word) {
					end = len(word)
				}
				lines = append(lines, word[i:end])
			}
			continue
		}

		if currentLine.Len()+len(word)+1 > width {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
		}
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return lines
}
