package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"vulnerawise/pkg/db" // Import the package that contains your download logic.
)

var fromURL string

// updatedbCmd represents the updatedb command which manages the database download/update.
// Default URL: https://api.vulnerawise.ai/vulnerabilities.db
var updatedbCmd = &cobra.Command{
	Use:   "updatedb",
	Short: "Download or update database",
	Long: `Download or update the local database containing CVE data.
Optionally, you can specify a URL using the --from-url flag to download the database from a remote source.`,
	Run: func(cmd *cobra.Command, args []string) {
		// If no URL is provided, use the default.
		url := fromURL
		if url == "" {
			url = "https://api.vulnerawise.ai/vulnerabilities.db"
		}
		fmt.Printf("Downloading database from URL: %s\n", url)

		// Call the DownloadAndUpdateDB function from your db package.
		if err := db.DownloadAndUpdateDB(url); err != nil {
			log.Printf("Error updating database: %v", err)
			return
		}
		fmt.Println("Database update process completed.")
	},
}

func init() {
	// Bind the optional --from-url flag.
	updatedbCmd.Flags().StringVar(&fromURL, "from-url", "", "Optional URL to download the database from")
	// Add updatedbCmd to the root command.
}
