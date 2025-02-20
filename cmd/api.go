package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/spf13/cobra"
	"vulnerawise/pkg/api"
	"vulnerawise/pkg/config"
	"vulnerawise/pkg/db"
)

var serverPort int

var serverCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the database.
		if err := db.Init(config.GetDBPath(), true); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		// Register the API endpoint.
		http.HandleFunc("/v1/vuln", api.VulnHandler)

		log.Printf("Starting API server on port %d...", serverPort)
		return http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil)
	},
}

func init() {
	// Define the --port flag with a default value of 8080.
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "Port to run the API server on")
	// Assuming rootCmd is available in the package,
	// add the server command to the root command.
}
