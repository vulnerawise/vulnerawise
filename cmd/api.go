package cmd

import (
	"fmt"
	"log"
	"net/http"

	"vulnerawise/pkg/api"
	"vulnerawise/pkg/db"

	"github.com/spf13/cobra"
)

var serverPort int

var serverCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the database.
		if err := db.Init(db.GetDBPath()); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}

		// In your main.go or wherever you set up routes
		http.Handle("/v1/vuln", api.CORSMiddleware(http.HandlerFunc(api.VulnHandler)))

		log.Printf("Starting API server on port %d...", serverPort)
		return http.ListenAndServe(fmt.Sprintf(":%d", serverPort), nil)
	},
}

func init() {
	// Define the --port flag with a default value of 8080.
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "Port to run the API server on")
}
