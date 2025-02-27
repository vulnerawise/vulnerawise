package cmd

import (
	"fmt"
	"log"
	"os"

	"vulnerawise/pkg/db"

	"github.com/spf13/cobra"
)

var skipUpdateCheck bool

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "vulnerawise",
	Short: "Vulnerawise cli tool to query and process CVE exploitation data, providing actionable intelligence for real-world threat prioritization.",
	Long:  `Vulnerawise cli tool to query and process CVE exploitation data, providing actionable intelligence for real-world threat prioritization.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip database check for updatedb command
		if cmd.Name() == "updatedb" {
			return
		}

		// Check for database updates unless --skip-update is specified
		if !skipUpdateCheck {
			if err := db.CheckAndUpdateIfNeeded(db.DefaultAPIBaseURL); err != nil {
				log.Printf("Warning: Failed to check for database updates: %v", err)
				// Continue execution as database update failure is non-critical
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Add persistent flags that will be available to all commands
	rootCmd.PersistentFlags().BoolVar(&skipUpdateCheck, "skip-update", false, "Skip database update check")

	// Add subcommands
	rootCmd.AddCommand(updatedbCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(trendingCmd)
}
