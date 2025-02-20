package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	downloadDB     bool
	downloadDBFrom string
	logFile        string
	verbose        bool
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "vulnerawise",
	Short: "Vulnerawise cli tool to query and process CVE exploitation data, providing actionable intelligence for real-world threat prioritization.",
	Long: `Vulnerawise cli tool to query and process CVE exploitation data, providing actionable intelligence for real-world threat prioritization.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
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
	// Add subcommands
	rootCmd.AddCommand(updatedbCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(trendingCmd)
}
