package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"embed"

	"github.com/spf13/cobra"
	"vulnerawise/pkg/audit"
)

var (
	policiesDir       string
	validIntegrations = []string{"grype", "trivy", "stackrox"}
)

// auditCmd represents the "audit" command.
var auditCmd = &cobra.Command{
	Use:   "audit [integration] [scan-file]",
	Short: "Audit vulnerability scanner reports against security policies",
	Long: `Audit vulnerability scanner reports against defined security policies.

Supported integrations:
  - grype
  - trivy
  - stackrox

Examples:
  vulnerawise audit trivy path/to/trivy-report.json
  vulnerawise audit grype path/to/grype-report.json

`,
	// These prevent Cobra from auto-printing usage/errors when we return an error.
	SilenceUsage:  true,
	SilenceErrors: true,

	RunE: runAuditCmd,
}

func init() {
	auditCmd.Flags().StringVar(&policiesDir, "policies-dir", "",
		"Directory containing YAML policy definitions (overrides embedded defaults)")
}

// runAuditCmd is the main execution function for the "audit" command.
func runAuditCmd(cmd *cobra.Command, args []string) error {
	// If no arguments: print help, exit code 0 (change to error if preferred).
	if len(args) == 0 {
		_ = cmd.Help()
		return nil
	}

	// Validate the first argument is a supported integration.
	integration := args[0]
	if !isSupportedIntegration(integration) {
		// Print a single error line, then the help, then return an error (exit != 0).
		_ = cmd.Help()
		return errors.New("\n Error: invalid integration")
	}

	// Validate argument count (must be exactly 2).
	if len(args) < 2 {
		_ = cmd.Help()
		return errors.New("\n Error: missing scan-file argument")
	}
	if len(args) > 2 {
		_ = cmd.Help()
		return fmt.Errorf("\n Error: too many arguments: %d", len(args))
	}

	// Now we have exactly 2 args, and the integration is valid.
	scanFile := filepath.Clean(args[1])
	fileInfo, err := os.Stat(scanFile)
	if err != nil {
		_ = cmd.Help()
		return fmt.Errorf("\n Error: cannot access file: %w", err)
	}
	if fileInfo.IsDir() {
		_ = cmd.Help()
		return errors.New("\n Error: scan-file is a directory")
	}

	// Decide custom vs. embedded policies
	if policiesDir != "" {
		policiesDir = filepath.Clean(policiesDir)
		fmt.Printf("Using custom policies from directory: %q\n", policiesDir)
		// TODO: load custom policy files from policiesDir
	} else {
		fmt.Println("Using embedded default policies...")
		fs := audit.GetDefaultPolicyFS()
		embedFS, _ := fs.(embed.FS)
		// TODO: parse policies from fs
		// Choose the exact file you want to print from the embedded filesystem
		fileName := "policies/policy8.yaml"

		data, err := embedFS.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("failed to read embedded policy file %q: %w", fileName, err)
		}

		// Print the file contents
		fmt.Printf("Contents of %s:\n\n%s\n", fileName, data)
	}

	fmt.Printf("Running audit for integration %q on file %q...\n", integration, scanFile)

	// --------------------------------------------------------------------------
	// TODO:
	//   1. Parse the scanFile for the chosen integration (grype/trivy/stackrox).
	//   2. Evaluate results against loaded policies.
	//   3. Print or return findings/violations.
	// --------------------------------------------------------------------------

	return nil
}

func isSupportedIntegration(integration string) bool {
	for _, val := range validIntegrations {
		if integration == val {
			return true
		}
	}
	return false
}
