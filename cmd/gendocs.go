package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func GenDocsCmd(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:     "gendocs",
		Aliases: []string{"docs", "mkdocs"},
		Short:   "Generate documentation",
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create docs directory if it doesn't exist
			if err := os.MkdirAll("./docs", 0755); err != nil {
				return fmt.Errorf("failed to create docs directory: %w", err)
			}

			rootCmd.DisableAutoGenTag = true

			// Generate markdown documentation
			if err := doc.GenMarkdownTree(rootCmd, "./docs"); err != nil {
				return fmt.Errorf("failed to generate markdown docs: %w", err)
			}

			fmt.Println("Documentation generated in ./docs")
			return nil
		},
	}
}
