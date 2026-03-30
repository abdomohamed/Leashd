package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/abdotalema/leashd/internal/config"
	"github.com/spf13/cobra"
)

var (
	flagInitName  string
	flagInitForce bool
	flagInitDetect bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold a rules.yaml in the current project directory",
	Long: `leashd init creates a rules.yaml file with sensible defaults.
It auto-detects requirements.txt, package.json, go.mod, and Cargo.toml
to pre-populate known-safe registry domains.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVar(&flagInitName, "name", "", "Project name (default: directory basename)")
	initCmd.Flags().BoolVar(&flagInitForce, "force", false, "Overwrite existing rules.yaml")
	initCmd.Flags().BoolVar(&flagInitDetect, "detect", true, "Auto-detect dependency files")
}

func runInit(cmd *cobra.Command, args []string) error {
	dir, err := projectDir()
	if err != nil {
		return err
	}

	rulesPath := filepath.Join(dir, "rules.yaml")
	if _, err := os.Stat(rulesPath); err == nil && !flagInitForce {
		return fmt.Errorf("rules.yaml already exists in %s (use --force to overwrite)", dir)
	}

	name := flagInitName
	if name == "" {
		name = filepath.Base(dir)
	}

	var extraRules []config.Rule
	if flagInitDetect {
		d := &config.Detector{Dir: dir}
		extraRules = d.DetectDependencies()
		if len(extraRules) > 0 {
			fmt.Printf("Detected %d rule(s) from project dependencies:\n", len(extraRules))
			for _, r := range extraRules {
				fmt.Printf("  + %s (%s)\n", r.ID, r.Comment)
			}
		}
	}

	data := config.Scaffold(name, extraRules)
	if err := os.WriteFile(rulesPath, data, 0644); err != nil {
		return fmt.Errorf("write rules.yaml: %w", err)
	}

	// Add .leashd/ to .gitignore if it exists.
	gitignorePath := filepath.Join(dir, ".gitignore")
	appendToGitignore(gitignorePath, ".leashd/")

	fmt.Printf("Created %s\n", rulesPath)
	fmt.Println("Edit rules.yaml to configure your policy, then run:")
	fmt.Printf("  sudo leashd run <your command>\n")
	return nil
}

func appendToGitignore(path string, entry string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // .gitignore doesn't exist — skip
	}
	if contains(string(data), entry) {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintln(f, entry)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && (s[:len(substr)] == substr ||
			containsAt(s, substr)))
}

func containsAt(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
