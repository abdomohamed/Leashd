package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// KnownPyPIDomains are the standard domains needed for pip/PyPI operations.
var KnownPyPIDomains = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"*.pythonhosted.org",
}

// Detector scans a project directory for dependency files and suggests rules.
type Detector struct {
	Dir string
}

// DetectDependencies scans for requirements.txt / pyproject.toml and returns
// pre-populated rules for known-safe package registries.
func (d *Detector) DetectDependencies() []Rule {
	var rules []Rule

	if d.hasFile("requirements.txt") || d.hasFile("pyproject.toml") || d.hasFile("setup.py") || d.hasFile("Pipfile") {
		rules = append(rules, Rule{
			ID:      "pypi",
			Comment: "PyPI package index and CDN — auto-detected from Python project",
			Domains: KnownPyPIDomains,
			Ports:   []uint16{443, 80},
			Action:  ActionAllow,
		})
	}

	if d.hasFile("package.json") || d.hasFile("yarn.lock") || d.hasFile("pnpm-lock.yaml") {
		rules = append(rules, Rule{
			ID:      "npm",
			Comment: "npm registry — auto-detected from Node.js project",
			Domains: []string{"registry.npmjs.org", "*.npmjs.org"},
			Ports:   []uint16{443, 80},
			Action:  ActionAllow,
		})
	}

	if d.hasFile("go.mod") {
		rules = append(rules, Rule{
			ID:      "go-modules",
			Comment: "Go module proxy and sum database — auto-detected from Go project",
			Domains: []string{"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"},
			Ports:   []uint16{443},
			Action:  ActionAllow,
		})
	}

	if d.hasFile("Cargo.toml") {
		rules = append(rules, Rule{
			ID:      "crates-io",
			Comment: "crates.io registry — auto-detected from Rust project",
			Domains: []string{"crates.io", "*.crates.io", "static.crates.io"},
			Ports:   []uint16{443},
			Action:  ActionAllow,
		})
	}

	return rules
}

// ParseRequirementsTxt reads a requirements.txt and returns the list of package names.
// This can be used to further refine suggestions in future.
func ParseRequirementsTxt(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var packages []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip version specifiers: package>=1.0 → package
		name := strings.FieldsFunc(line, func(r rune) bool {
			return r == '>' || r == '<' || r == '=' || r == '!' || r == '[' || r == ';'
		})[0]
		packages = append(packages, strings.TrimSpace(name))
	}
	return packages, scanner.Err()
}

func (d *Detector) hasFile(name string) bool {
	_, err := os.Stat(filepath.Join(d.Dir, name))
	return err == nil
}
