package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectPython(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests>=2.0\nnumpy\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Detector{Dir: dir}
	rules := d.DetectDependencies()
	if len(rules) == 0 {
		t.Fatal("expected at least one rule, got none")
	}
	found := false
	for _, r := range rules {
		if r.ID == "pypi" {
			found = true
		}
	}
	if !found {
		t.Error("expected a pypi rule to be detected")
	}
}

func TestDetectNoFiles(t *testing.T) {
	dir := t.TempDir()
	d := &Detector{Dir: dir}
	rules := d.DetectDependencies()
	if len(rules) != 0 {
		t.Errorf("expected no rules for empty dir, got %d", len(rules))
	}
}

func TestDetectNode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Detector{Dir: dir}
	rules := d.DetectDependencies()
	found := false
	for _, r := range rules {
		if r.ID == "npm" {
			found = true
		}
	}
	if !found {
		t.Error("expected npm rule for package.json project")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	content := "# comment\nrequests>=2.28\nnumpy==1.24\n-r other.txt\npandas[excel]\n"
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"requests", "numpy", "pandas"}
	if len(pkgs) != len(expected) {
		t.Fatalf("expected %v packages, got %v", expected, pkgs)
	}
	for i, p := range pkgs {
		if p != expected[i] {
			t.Errorf("package[%d]: expected %q, got %q", i, expected[i], p)
		}
	}
}
