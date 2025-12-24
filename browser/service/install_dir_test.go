package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultInstallDir_ExplicitWins(t *testing.T) {
	dir := defaultInstallDir("/custom/path")
	if dir != "/custom/path" {
		t.Fatalf("expected explicit path, got %q", dir)
	}
}

func TestDirHasDriver(t *testing.T) {
	tmp := t.TempDir()
	if dirHasDriver(tmp) {
		t.Fatalf("expected no driver")
	}
	p := filepath.Join(tmp, ChromeDriver)
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !dirHasDriver(tmp) {
		t.Fatalf("expected driver present")
	}
}
