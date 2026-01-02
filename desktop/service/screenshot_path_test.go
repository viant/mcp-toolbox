package service

import (
	"strings"
	"testing"
)

func TestDefaultScreenshotDestURL(t *testing.T) {
	url, err := DefaultScreenshotDestURL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "file://") {
		t.Fatalf("expected file:// url, got %q", url)
	}
	if !strings.Contains(url, "/mcp-toolbox/desktop/screenshots/") {
		t.Fatalf("unexpected url: %q", url)
	}
	if !strings.HasSuffix(url, ".png") {
		t.Fatalf("expected .png url, got %q", url)
	}
}
