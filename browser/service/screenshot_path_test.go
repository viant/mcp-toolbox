package service

import (
	"strings"
	"testing"
)

func TestDefaultScreenshotDestURL(t *testing.T) {
	url, err := DefaultScreenshotDestURL("localhost:4444")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(url, "file://") {
		t.Fatalf("expected file:// url, got %q", url)
	}
	if !strings.Contains(url, "localhost_4444") {
		t.Fatalf("expected session id in url, got %q", url)
	}
	if !strings.HasSuffix(url, ".png") {
		t.Fatalf("expected png suffix, got %q", url)
	}
}
