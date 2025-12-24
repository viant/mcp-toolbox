package service

import (
	"context"
	"testing"
)

func TestResolveChromeForTestingVersion_Major(t *testing.T) {
	prevFetch := chromeForTestingFetch
	t.Cleanup(func() { chromeForTestingFetch = prevFetch })
	chromeForTestingFetch = func(_ context.Context, url string) (string, error) {
		if url == chromeForTestingBaseURL+"/LATEST_RELEASE_143" {
			return "143.0.1234.5", nil
		}
		return "", nil
	}

	got, err := resolveChromeForTestingVersion(context.Background(), "143", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "143.0.1234.5" {
		t.Fatalf("expected resolved version, got %q", got)
	}
}

func TestResolveChromeForTestingVersion_Stable(t *testing.T) {
	prevFetch := chromeForTestingFetch
	t.Cleanup(func() { chromeForTestingFetch = prevFetch })
	chromeForTestingFetch = func(_ context.Context, url string) (string, error) {
		if url == chromeForTestingBaseURL+"/LATEST_RELEASE_STABLE" {
			return "144.0.0.0", nil
		}
		return "", nil
	}

	got, err := resolveChromeForTestingVersion(context.Background(), "stable", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "144.0.0.0" {
		t.Fatalf("expected resolved version, got %q", got)
	}
}
