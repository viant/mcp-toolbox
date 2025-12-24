package service

import "testing"

func TestResolveBrowser_DefaultsToChrome(t *testing.T) {
	if got := resolveBrowser("", ""); got != ChromeBrowser {
		t.Fatalf("expected %q, got %q", ChromeBrowser, got)
	}
}

func TestResolveBrowser_PrefersRequested(t *testing.T) {
	if got := resolveBrowser(FirefoxBrowser, " chrome "); got != ChromeBrowser {
		t.Fatalf("expected %q, got %q", ChromeBrowser, got)
	}
}

func TestResolveBrowser_UsesExisting(t *testing.T) {
	if got := resolveBrowser(" FIREFOX ", ""); got != FirefoxBrowser {
		t.Fatalf("expected %q, got %q", FirefoxBrowser, got)
	}
}
