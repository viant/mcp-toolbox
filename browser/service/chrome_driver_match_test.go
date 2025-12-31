package service

import "testing"

func TestParseMajor_ChromeVersion(t *testing.T) {
	tests := []struct {
		out   string
		major int
	}{
		{"Google Chrome 125.0.6422.76", 125},
		{"Chromium 120.0.6099.71 snap", 120},
		{"Google Chrome 143.0.1234.5", 143},
	}
	for _, tt := range tests {
		got, ok := parseMajor(tt.out, chromeVersionMatcher)
		if !ok || got != tt.major {
			t.Fatalf("parseMajor(%q) = %v,%v; want %v,true", tt.out, got, ok, tt.major)
		}
	}
}

func TestParseMajor_ChromeDriverVersion(t *testing.T) {
	got, ok := parseMajor("ChromeDriver 125.0.6422.76 (deadbeef)", chromedriverVersionMatcher)
	if !ok || got != 125 {
		t.Fatalf("parseMajor(chromedriver) = %v,%v; want 125,true", got, ok)
	}
}
