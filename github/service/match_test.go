package service

import (
	"testing"
)

func Test_filterContentPatterns_OR_Split_and_CaseInsensitiveRegex(t *testing.T) {
	// Given an OR pattern without regex delimiters
	in := []string{"restamp|re-stamp|restamping"}
	out := filterContentPatterns(in)
	// Expect it to expand into individual tokens (treated as literals)
	if len(out) != 3 {
		t.Fatalf("expected 3 tokens after split, got %d: %#v", len(out), out)
	}
}

func Test_countMatches_and_findMatchRanges_with_OR(t *testing.T) {
	// Mixed content with different casings and hyphen
	src := []byte("Restamping allows re-stamp operations. Also restamp and RESTAMPING occur.")
	pats := filterContentPatterns([]string{"restamp|re-stamp|restamping"})
	// Force case-insensitive
	ci := true

	if n := countMatches(src, pats, ci); n <= 0 {
		t.Fatalf("expected matches > 0, got %d", n)
	}
	if rs := findMatchRanges(src, pats, ci); len(rs) == 0 {
		t.Fatalf("expected non-empty match ranges")
	}
	// Ensure snippets are produced in match mode
	snips, _, covered, total := buildMatchSnippetsCompact(src, pats, ci, 2, 200, 5)
	if len(snips) == 0 || total == 0 || covered == 0 {
		t.Fatalf("expected non-empty snippets and counts, got snips=%d covered=%d total=%d", len(snips), covered, total)
	}
}
