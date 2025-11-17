package service

import "strings"

// effectivePreviewMode normalizes and picks the final preview mode.
// Accepts aliases: "match"|"matches"|"search" -> "match"; "head" -> "head".
// If invalid/empty, chooses "match" when content filters exist; otherwise "head".
// If "match" requested without content filters, falls back to "head".
func effectivePreviewMode(mode string, hasContentFilters bool) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "match", "matches", "search":
		if hasContentFilters {
			return "match"
		}
		return "head"
	case "head":
		return "head"
	default:
		if hasContentFilters {
			return "match"
		}
		return "head"
	}
}
