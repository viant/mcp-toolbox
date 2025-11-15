package service

// Minimal stubs for sed preview/transform; keep behavior unchanged when scripts are absent.

func applySedPreview(text string, scripts []string, maxEdits int, diffCap int) (int, string) {
	// No-op: return zero edits and empty diff
	return 0, ""
}

func applySedTransform(text string, scripts []string) string {
	// No-op transform
	return text
}
