package service

import (
    "os"
    "strings"
)

// safePart normalizes a string for use in composite keys.
// It trims spaces and replaces separators with underscores for stability.
func safePart(s string) string {
    s = strings.TrimSpace(os.ExpandEnv(s))
    repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "|", "_", " ", "_", "@", "_")
    return repl.Replace(s)
}

// joinKey joins parts with '|' after normalizing each with safePart.
func joinKey(parts ...string) string {
    if len(parts) == 0 {
        return ""
    }
    norm := make([]string, 0, len(parts))
    for _, p := range parts {
        norm = append(norm, safePart(p))
    }
    return strings.Join(norm, "|")
}

