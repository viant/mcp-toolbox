package service

import "strings"

func resolveBrowser(existing string, requested string) string {
	if strings.TrimSpace(requested) != "" {
		return strings.ToLower(strings.TrimSpace(requested))
	}
	if strings.TrimSpace(existing) != "" {
		return strings.ToLower(strings.TrimSpace(existing))
	}
	return ChromeBrowser
}
