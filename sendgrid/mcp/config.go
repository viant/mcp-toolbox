package mcp

import (
	"strings"

	nsprov "github.com/viant/mcp/server/namespace"
)

var defaultNamespaceClaimKeys = []string{"email", "sub"}

// Config controls strict request identity resolution for SendGrid tools.
type Config struct {
	NamespaceClaimKeys []string
	NamespaceProvider  nsprov.Provider
}

// ParseNamespaceClaimKeys parses a comma-separated claim lookup order.
func ParseNamespaceClaimKeys(value string) []string {
	return NormalizeNamespaceClaimKeys(strings.Split(value, ","))
}

// NormalizeNamespaceClaimKeys removes empty and duplicate claim names.
func NormalizeNamespaceClaimKeys(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	if len(result) == 0 {
		return append([]string(nil), defaultNamespaceClaimKeys...)
	}
	return result
}
