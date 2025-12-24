package service

import "strings"

func enforceHeadfulCaps(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		lower := strings.ToLower(trimmed)
		if lower == "headless" || strings.HasPrefix(lower, "--headless") || strings.HasPrefix(lower, "-headless") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
