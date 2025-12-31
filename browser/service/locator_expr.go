package service

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseLocatorExpr parses a minimal locator expression used in browserRun selector blocks, e.g.:
//   "text=Sign in"
//   "role=button name='Sign in' exact=true"
//   "within(text='Dialog') role=button name='Sign in'"
//   "or(text='Sign in', text='Log in')"
//   "and(role=button, name='Submit')"    (equivalent to multiple terms, but explicit)
//   "not(text='Cancel')"
//
// It returns (locator, ok). When ok=false, caller should treat it as a normal selector.
func parseLocatorExpr(expr string) (*Locator, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, false
	}
	// Heuristic: must include at least one known key= pair.
	// Allow function forms even without raw key=value at the top level (e.g. not(...)).
	if strings.Contains(expr, "=") || strings.HasPrefix(strings.ToLower(expr), "within(") ||
		strings.HasPrefix(strings.ToLower(expr), "or(") ||
		strings.HasPrefix(strings.ToLower(expr), "and(") ||
		strings.HasPrefix(strings.ToLower(expr), "not(") {
		loc, err := parseLocatorExprRec(expr)
		if err != nil || loc == nil {
			return nil, false
		}
		return loc, true
	}
	return nil, false
}

func marshalLocatorJSON(loc *Locator) string {
	if loc == nil {
		return ""
	}
	b, _ := json.Marshal(loc)
	return string(b)
}

func parseLocatorExprRec(expr string) (*Locator, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty")
	}
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "or(") && strings.HasSuffix(expr, ")") {
		body := strings.TrimSpace(expr[3 : len(expr)-1])
		parts := splitArgs(body)
		var any []*Locator
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			sub, err := parseLocatorExprRec(p)
			if err != nil {
				return nil, err
			}
			any = append(any, sub)
		}
		if len(any) == 0 {
			return nil, fmt.Errorf("or() empty")
		}
		return &Locator{Any: any}, nil
	}
	if strings.HasPrefix(lower, "and(") && strings.HasSuffix(expr, ")") {
		body := strings.TrimSpace(expr[4 : len(expr)-1])
		parts := splitArgs(body)
		var all []*Locator
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			sub, err := parseLocatorExprRec(p)
			if err != nil {
				return nil, err
			}
			all = append(all, sub)
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("and() empty")
		}
		return &Locator{All: all}, nil
	}
	if strings.HasPrefix(lower, "not(") && strings.HasSuffix(expr, ")") {
		body := strings.TrimSpace(expr[4 : len(expr)-1])
		sub, err := parseLocatorExprRec(body)
		if err != nil {
			return nil, err
		}
		return &Locator{Not: sub}, nil
	}

	// Extract optional within(...)
	var within *Locator
	rest := expr
	if wExpr, after, ok := extractFuncCall(rest, "within"); ok {
		sub, err := parseLocatorExprRec(wExpr)
		if err != nil {
			return nil, err
		}
		within = sub
		rest = strings.TrimSpace(after)
		if rest != "" {
			// Support `within(...) <expr>` where <expr> can be composite (or/and/not) or leaf tokens.
			if inner, err := parseLocatorExprRec(rest); err == nil && inner != nil {
				// If the nested locator already has its own within, keep it intact by wrapping.
				if inner.Within != nil {
					return &Locator{Within: within, All: []*Locator{inner}}, nil
				}
				inner.Within = within
				return inner, nil
			}
		}
	}

	tokens := scanKeyValueTokens(rest)
	loc := &Locator{}
	used := false
	for k, v := range tokens {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "text":
			loc.Text = v
			used = true
		case "name":
			loc.Name = v
			used = true
		case "role":
			loc.Role = v
			used = true
		case "testid", "test_id", "test-id", "data-testid":
			loc.TestID = v
			used = true
		case "css":
			loc.CSS = v
			used = true
		case "xpath":
			loc.XPath = v
			used = true
		case "exact":
			loc.Exact = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
			used = true
		}
	}
	if within != nil {
		loc.Within = within
		used = true
	}
	if !used {
		return nil, fmt.Errorf("no locator keys")
	}
	return loc, nil
}

func extractFuncCall(expr string, name string) (inner string, after string, ok bool) {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	prefix := strings.ToLower(name) + "("
	if !strings.HasPrefix(lower, prefix) {
		return "", expr, false
	}
	// Find matching closing paren for the first function call.
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			depth--
			if depth == 0 {
				inner = strings.TrimSpace(expr[len(prefix) : i])
				after = strings.TrimSpace(expr[i+1:])
				return inner, after, true
			}
		}
	}
	return "", expr, false
}

func splitTopLevel(s string, sep byte) []string {
	var out []string
	start := 0
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && c == sep {
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Prefer comma separation, but allow '|' as legacy separator (used in early drafts).
	parts := splitTopLevel(s, ',')
	if len(parts) <= 1 {
		parts = splitTopLevel(s, '|')
	}
	return parts
}

func scanKeyValueTokens(s string) map[string]string {
	out := map[string]string{}
	i := 0
	n := len(s)
	for i < n {
		for i < n && isSpace(s[i]) {
			i++
		}
		if i >= n {
			break
		}
		// key
		kStart := i
		for i < n && !isSpace(s[i]) && s[i] != '=' {
			i++
		}
		k := strings.TrimSpace(s[kStart:i])
		for i < n && isSpace(s[i]) {
			i++
		}
		if i >= n || s[i] != '=' {
			// not a key=value; skip token
			for i < n && !isSpace(s[i]) {
				i++
			}
			continue
		}
		i++ // '='
		for i < n && isSpace(s[i]) {
			i++
		}
		if i >= n {
			out[k] = ""
			break
		}
		// value (quoted or until whitespace)
		var v string
		if s[i] == '\'' || s[i] == '"' {
			q := s[i]
			i++
			vStart := i
			for i < n && s[i] != q {
				i++
			}
			v = s[vStart:i]
			if i < n && s[i] == q {
				i++
			}
		} else {
			vStart := i
			for i < n && !isSpace(s[i]) {
				i++
			}
			v = s[vStart:i]
		}
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
