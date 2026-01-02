package service

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type dslCommand struct {
	Assign string
	Name   string
	Args   []any
	Kw     map[string]any
}

func parseDSL(line string) (*dslCommand, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty command")
	}

	assign, rhs := splitAssign(line)
	name, argsText, err := splitCall(rhs)
	if err != nil {
		return nil, err
	}

	args, kw, err := parseArgs(argsText)
	if err != nil {
		return nil, err
	}

	return &dslCommand{
		Assign: assign,
		Name:   name,
		Args:   args,
		Kw:     kw,
	}, nil
}

func splitAssign(s string) (assign string, rhs string) {
	// Very small subset: "name = call(...)"
	// Only accept assignment if the left side is a single identifier.
	i := strings.Index(s, "=")
	if i < 0 {
		return "", s
	}
	left := strings.TrimSpace(s[:i])
	right := strings.TrimSpace(s[i+1:])
	if left == "" || right == "" {
		return "", s
	}
	if !isIdent(left) {
		return "", s
	}
	return left, right
}

func splitCall(s string) (name string, argsText string, err error) {
	open := strings.Index(s, "(")
	if open < 0 || !strings.HasSuffix(s, ")") {
		return "", "", fmt.Errorf("expected call syntax name(...): %q", s)
	}
	name = strings.TrimSpace(s[:open])
	if !isIdent(name) {
		return "", "", fmt.Errorf("invalid command name: %q", name)
	}
	argsText = strings.TrimSpace(s[open+1 : len(s)-1])
	return name, argsText, nil
}

func parseArgs(s string) ([]any, map[string]any, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil, nil
	}
	parts, err := splitCSV(s)
	if err != nil {
		return nil, nil, err
	}
	var (
		args []any
		kw   = map[string]any{}
	)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if k, v, ok := splitKV(p); ok {
			val, err := parseValue(v)
			if err != nil {
				return nil, nil, err
			}
			kw[k] = val
			continue
		}
		val, err := parseValue(p)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, val)
	}
	if len(kw) == 0 {
		kw = nil
	}
	return args, kw, nil
}

func splitKV(s string) (key, value string, ok bool) {
	i := strings.Index(s, "=")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(s[:i])
	value = strings.TrimSpace(s[i+1:])
	if !isIdent(key) || value == "" {
		return "", "", false
	}
	return key, value, true
}

func parseValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return unquote(s)
	}
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if strings.ContainsAny(s, ".eE") {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
	}
	if i, err := strconv.Atoi(s); err == nil {
		return i, nil
	}
	return s, nil
}

func unquote(s string) (string, error) {
	quote := s[0]
	var b strings.Builder
	for i := 1; i < len(s)-1; i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s)-1 {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case '\'':
				b.WriteByte('\'')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(ch)
	}
	if s[0] != quote || s[len(s)-1] != quote {
		return "", fmt.Errorf("invalid quoted string: %q", s)
	}
	return b.String(), nil
}

func splitCSV(s string) ([]string, error) {
	var (
		out []string
		cur strings.Builder
		inQ byte
		esc bool
	)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if esc {
			cur.WriteByte(ch)
			esc = false
			continue
		}
		if ch == '\\' && inQ != 0 {
			cur.WriteByte(ch)
			esc = true
			continue
		}
		if inQ != 0 {
			if ch == inQ {
				inQ = 0
			}
			cur.WriteByte(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			inQ = ch
			cur.WriteByte(ch)
			continue
		}
		if ch == ',' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	if inQ != 0 {
		return nil, fmt.Errorf("unterminated string literal")
	}
	out = append(out, cur.String())
	return out, nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !unicode.IsLetter(r) && r != '_' {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}
