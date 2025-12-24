package service

import (
	"unicode/utf8"
)

func truncateUTF8ByBytes(s string, maxBytes int) (out string, truncated bool) {
	if maxBytes <= 0 {
		return s, false
	}
	b := []byte(s)
	if len(b) <= maxBytes {
		return s, false
	}
	b = b[:maxBytes]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b), true
}
