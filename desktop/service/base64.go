package service

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 data")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	// Some clients include data: URLs; best-effort strip prefix.
	if i := strings.Index(s, "base64,"); i >= 0 {
		b, err2 := base64.StdEncoding.DecodeString(s[i+7:])
		if err2 == nil {
			return b, nil
		}
	}
	return nil, err
}
