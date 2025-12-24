package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func DefaultScreenshotDestURL(sessionID string) (string, error) {
	base := filepath.Join(os.TempDir(), "mcp-toolbox", "browser", "screenshots")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	safeSession := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(strings.TrimSpace(sessionID))
	if safeSession == "" {
		safeSession = "session"
	}
	name := fmt.Sprintf("%s_%s.png", safeSession, time.Now().UTC().Format("20060102T150405.000Z"))
	return "file://" + filepath.ToSlash(filepath.Join(base, name)), nil
}
