package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func DefaultScreenshotDestURL() (string, error) {
	base := filepath.Join(os.TempDir(), "mcp-toolbox", "desktop", "screenshots")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("desktop_%s.png", time.Now().UTC().Format("20060102T150405.000Z"))
	return "file://" + filepath.ToSlash(filepath.Join(base, name)), nil
}
