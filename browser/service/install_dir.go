package service

import (
	"os"
	"path/filepath"
	"strings"
)

const preferredInstallDir = "/opt/local/webdriver"

func defaultInstallDir(explicit string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit
	}

	homeBased := "."
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		homeBased = filepath.Join(home, ".mcp-toolbox", "browser", "webdriver")
	}

	// Prefer /opt/local/webdriver only if it already contains driver binaries.
	// This avoids defaulting to a potentially non-writable system folder.
	if dirHasDriver(preferredInstallDir) {
		return preferredInstallDir
	}
	return homeBased
}

func dirHasDriver(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	for _, name := range []string{ChromeDriver, GeckoDriver} {
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}
