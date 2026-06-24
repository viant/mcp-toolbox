//go:build linux || windows

package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func purgePersistentTokenCache(_ context.Context, name string) error {
	base, err := persistentCacheBaseDir()
	if err != nil {
		return err
	}
	var joined error
	for _, cacheName := range []string{name, name + ".cae"} {
		err := os.Remove(filepath.Join(base, ".IdentityService", cacheName))
		if err == nil || errors.Is(err, os.ErrNotExist) {
			continue
		}
		joined = errors.Join(joined, err)
	}
	return joined
}

func persistentCacheBaseDir() (string, error) {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return dir, nil
		}
	}
	return os.UserHomeDir()
}
