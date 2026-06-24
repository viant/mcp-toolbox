//go:build darwin

package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/keybase/go-keychain"
)

func purgePersistentTokenCache(_ context.Context, name string) error {
	var joined error
	for _, cacheName := range []string{name, name + ".cae"} {
		err := keychain.DeleteGenericPasswordItem(cacheName, "MSALCache")
		if errors.Is(err, keychain.ErrorItemNotFound) || errors.Is(err, keychain.ErrorNoSuchKeychain) {
			err = nil
		}
		joined = errors.Join(joined, err, removePersistentCacheFile(cacheName))
	}
	return joined
}

func removePersistentCacheFile(name string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(home, ".IdentityService", name))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
