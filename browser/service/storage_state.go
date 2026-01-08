package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tebeka/selenium"
)

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Expiry   uint   `json:"expiry,omitempty"` // unix seconds (selenium.Cookie uses uint)
}

type StorageState struct {
	Cookies        []Cookie          `json:"cookies,omitempty"`
	LocalStorage   map[string]string `json:"localStorage,omitempty"`
	SessionStorage map[string]string `json:"sessionStorage,omitempty"`
}

type StorageSaveInput struct {
	SessionID            string `json:"sessionID,omitempty"`
	DestURL              string `json:"destURL,omitempty"`
	IncludeLocalStorage  bool   `json:"includeLocalStorage,omitempty"`
	IncludeSessionStorage bool  `json:"includeSessionStorage,omitempty"`
}

type StorageSaveOutput struct {
	SessionID string `json:"sessionID,omitempty"`
	DestURL   string `json:"destURL,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
}

type StorageLoadInput struct {
	SessionID string `json:"sessionID,omitempty"`
	SourceURL string `json:"sourceURL,omitempty"`
	// URL optionally navigates before applying cookies/storage (recommended to match cookie domain).
	URL string `json:"url,omitempty"`
}

type StorageLoadOutput struct {
	SessionID string `json:"sessionID,omitempty"`
	Cookies   int    `json:"cookies,omitempty"`
}

func (s *Service) StorageSave(ctx context.Context, in *StorageSaveInput) (*StorageSaveOutput, error) {
	if in == nil {
		in = &StorageSaveInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	if strings.TrimSpace(in.DestURL) == "" {
		return nil, fmt.Errorf("destURL is required")
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}

	state := &StorageState{}

	sess.lock.Lock()
	defer sess.lock.Unlock()

	// Cookies
	cookies, err := sess.driver.GetCookies()
	if err != nil {
		return nil, err
	}
	state.Cookies = make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		out := Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			Expiry:   c.Expiry,
		}
		state.Cookies = append(state.Cookies, out)
	}

	// Storage (best-effort; may fail on some pages/contexts)
	if in.IncludeLocalStorage {
		if m, ok := s.readStorageMap(sess, "localStorage"); ok {
			state.LocalStorage = m
		}
	}
	if in.IncludeSessionStorage {
		if m, ok := s.readStorageMap(sess, "sessionStorage"); ok {
			state.SessionStorage = m
		}
	}

	b, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader(b)); err != nil {
		return nil, err
	}
	return &StorageSaveOutput{SessionID: in.SessionID, DestURL: in.DestURL, Bytes: len(b)}, nil
}

func (s *Service) StorageLoad(ctx context.Context, in *StorageLoadInput) (*StorageLoadOutput, error) {
	if in == nil {
		in = &StorageLoadInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	if strings.TrimSpace(in.SourceURL) == "" {
		return nil, fmt.Errorf("sourceURL is required")
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}

	r, err := s.fs.OpenURL(ctx, in.SourceURL)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var state StorageState
	if err := json.NewDecoder(r).Decode(&state); err != nil {
		return nil, err
	}

	sess.lock.Lock()
	defer sess.lock.Unlock()

	// Navigate first (recommended so cookie domain matches), when requested.
	if strings.TrimSpace(in.URL) != "" {
		if err := sess.driver.Get(strings.TrimSpace(in.URL)); err != nil && !isPageLoadTimeout(err) {
			return nil, err
		}
	}

	// Cookies must be set after navigating to a compatible domain.
	setCookies := 0
	for _, c := range state.Cookies {
		if strings.TrimSpace(c.Name) == "" {
			continue
		}
		if err := sess.driver.AddCookie(&selenium.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			Expiry:   c.Expiry,
		}); err == nil {
			setCookies++
		}
	}

	// Apply storage maps (best-effort).
	if len(state.LocalStorage) > 0 {
		_, _ = sess.driver.ExecuteScript(storageSetScript("localStorage"), []any{state.LocalStorage})
	}
	if len(state.SessionStorage) > 0 {
		_, _ = sess.driver.ExecuteScript(storageSetScript("sessionStorage"), []any{state.SessionStorage})
	}

	return &StorageLoadOutput{SessionID: in.SessionID, Cookies: setCookies}, nil
}

func (s *Service) readStorageMap(sess *Session, storageName string) (map[string]string, bool) {
	if sess == nil || sess.driver == nil {
		return nil, false
	}
	v, err := sess.driver.ExecuteScript(storageReadScript(storageName), nil)
	if err != nil || v == nil {
		return nil, false
	}
	// Returned as map[string]any from JSON.parse -> decoded by selenium into map[string]any
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]any:
		for k, val := range m {
			out[k] = fmt.Sprintf("%v", val)
		}
		return out, true
	default:
		return nil, false
	}
}

func storageReadScript(name string) string {
	return fmt.Sprintf(`(function(){
		try {
			var s = window.%s;
			if (!s) return {};
			var out = {};
			for (var i = 0; i < s.length; i++) {
				var k = s.key(i);
				out[k] = s.getItem(k);
			}
			return out;
		} catch (e) { return {}; }
	})();`, name)
}

func storageSetScript(name string) string {
	return fmt.Sprintf(`(function(items){
		try {
			var s = window.%s;
			if (!s || !items) return true;
			for (var k in items) {
				if (Object.prototype.hasOwnProperty.call(items, k)) {
					s.setItem(k, String(items[k]));
				}
			}
			return true;
		} catch (e) { return false; }
	})(arguments[0]);`, name)
}
