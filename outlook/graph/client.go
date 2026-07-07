package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bytes"
	"io"
	"sort"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azcache "github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/viant/afs"
	nsprov "github.com/viant/mcp/server/namespace"
)

// Manager provides Microsoft Graph client instances per account alias.
type Manager struct {
	clientID   string
	storageDir string
	ns         *nsprov.DefaultProvider
	// clients caches GraphServiceClient instances per alias+tenant+scopes.
	mu      sync.RWMutex
	clients map[string]*msgraphsdk.GraphServiceClient
	// creds caches device code credentials per namespace+alias+tenant+scopes.
	creds map[string]*azidentity.DeviceCodeCredential
	// inflight credential acquisitions per namespace+alias+tenant+scopes to serialize device flows.
	waiters map[string][]chan struct{}
	// persistentCache is the optional cross-process MSAL token cache.
	cacheOnce       sync.Once
	persistentCache azidentity.Cache
	cacheErr        error
}

const silentTokenTimeout = 10 * time.Second

func NewManager(clientID, storageDir string) *Manager {
	return &Manager{
		clientID:   clientID,
		storageDir: storageDir,
		ns:         nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}}),
		clients:    map[string]*msgraphsdk.GraphServiceClient{},
		creds:      map[string]*azidentity.DeviceCodeCredential{},
		waiters:    map[string][]chan struct{}{},
	}
}

func (m *Manager) authRecordPath(ns, alias string) string {
	return filepath.Join(m.storageDir, fmt.Sprintf("%s_%s_auth_record.json", safePart(ns), safePart(alias)))
}

// authRecordURL returns a storage URL for the auth record. Supports mem:// and file paths.
func (m *Manager) authRecordURL(ns, alias string) string {
	base := strings.TrimRight(os.ExpandEnv(m.storageDir), "/")
	name := fmt.Sprintf("%s_%s_auth_record.json", safePart(ns), safePart(alias))
	if strings.HasPrefix(base, "mem://") || strings.HasPrefix(base, "file://") {
		return base + "/" + name
	}
	return filepath.Join(base, name)
}

func safePart(s string) string {
	s = strings.TrimSpace(os.ExpandEnv(s))
	// Replace characters unsafe for filenames or caches
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "|", "_", " ", "_", "@", "_")
	return repl.Replace(s)
}

func (m *Manager) persistentCacheName() string {
	clientID := safePart(m.clientID)
	if clientID == "" {
		clientID = "default"
	}
	return "mcp-toolbox-outlook-" + clientID
}

func (m *Manager) tokenCache() (azidentity.Cache, bool) {
	m.cacheOnce.Do(func() {
		m.persistentCache, m.cacheErr = azcache.New(&azcache.Options{Name: m.persistentCacheName()})
	})
	return m.persistentCache, m.cacheErr == nil
}

func (m *Manager) applyTokenCache(opts *azidentity.DeviceCodeCredentialOptions) {
	if c, ok := m.tokenCache(); ok {
		opts.Cache = c
	}
}

func (m *Manager) ensureDirs() error {
	m.storageDir = expandPath(m.storageDir)
	if m.storageDir == "" {
		return errors.New("storageDir is required")
	}
	// Use AFS to ensure storage directory exists; no file:// scheme required
	base := expandPath(m.storageDir)
	if base == "" {
		return errors.New("storageDir is required")
	}
	return afs.New().Create(context.Background(), base, 0o700, true)
}

func expandPath(p string) string {
	if p == "" {
		return p
	}
	// expand $HOME and other env vars
	p = os.ExpandEnv(p)
	// expand ~ and ~/ to home dir
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				p = home
			} else if strings.HasPrefix(p, "~/") {
				p = filepath.Join(home, p[2:])
			}
		}
	}
	return p
}

// NeedsInteractive checks quickly (non-interactive) whether a device flow is required.
func (m *Manager) NeedsInteractive(ctx context.Context, alias, tenantID string, scopes []string) bool {
	start := time.Now()
	debugf("graph.NeedsInteractive start alias=%q tenant=%q deadline_in=%s", alias, tenantID, debugDeadline(ctx))
	if err := m.ensureDirs(); err != nil {
		debugf("graph.NeedsInteractive ensureDirs_error alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return true
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	debugf("graph.NeedsInteractive namespace ns=%q alias=%q tenant=%q kind=%q isDefault=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, dsc.Kind, dsc.IsDefault, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	// Load record if present
	// afs-only I/O: use recURL; skip local path
	recURL := m.authRecordURL(ns, alias)
	var rec azidentity.AuthenticationRecord
	haveRec := false
	var recordBytes int
	var openErr, readErr, unmarshalErr error
	recordStart := time.Now()
	if rc, err := afs.New().OpenURL(ctx, recURL); err == nil && rc != nil {
		if data, rerr := io.ReadAll(rc); rerr == nil {
			recordBytes = len(data)
			unmarshalErr = json.Unmarshal(data, &rec)
			haveRec = unmarshalErr == nil
		} else {
			readErr = rerr
		}
		_ = rc.Close()
	} else {
		openErr = err
	}
	debugf("graph.NeedsInteractive auth_record ns=%q alias=%q tenant=%q haveRec=%v bytes=%d openErr=%v readErr=%v unmarshalErr=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, haveRec, recordBytes, openErr, readErr, unmarshalErr, time.Since(recordStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	if !haveRec {
		debugf("graph.NeedsInteractive result ns=%q alias=%q tenant=%q needsInteractive=true reason=no_auth_record total=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return true
	}
	// removed log.Printf diagnostics
	credStart := time.Now()
	opts := &azidentity.DeviceCodeCredentialOptions{
		TenantID:   tenantID,
		ClientID:   m.clientID,
		UserPrompt: func(context.Context, azidentity.DeviceCodeMessage) error { return nil },
	}
	opts.AuthenticationRecord = rec
	m.applyTokenCache(opts)
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		debugf("graph.NeedsInteractive new_credential_error ns=%q alias=%q tenant=%q err=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(credStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return true
	}
	debugf("graph.NeedsInteractive credential_ok ns=%q alias=%q tenant=%q elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, time.Since(credStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	ctx2, cancel := context.WithTimeout(ctx, silentTokenTimeout)
	defer cancel()
	tokenStart := time.Now()
	_, err = cred.GetToken(ctx2, policy.TokenRequestOptions{Scopes: scopes})
	need := err != nil
	debugf("graph.NeedsInteractive silent_token ns=%q alias=%q tenant=%q needsInteractive=%v err=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, need, err, time.Since(tokenStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	// removed log.Printf diagnostics
	debugf("graph.NeedsInteractive result ns=%q alias=%q tenant=%q needsInteractive=%v total=%s deadline_in=%s", ns, alias, tenantID, need, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return need
}

// Client returns a ready-to-use GraphServiceClient with given scopes.
func (m *Manager) Client(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*msgraphsdk.GraphServiceClient, error) {
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	key := m.clientKey(ns, alias, tenantID, scopes)
	cred, err := m.Credential(ctx, alias, tenantID, scopes, prompt)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	if cli, ok := m.clients[key]; ok {
		m.mu.RUnlock()
		return cli, nil
	}
	m.mu.RUnlock()

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, scopes)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	// Double-check in case another goroutine created it meanwhile.
	if existing, ok := m.clients[key]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	m.clients[key] = client
	m.mu.Unlock()
	// removed log.Printf diagnostics
	return client, nil
}

// Acquire performs authentication only (useful to trigger device-code flow explicitly).
func (m *Manager) Acquire(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) error {
	_, _, err := m.acquireCredential(ctx, alias, tenantID, scopes, prompt)
	return err
}

// HasAuthRecord reports whether an auth record exists for alias.
func (m *Manager) HasAuthRecord(ctx context.Context, alias string) bool {
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	recURL := m.authRecordURL(ns, alias)
	ok, _ := afs.New().Exists(ctx, recURL)
	return ok
}

// ResetAuth clears local authentication state for an alias in the current namespace.
func (m *Manager) ResetAuth(ctx context.Context, alias, tenantID string, scopes []string, purgePersistent bool) (ResetResult, error) {
	if err := m.ensureDirs(); err != nil {
		return ResetResult{}, err
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	result := ResetResult{PersistentCacheName: m.persistentCacheName()}

	m.mu.Lock()
	credPrefix := m.cacheKeyPrefix(ns, alias, tenantID)
	for key := range m.creds {
		if strings.HasPrefix(key, credPrefix) {
			delete(m.creds, key)
			result.ClearedMemory = true
		}
	}
	for key := range m.clients {
		if strings.HasPrefix(key, credPrefix) {
			delete(m.clients, key)
			result.ClearedMemory = true
		}
	}
	for key, waiters := range m.waiters {
		if strings.HasPrefix(key, credPrefix) {
			delete(m.waiters, key)
			for _, ch := range waiters {
				close(ch)
			}
		}
	}
	m.mu.Unlock()

	recURL := m.authRecordURL(ns, alias)
	exists, _ := afs.New().Exists(ctx, recURL)
	if exists {
		if err := afs.New().Delete(ctx, recURL); err != nil {
			return result, err
		}
		result.ClearedAuthRecord = true
	}
	if purgePersistent {
		if err := purgePersistentTokenCache(ctx, result.PersistentCacheName); err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		} else {
			result.PurgedPersistentCache = true
		}
	}
	return result, nil
}

// acquireCredential performs Device Code flow. If an auth record exists, use it for silent login.
func (m *Manager) acquireCredential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, azidentity.AuthenticationRecord, error) {
	start := time.Now()
	if err := m.ensureDirs(); err != nil {
		debugf("graph.acquireCredential ensureDirs_error alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return nil, azidentity.AuthenticationRecord{}, err
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	debugf("graph.acquireCredential start ns=%q alias=%q tenant=%q deadline_in=%s", ns, alias, tenantID, debugDeadline(ctx))
	// afs-only I/O: use recURL; skip local path
	var rec azidentity.AuthenticationRecord
	haveRec := false
	var recordBytes int
	var openErr, readErr, unmarshalErr error
	recordStart := time.Now()
	if rc, err := afs.New().OpenURL(ctx, m.authRecordURL(ns, alias)); err == nil && rc != nil {
		if data, rerr := io.ReadAll(rc); rerr == nil {
			recordBytes = len(data)
			unmarshalErr = json.Unmarshal(data, &rec)
			haveRec = unmarshalErr == nil
		} else {
			readErr = rerr
		}
		_ = rc.Close()
	} else {
		openErr = err
	}
	debugf("graph.acquireCredential auth_record ns=%q alias=%q tenant=%q haveRec=%v bytes=%d openErr=%v readErr=%v unmarshalErr=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, haveRec, recordBytes, openErr, readErr, unmarshalErr, time.Since(recordStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))

	// Persist tokens via azidentity/cache (Keychain on macOS).
	// Always provide a prompt callback (to avoid SDK printing to stdout and
	// to surface the device code message via our UI when interaction is needed).
	var userPrompt = func(_ context.Context, m azidentity.DeviceCodeMessage) error {
		if prompt != nil {
			prompt(m.Message)
		}
		return nil
	}
	opts := &azidentity.DeviceCodeCredentialOptions{
		TenantID:   tenantID,
		ClientID:   m.clientID,
		UserPrompt: userPrompt,
	}
	if haveRec {
		opts.AuthenticationRecord = rec
	}
	m.applyTokenCache(opts)
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		debugf("graph.acquireCredential new_credential_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return nil, azidentity.AuthenticationRecord{}, err
	}

	if haveRec {
		// Try a quick silent token preflight. If it fails, fall back to interactive flow
		// (this will invoke the prompt with a device code), then persist a fresh record.
		tctx, cancel := context.WithTimeout(ctx, silentTokenTimeout)
		_, preErr := cred.GetToken(tctx, policy.TokenRequestOptions{Scopes: scopes})
		cancel()
		debugf("graph.acquireCredential silent_preflight ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, preErr, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		if preErr != nil {
			rec, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
			if err != nil {
				debugf("graph.acquireCredential authenticate_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
				return nil, azidentity.AuthenticationRecord{}, err
			}
			if b, err := json.Marshal(rec); err == nil {
				recURL := m.authRecordURL(ns, alias)
				_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
				// removed log.Printf diagnostics
			}
			debugf("graph.acquireCredential authenticate_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		}
	} else {
		// No record: perform interactive device login and persist record.
		rec, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
		if err != nil {
			debugf("graph.acquireCredential authenticate_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return nil, azidentity.AuthenticationRecord{}, err
		}
		if b, err := json.Marshal(rec); err == nil {
			recURL := m.authRecordURL(ns, alias)
			_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
			// removed log.Printf diagnostics
		}
		debugf("graph.acquireCredential authenticate_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	}
	debugf("graph.acquireCredential done ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return cred, rec, nil
}

func outlookDebug() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OUTLOOK_MCP_DEBUG")))
	return v != "" && v != "0" && v != "false"
}

// DefaultScopes returns the minimal set for email, calendar, tasks with offline access.
func DefaultScopes() []string {
	return []string{
		"https://graph.microsoft.com/.default",
	}
}

// Convenience helpers
func isoNowPlus(days int) (start string, end string) {
	now := time.Now().UTC()
	start = now.Format(time.RFC3339)
	end = now.Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	return
}

// clientKey builds a stable cache key from alias, tenantID, and normalized scopes.
func (m *Manager) clientKey(ns, alias, tenantID string, scopes []string) string {
	// normalize scopes: lowercase and sort
	if len(scopes) > 0 {
		norm := make([]string, 0, len(scopes))
		for _, s := range scopes {
			if s == "" {
				continue
			}
			norm = append(norm, strings.ToLower(s))
		}
		sort.Strings(norm)
		scopes = norm
	}
	if ns == "" {
		ns = "default"
	}
	return ns + "|" + alias + "|" + tenantID + "|" + strings.Join(scopes, ",")
}

func (m *Manager) cacheKeyPrefix(ns, alias, tenantID string) string {
	if ns == "" {
		ns = "default"
	}
	return ns + "|" + alias + "|" + tenantID + "|"
}

func (m *Manager) cachedCredential(ctx context.Context, key string, scopes []string) (*azidentity.DeviceCodeCredential, bool) {
	m.mu.RLock()
	cred := m.creds[key]
	m.mu.RUnlock()
	if cred == nil {
		return nil, false
	}
	if m.credentialUsable(ctx, cred, scopes) {
		return cred, true
	}
	m.dropCredential(key, cred)
	return nil, false
}

func (m *Manager) credentialUsable(ctx context.Context, cred *azidentity.DeviceCodeCredential, scopes []string) bool {
	start := time.Now()
	if cred == nil {
		debugf("graph.credentialUsable result ok=false reason=nil_credential elapsed=%s deadline_in=%s", time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return false
	}
	tctx, cancel := context.WithTimeout(ctx, silentTokenTimeout)
	defer cancel()
	_, err := cred.GetToken(tctx, policy.TokenRequestOptions{Scopes: scopes})
	ok := err == nil
	debugf("graph.credentialUsable result ok=%v err=%v elapsed=%s deadline_in=%s", ok, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return ok
}

func (m *Manager) dropCredential(key string, cred *azidentity.DeviceCodeCredential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds[key] == cred {
		delete(m.creds, key)
		delete(m.clients, key)
	}
}

// Credential returns a cached DeviceCodeCredential for alias, acquiring and caching if needed.
func (m *Manager) Credential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, error) {
	start := time.Now()
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	key := m.clientKey(ns, alias, tenantID, scopes)
	debugf("graph.Credential start ns=%q alias=%q tenant=%q deadline_in=%s", ns, alias, tenantID, debugDeadline(ctx))
	if c, ok := m.cachedCredential(ctx, key, scopes); ok {
		debugf("graph.Credential cache_hit ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return c, nil
	}
	debugf("graph.Credential cache_miss ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	// Inflight coordination
	m.mu.Lock()
	if c := m.creds[key]; c != nil {
		m.mu.Unlock()
		if m.credentialUsable(ctx, c, scopes) {
			debugf("graph.Credential cache_hit_after_lock ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return c, nil
		}
		debugf("graph.Credential drop_unusable ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		m.dropCredential(key, c)
		m.mu.Lock()
	}
	if lst, ok := m.waiters[key]; ok {
		ch := make(chan struct{})
		m.waiters[key] = append(lst, ch)
		m.mu.Unlock()
		debugf("graph.Credential wait_inflight ns=%q alias=%q tenant=%q waiters=%d elapsed=%s deadline_in=%s", ns, alias, tenantID, len(lst)+1, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		select {
		case <-ctx.Done():
			debugf("graph.Credential wait_inflight_context_done ns=%q alias=%q tenant=%q err=%v elapsed=%s", ns, alias, tenantID, ctx.Err(), time.Since(start).Round(time.Millisecond))
			return nil, ctx.Err()
		case <-ch:
		}
		m.mu.RLock()
		c := m.creds[key]
		m.mu.RUnlock()
		if c == nil {
			debugf("graph.Credential wait_inflight_no_credential ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return nil, errors.New("credential acquisition failed")
		}
		if !m.credentialUsable(ctx, c, scopes) {
			m.dropCredential(key, c)
			debugf("graph.Credential wait_inflight_unusable ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return nil, errors.New("credential acquisition failed")
		}
		debugf("graph.Credential wait_inflight_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return c, nil
	}
	// Mark inflight
	m.waiters[key] = []chan struct{}{}
	m.mu.Unlock()
	debugf("graph.Credential acquire_start ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	cred, _, err := m.acquireCredential(ctx, alias, tenantID, scopes, prompt)
	// Publish result and wake waiters
	m.mu.Lock()
	if existing := m.creds[key]; existing != nil {
		cred = existing
	} else if err == nil {
		m.creds[key] = cred
	}
	lst := m.waiters[key]
	delete(m.waiters, key)
	m.mu.Unlock()
	for _, ch := range lst {
		close(ch)
	}
	if err != nil {
		debugf("graph.Credential acquire_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return nil, err
	}
	debugf("graph.Credential acquire_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return cred, nil
}
