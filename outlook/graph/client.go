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
	oaauth "github.com/viant/mcp-toolbox/auth"
	nsprov "github.com/viant/mcp/server/namespace"
)

// Manager provides Microsoft Graph client instances per account alias.
type Manager struct {
	clientID   string
	storageDir string
	auth       *oaauth.Service
	ns         *nsprov.DefaultProvider
	// pending holds device-code prompts keyed by account alias.
	pending map[string]*pendingAuth
	// clients caches GraphServiceClient instances per alias+tenant+scopes.
	mu      sync.RWMutex
	clients map[string]*msgraphsdk.GraphServiceClient
	// creds caches device code credentials per alias, kept in memory until process restarts.
	creds map[string]*azidentity.DeviceCodeCredential
	// inflight credential acquisitions per ns|alias to serialize device flows
	waiters map[string][]chan struct{}
	// persistentCache is the optional cross-process MSAL token cache.
	cacheOnce       sync.Once
	persistentCache azidentity.Cache
	cacheErr        error
}

type pendingAuth struct{ message string }

const silentTokenTimeout = 10 * time.Second

func NewManager(clientID, storageDir string) *Manager {
	return &Manager{
		clientID:   clientID,
		storageDir: storageDir,
		auth:       oaauth.New(),
		ns:         nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}}),
		pending:    map[string]*pendingAuth{},
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
	if err := m.ensureDirs(); err != nil {
		return true
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	// Load record if present
	// afs-only I/O: use recURL; skip local path
	recURL := m.authRecordURL(ns, alias)
	var rec azidentity.AuthenticationRecord
	haveRec := false
	if rc, err := afs.New().OpenURL(ctx, recURL); err == nil && rc != nil {
		if data, rerr := io.ReadAll(rc); rerr == nil {
			haveRec = json.Unmarshal(data, &rec) == nil
		}
		_ = rc.Close()
	}
	if !haveRec {
		return true
	}
	// removed log.Printf diagnostics
	opts := &azidentity.DeviceCodeCredentialOptions{
		TenantID:   tenantID,
		ClientID:   m.clientID,
		UserPrompt: func(context.Context, azidentity.DeviceCodeMessage) error { return nil },
	}
	opts.AuthenticationRecord = rec
	m.applyTokenCache(opts)
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		return true
	}
	ctx2, cancel := context.WithTimeout(ctx, silentTokenTimeout)
	defer cancel()
	_, err = cred.GetToken(ctx2, policy.TokenRequestOptions{Scopes: scopes})
	need := err != nil
	// removed log.Printf diagnostics
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
	// removed log.Printf diagnostics
	m.mu.RLock()
	if cli, ok := m.clients[key]; ok {
		m.mu.RUnlock()
		// removed log.Printf diagnostics
		return cli, nil
	}
	m.mu.RUnlock()

	// Reuse in-memory credential per alias; acquire and cache if absent.
	m.mu.RLock()
	cred := m.creds[ns+"|"+alias]
	m.mu.RUnlock()
	if cred == nil {
		var rec azidentity.AuthenticationRecord
		var err error
		cred, rec, err = m.acquireCredential(ctx, alias, tenantID, scopes, prompt)
		if err != nil {
			return nil, err
		}
		_ = rec // reserved, if needed later
		m.mu.Lock()
		m.creds[ns+"|"+alias] = cred
		m.mu.Unlock()
		// removed log.Printf diagnostics
	}
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
	credKey := ns + "|" + alias
	if _, ok := m.creds[credKey]; ok {
		result.ClearedMemory = true
	}
	delete(m.creds, credKey)
	for key := range m.clients {
		parts := strings.SplitN(key, "|", 4)
		if len(parts) >= 2 && parts[0] == ns && parts[1] == alias {
			delete(m.clients, key)
			result.ClearedMemory = true
		}
	}
	for key, waiters := range m.waiters {
		parts := strings.SplitN(key, "|", 3)
		if len(parts) >= 2 && parts[0] == ns && parts[1] == alias {
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

// StartDeviceLogin launches the device code authentication in background.
// It stores the prompt message to be retrievable via DevicePrompt.
func (m *Manager) StartDeviceLogin(ctx context.Context, alias, tenantID string, scopes []string, onComplete func(error)) {
	m.mu.Lock()
	if _, ok := m.pending[alias]; ok {
		m.mu.Unlock()
		return
	}
	holder := &pendingAuth{}
	m.pending[alias] = holder
	m.mu.Unlock()
	go func() {
		prompt := func(msg string) {
			m.mu.Lock()
			holder.message = msg
			m.mu.Unlock()
		}
		_, err := m.Credential(ctx, alias, tenantID, scopes, prompt)
		if onComplete != nil {
			onComplete(err)
		}
		m.mu.Lock()
		delete(m.pending, alias)
		m.mu.Unlock()
	}()
}

// acquireCredential performs Device Code flow. If an auth record exists, use it for silent login.
func (m *Manager) acquireCredential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, azidentity.AuthenticationRecord, error) {
	if err := m.ensureDirs(); err != nil {
		return nil, azidentity.AuthenticationRecord{}, err
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	// afs-only I/O: use recURL; skip local path
	var rec azidentity.AuthenticationRecord
	haveRec := false
	if rc, err := afs.New().OpenURL(ctx, m.authRecordURL(ns, alias)); err == nil && rc != nil {
		if data, rerr := io.ReadAll(rc); rerr == nil {
			_ = json.Unmarshal(data, &rec)
			haveRec = true
		}
		_ = rc.Close()
	}

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
		return nil, azidentity.AuthenticationRecord{}, err
	}

	if haveRec {
		// Try a quick silent token preflight. If it fails, fall back to interactive flow
		// (this will invoke the prompt with a device code), then persist a fresh record.
		tctx, cancel := context.WithTimeout(ctx, silentTokenTimeout)
		_, preErr := cred.GetToken(tctx, policy.TokenRequestOptions{Scopes: scopes})
		cancel()
		if preErr != nil {
			rec, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
			if err != nil {
				return nil, azidentity.AuthenticationRecord{}, err
			}
			if b, err := json.Marshal(rec); err == nil {
				recURL := m.authRecordURL(ns, alias)
				_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
				// removed log.Printf diagnostics
			}
		}
	} else {
		// No record: perform interactive device login and persist record.
		rec, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
		if err != nil {
			return nil, azidentity.AuthenticationRecord{}, err
		}
		if b, err := json.Marshal(rec); err == nil {
			recURL := m.authRecordURL(ns, alias)
			_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
			// removed log.Printf diagnostics
		}
	}
	return cred, rec, nil
}

func outlookDebug() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OUTLOOK_MCP_DEBUG")))
	return v != "" && v != "0" && v != "false"
}

// DevicePrompt returns the last device-code prompt message for alias.
func (m *Manager) DevicePrompt(alias string) string {
	m.mu.RLock()
	p, ok := m.pending[alias]
	msg := ""
	if ok && p != nil {
		msg = p.message
	}
	m.mu.RUnlock()
	return msg
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

// Credential returns a cached DeviceCodeCredential for alias, acquiring and caching if needed.
func (m *Manager) Credential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, error) {
	ns, _ := m.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	key := ns + "|" + alias
	// Fast path: cached
	m.mu.RLock()
	if c := m.creds[key]; c != nil {
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()
	// Inflight coordination
	m.mu.Lock()
	if c := m.creds[key]; c != nil {
		m.mu.Unlock()
		return c, nil
	}
	if lst, ok := m.waiters[key]; ok {
		ch := make(chan struct{})
		m.waiters[key] = append(lst, ch)
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch:
		}
		m.mu.RLock()
		c := m.creds[key]
		m.mu.RUnlock()
		if c == nil {
			return nil, errors.New("credential acquisition failed")
		}
		return c, nil
	}
	// Mark inflight
	m.waiters[key] = []chan struct{}{}
	m.mu.Unlock()
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
		return nil, err
	}
	return cred, nil
}
