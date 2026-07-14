package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bytes"
	"io"
	"net/http"
	"sort"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azcache "github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/viant/afs"
	nsprov "github.com/viant/mcp/server/namespace"
)

// Manager provides Microsoft Graph client instances per account alias.
type Manager struct {
	clientID                 string
	storageDir               string
	ns                       nsprov.Provider
	requireIdentityNamespace bool
	authFlow                 AuthFlow
	authority                string

	oauthRedirectURL      string
	oauthScopes           []string
	oauthHTTPClient       *http.Client
	oauthAuthURLOverride  string
	oauthTokenURLOverride string

	// clients caches GraphServiceClient instances per alias+tenant+scopes.
	mu      sync.RWMutex
	clients map[string]*msgraphsdk.GraphServiceClient
	// creds caches Graph token credentials per namespace+alias+tenant+scopes.
	creds map[string]azcore.TokenCredential
	// inflight credential acquisitions per namespace+alias+tenant+scopes to serialize device flows.
	waiters map[string][]chan struct{}
	// persistentCache is the optional cross-process MSAL token cache.
	cacheOnce       sync.Once
	persistentCache azidentity.Cache
	cacheErr        error
}

const silentTokenTimeout = 10 * time.Second

const (
	IdentityNamespaceRequiredReason  = "identity_namespace_required"
	IdentityNamespaceRequiredMessage = "Unauthorized: identity namespace is required"
)

var ErrIdentityNamespaceRequired = errors.New(IdentityNamespaceRequiredMessage)

type AuthCheckStatus string

const (
	AuthCheckReady            AuthCheckStatus = "ready"
	AuthCheckNeedsInteractive AuthCheckStatus = "needs_interactive"
	AuthCheckTransient        AuthCheckStatus = "transient"
	AuthCheckFailed           AuthCheckStatus = "failed"
)

const TransientAuthProviderMessage = "Outlook authentication provider is temporarily unavailable; retry later. Existing Outlook auth was not reset and re-authentication is not required."

type AuthCheckResult struct {
	Status AuthCheckStatus
	Reason string
	Err    error
}

type AuthProviderError struct {
	Transient bool
	Message   string
	Err       error
}

func (e *AuthProviderError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "Outlook authentication failed"
}

func (e *AuthProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewTransientAuthProviderError(err error) error {
	return &AuthProviderError{Transient: true, Message: TransientAuthProviderMessage, Err: err}
}

func UserMessageForAuthError(err error) string {
	if err == nil {
		return ""
	}
	if IsTransientAuthProviderError(err) {
		return TransientAuthProviderMessage
	}
	return err.Error()
}

func IsTransientAuthProviderError(err error) bool {
	if err == nil {
		return false
	}
	var authErr *AuthProviderError
	if errors.As(err, &authErr) && authErr.Transient {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) && IsTransientAuthProviderError(urlErr.Err) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"unable to resolve an endpoint",
		"context deadline exceeded",
		"i/o timeout",
		"no such host",
		"server misbehaving",
		"tls handshake timeout",
		"temporary failure",
		"connection refused",
		"connection reset",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func NewManager(clientID, storageDir string) *Manager {
	return newManager(clientID, storageDir, nil)
}

func NewManagerWithNamespaceClaimKeys(clientID, storageDir string, namespaceClaimKeys []string) *Manager {
	return newManager(clientID, storageDir, normalizeNamespaceClaimKeys(namespaceClaimKeys))
}

func newManager(clientID, storageDir string, claimKeys []string) *Manager {
	return NewManagerWithConfig(&ManagerConfig{
		ClientID:           clientID,
		StorageDir:         storageDir,
		NamespaceClaimKeys: claimKeys,
		AuthFlow:           AuthFlowDevice,
	})
}

func NewManagerWithConfig(cfg *ManagerConfig) *Manager {
	if cfg == nil {
		cfg = &ManagerConfig{}
	}
	claimKeys := normalizeNamespaceClaimKeys(cfg.NamespaceClaimKeys)
	authFlow := NormalizeAuthFlow(string(cfg.AuthFlow))
	namespaceProvider := cfg.NamespaceProvider
	if namespaceProvider == nil {
		namespaceProvider = nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, ClaimKeys: claimKeys, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}})
	}
	return &Manager{
		clientID:                 cfg.ClientID,
		storageDir:               cfg.StorageDir,
		ns:                       namespaceProvider,
		requireIdentityNamespace: cfg.RequireIdentityNamespace,
		authFlow:                 authFlow,
		authority:                cfg.Authority,
		oauthRedirectURL:         cfg.OAuthRedirectURL,
		oauthScopes:              normalizeScopes(cfg.OAuthScopes),
		oauthHTTPClient:          cfg.OAuthHTTPClient,
		oauthAuthURLOverride:     cfg.OAuthAuthURLOverride,
		oauthTokenURLOverride:    cfg.OAuthTokenURLOverride,
		clients:                  map[string]*msgraphsdk.GraphServiceClient{},
		creds:                    map[string]azcore.TokenCredential{},
		waiters:                  map[string][]chan struct{}{},
	}
}

// ResolveIdentityNamespace resolves an unverified JWT identity namespace and
// rejects default, token-hash, malformed, and missing-claim results.
func ResolveIdentityNamespace(ctx context.Context, provider nsprov.Provider) (string, error) {
	if provider == nil {
		return "", ErrIdentityNamespaceRequired
	}
	descriptor, err := provider.Namespace(ctx)
	if err != nil {
		return "", ErrIdentityNamespaceRequired
	}
	return identityNamespaceFromDescriptor(descriptor)
}

func identityNamespaceFromDescriptor(descriptor nsprov.Descriptor) (string, error) {
	name := strings.TrimSpace(descriptor.Name)
	if descriptor.Kind != nsprov.KindIdentity || name == "" {
		return "", ErrIdentityNamespaceRequired
	}
	return name, nil
}

func (m *Manager) namespace(ctx context.Context) (string, error) {
	if m.requireIdentityNamespace {
		if descriptor, ok := nsprov.FromContext(ctx); ok {
			return identityNamespaceFromDescriptor(descriptor)
		}
		return ResolveIdentityNamespace(ctx, m.ns)
	}
	descriptor, _ := m.ns.Namespace(ctx)
	if name := strings.TrimSpace(descriptor.Name); name != "" {
		return name, nil
	}
	return "default", nil
}

func normalizeNamespaceClaimKeys(keys []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, key)
	}
	if len(result) == 0 {
		return nil
	}
	return result
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

type authRecordLoadResult struct {
	record       azidentity.AuthenticationRecord
	haveRecord   bool
	bytes        int
	openErr      error
	readErr      error
	unmarshalErr error
	elapsed      time.Duration
}

func (m *Manager) loadAuthRecord(ctx context.Context, ns, alias string) authRecordLoadResult {
	start := time.Now()
	var result authRecordLoadResult
	rc, err := afs.New().OpenURL(ctx, m.authRecordURL(ns, alias))
	if err != nil || rc == nil {
		result.openErr = err
		result.elapsed = time.Since(start)
		return result
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		result.readErr = err
		result.elapsed = time.Since(start)
		return result
	}
	result.bytes = len(data)
	result.unmarshalErr = json.Unmarshal(data, &result.record)
	result.haveRecord = result.unmarshalErr == nil
	result.elapsed = time.Since(start)
	return result
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

// AuthCheck checks whether a credential is usable, needs user sign-in, or failed for a provider/local reason.
func (m *Manager) AuthCheck(ctx context.Context, alias, tenantID string, scopes []string) AuthCheckResult {
	if m.authFlow == AuthFlowAuthCode {
		return m.oauthAuthCheck(ctx, alias, tenantID, scopes)
	}
	start := time.Now()
	debugf("graph.AuthCheck start alias=%q tenant=%q deadline_in=%s", alias, tenantID, debugDeadline(ctx))
	ns, err := m.namespace(ctx)
	if err != nil {
		debugf("graph.AuthCheck result alias=%q tenant=%q status=%q reason=%q", alias, tenantID, AuthCheckFailed, IdentityNamespaceRequiredReason)
		return AuthCheckResult{Status: AuthCheckFailed, Reason: IdentityNamespaceRequiredReason, Err: err}
	}
	if err := m.ensureDirs(); err != nil {
		debugf("graph.AuthCheck ensureDirs_error alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return AuthCheckResult{Status: AuthCheckFailed, Reason: "storage_unavailable", Err: err}
	}
	debugf("graph.AuthCheck namespace ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	record := m.loadAuthRecord(ctx, ns, alias)
	debugf("graph.AuthCheck auth_record ns=%q alias=%q tenant=%q haveRec=%v bytes=%d openErr=%v readErr=%v unmarshalErr=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, record.haveRecord, record.bytes, record.openErr, record.readErr, record.unmarshalErr, record.elapsed.Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	if !record.haveRecord {
		debugf("graph.AuthCheck result ns=%q alias=%q tenant=%q status=%q reason=no_auth_record total=%s deadline_in=%s", ns, alias, tenantID, AuthCheckNeedsInteractive, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return AuthCheckResult{Status: AuthCheckNeedsInteractive, Reason: "no_usable_auth_record"}
	}
	// removed log.Printf diagnostics
	credStart := time.Now()
	opts := &azidentity.DeviceCodeCredentialOptions{
		TenantID:   tenantID,
		ClientID:   m.clientID,
		UserPrompt: func(context.Context, azidentity.DeviceCodeMessage) error { return nil },
	}
	opts.AuthenticationRecord = record.record
	m.applyTokenCache(opts)
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		debugf("graph.AuthCheck new_credential_error ns=%q alias=%q tenant=%q err=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(credStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return AuthCheckResult{Status: AuthCheckFailed, Reason: "credential_init_failed", Err: err}
	}
	debugf("graph.AuthCheck credential_ok ns=%q alias=%q tenant=%q elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, time.Since(credStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	ctx2, cancel := context.WithTimeout(ctx, silentTokenTimeout)
	defer cancel()
	tokenStart := time.Now()
	_, err = cred.GetToken(ctx2, policy.TokenRequestOptions{Scopes: scopes})
	debugf("graph.AuthCheck silent_token ns=%q alias=%q tenant=%q err=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(tokenStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	if err == nil {
		debugf("graph.AuthCheck result ns=%q alias=%q tenant=%q status=%q total=%s deadline_in=%s", ns, alias, tenantID, AuthCheckReady, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return AuthCheckResult{Status: AuthCheckReady}
	}
	if IsTransientAuthProviderError(err) {
		debugf("graph.AuthCheck result ns=%q alias=%q tenant=%q status=%q reason=transient_provider err=%v total=%s deadline_in=%s", ns, alias, tenantID, AuthCheckTransient, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return AuthCheckResult{Status: AuthCheckTransient, Reason: "transient_provider", Err: NewTransientAuthProviderError(err)}
	}
	debugf("graph.AuthCheck result ns=%q alias=%q tenant=%q status=%q reason=silent_token_failed err=%v total=%s deadline_in=%s", ns, alias, tenantID, AuthCheckNeedsInteractive, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return AuthCheckResult{Status: AuthCheckNeedsInteractive, Reason: "silent_token_failed", Err: err}
}

// NeedsInteractive checks quickly (non-interactive) whether a device flow is required.
func (m *Manager) NeedsInteractive(ctx context.Context, alias, tenantID string, scopes []string) bool {
	return m.AuthCheck(ctx, alias, tenantID, scopes).Status == AuthCheckNeedsInteractive
}

// Client returns a ready-to-use GraphServiceClient with given scopes.
func (m *Manager) Client(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*msgraphsdk.GraphServiceClient, error) {
	ns, err := m.namespace(ctx)
	if err != nil {
		return nil, err
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
	ns, err := m.namespace(ctx)
	if err != nil {
		return false
	}
	recURL := m.authRecordURL(ns, alias)
	ok, _ := afs.New().Exists(ctx, recURL)
	return ok
}

// ResetAuth clears local authentication state for an alias in the current namespace.
func (m *Manager) ResetAuth(ctx context.Context, alias, tenantID string, scopes []string, purgePersistent bool) (ResetResult, error) {
	ns, err := m.namespace(ctx)
	if err != nil {
		return ResetResult{}, err
	}
	if err := m.ensureDirs(); err != nil {
		return ResetResult{}, err
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
	clearedOAuth, warnings, err := m.clearOAuthTokens(ctx, ns, alias, tenantID, scopes)
	if err != nil {
		return result, err
	}
	result.ClearedOAuthToken = clearedOAuth
	if len(warnings) > 0 {
		result.Warnings = append(result.Warnings, warnings...)
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
	ns, err := m.namespace(ctx)
	if err != nil {
		return nil, azidentity.AuthenticationRecord{}, err
	}
	if err := m.ensureDirs(); err != nil {
		debugf("graph.acquireCredential ensureDirs_error alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return nil, azidentity.AuthenticationRecord{}, err
	}
	debugf("graph.acquireCredential start ns=%q alias=%q tenant=%q deadline_in=%s", ns, alias, tenantID, debugDeadline(ctx))
	// afs-only I/O: use recURL; skip local path
	record := m.loadAuthRecord(ctx, ns, alias)
	debugf("graph.acquireCredential auth_record ns=%q alias=%q tenant=%q haveRec=%v bytes=%d openErr=%v readErr=%v unmarshalErr=%v elapsed=%s total=%s deadline_in=%s", ns, alias, tenantID, record.haveRecord, record.bytes, record.openErr, record.readErr, record.unmarshalErr, record.elapsed.Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))

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
	if record.haveRecord {
		opts.AuthenticationRecord = record.record
	}
	m.applyTokenCache(opts)
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		debugf("graph.acquireCredential new_credential_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return nil, azidentity.AuthenticationRecord{}, err
	}

	if record.haveRecord {
		// Try a quick silent token preflight. Transient provider/network failures are
		// returned as retryable errors; auth failures fall back to device-code login.
		tctx, cancel := context.WithTimeout(ctx, silentTokenTimeout)
		_, preErr := cred.GetToken(tctx, policy.TokenRequestOptions{Scopes: scopes})
		cancel()
		debugf("graph.acquireCredential silent_preflight ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, preErr, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		if preErr != nil {
			if IsTransientAuthProviderError(preErr) {
				debugf("graph.acquireCredential transient_preflight ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, preErr, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
				return nil, azidentity.AuthenticationRecord{}, NewTransientAuthProviderError(preErr)
			}
			record.record, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
			if err != nil {
				debugf("graph.acquireCredential authenticate_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
				return nil, azidentity.AuthenticationRecord{}, err
			}
			if b, err := json.Marshal(record.record); err == nil {
				recURL := m.authRecordURL(ns, alias)
				_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
				// removed log.Printf diagnostics
			}
			debugf("graph.acquireCredential authenticate_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		}
	} else {
		// No record: perform interactive device login and persist record.
		record.record, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{Scopes: scopes})
		if err != nil {
			debugf("graph.acquireCredential authenticate_error ns=%q alias=%q tenant=%q err=%v elapsed=%s deadline_in=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return nil, azidentity.AuthenticationRecord{}, err
		}
		if b, err := json.Marshal(record.record); err == nil {
			recURL := m.authRecordURL(ns, alias)
			_ = afs.New().Upload(ctx, recURL, 0o600, bytes.NewReader(b))
			// removed log.Printf diagnostics
		}
		debugf("graph.acquireCredential authenticate_ok ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	}
	debugf("graph.acquireCredential done ns=%q alias=%q tenant=%q elapsed=%s deadline_in=%s", ns, alias, tenantID, time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
	return cred, record.record, nil
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

func (m *Manager) cachedCredential(ctx context.Context, key string, scopes []string) (azcore.TokenCredential, bool) {
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

func (m *Manager) credentialUsable(ctx context.Context, cred azcore.TokenCredential, scopes []string) bool {
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

func (m *Manager) dropCredential(key string, cred azcore.TokenCredential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds[key] == cred {
		delete(m.creds, key)
		delete(m.clients, key)
	}
}

// Credential returns a cached Graph token credential for alias, acquiring and caching if needed.
func (m *Manager) Credential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (azcore.TokenCredential, error) {
	start := time.Now()
	ns, err := m.namespace(ctx)
	if err != nil {
		return nil, err
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
	var cred azcore.TokenCredential
	if m.authFlow == AuthFlowAuthCode {
		cred, err = m.oauthCredential(ctx, ns, alias, tenantID, scopes)
	} else {
		cred, _, err = m.acquireCredential(ctx, alias, tenantID, scopes, prompt)
	}
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
