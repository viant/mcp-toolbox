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
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/viant/afs"
	oaauth "github.com/viant/mcp-toolbox/auth"
)

// Manager provides Microsoft Graph client instances per account alias.
type Manager struct {
	clientID   string
	storageDir string
	auth       *oaauth.Service
	// pending holds device-code prompts keyed by account alias.
	pending map[string]*pendingAuth
	// clients caches GraphServiceClient instances per alias+tenant+scopes.
	mu      sync.RWMutex
	clients map[string]*msgraphsdk.GraphServiceClient
	// creds caches device code credentials per alias, kept in memory until process restarts.
	creds map[string]*azidentity.DeviceCodeCredential
}

type pendingAuth struct{ message string }

func NewManager(clientID, storageDir string) *Manager {
	return &Manager{
		clientID:   clientID,
		storageDir: storageDir,
		auth:       oaauth.New(),
		pending:    map[string]*pendingAuth{},
		clients:    map[string]*msgraphsdk.GraphServiceClient{},
		creds:      map[string]*azidentity.DeviceCodeCredential{},
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
	ns, _ := m.auth.Namespace(ctx)
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
			_ = json.Unmarshal(data, &rec)
			haveRec = true
		}
		_ = rc.Close()
	}
	// removed log.Printf diagnostics
	opts := &azidentity.DeviceCodeCredentialOptions{
		TenantID:   tenantID,
		ClientID:   m.clientID,
		UserPrompt: func(context.Context, azidentity.DeviceCodeMessage) error { return nil },
	}
	if haveRec {
		opts.AuthenticationRecord = rec
	}
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		return true
	}
	ctx2, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	_, err = cred.GetToken(ctx2, policy.TokenRequestOptions{Scopes: scopes})
	need := err != nil
	// removed log.Printf diagnostics
	return need
}

// Client returns a ready-to-use GraphServiceClient with given scopes.
func (m *Manager) Client(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*msgraphsdk.GraphServiceClient, error) {
	ns, _ := m.auth.Namespace(ctx)
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
	ns, _ := m.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	recURL := m.authRecordURL(ns, alias)
	ok, _ := afs.New().Exists(ctx, recURL)
	return ok
}

// StartDeviceLogin launches the device code authentication in background.
// It stores the prompt message to be retrievable via DevicePrompt.
func (m *Manager) StartDeviceLogin(ctx context.Context, alias, tenantID string, scopes []string, onComplete func()) {
	if _, ok := m.pending[alias]; ok {
		return
	}
	holder := &pendingAuth{}
	m.pending[alias] = holder
	go func() {
		prompt := func(msg string) { holder.message = msg }
		if _, _, err := m.acquireCredential(ctx, alias, tenantID, scopes, prompt); err == nil {
			if onComplete != nil {
				onComplete()
			}
		}
		delete(m.pending, alias)
	}()
}

// acquireCredential performs Device Code flow. If an auth record exists, use it for silent login.
func (m *Manager) acquireCredential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, azidentity.AuthenticationRecord, error) {
	if err := m.ensureDirs(); err != nil {
		return nil, azidentity.AuthenticationRecord{}, err
	}
	ns, _ := m.auth.Namespace(ctx)
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
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		return nil, azidentity.AuthenticationRecord{}, err
	}

	if haveRec {
		// Try a quick silent token preflight. If it fails, fall back to interactive flow
		// (this will invoke the prompt with a device code), then persist a fresh record.
		tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
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
	if p, ok := m.pending[alias]; ok {
		return p.message
	}
	return ""
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
	m.mu.RLock()
	if c := m.creds[key]; c != nil {
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()
	cred, _, err := m.acquireCredential(ctx, alias, tenantID, scopes, prompt)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if existing := m.creds[key]; existing != nil {
		m.mu.Unlock()
		return existing, nil
	}
	m.creds[key] = cred
	m.mu.Unlock()
	return cred, nil
}
