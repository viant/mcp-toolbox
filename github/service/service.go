package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	// afsurl used elsewhere in package; keep if needed
	oa "github.com/viant/mcp-toolbox/auth"
	"github.com/viant/mcp-toolbox/github/adapter"
	nsprov "github.com/viant/mcp/server/namespace"
	oob "github.com/viant/mcp/server/oob"
)

// parseDelimitedRegex parses patterns like /pattern/ or /pattern/flags and returns
// (isRegex, normalizedPattern, flags). Supported flag: i (case-insensitive).
func parseDelimitedRegex(q string) (bool, string, string) {
	q = strings.TrimSpace(q)
	if len(q) < 2 {
		return false, "", ""
	}
	if !strings.HasPrefix(q, "/") {
		return false, "", ""
	}
	// Find last '/'
	idx := strings.LastIndex(q, "/")
	if idx <= 0 {
		return false, "", ""
	}
	pat := q[1:idx]
	flags := q[idx+1:]
	return true, pat, flags
}

type Service struct {
	baseURL    string
	useText    bool
	pending    *PendingAuths
	auth       *oa.Service
	ns         *nsprov.DefaultProvider
	clientID   string
	storageDir string

	mu             sync.RWMutex
	tokens         map[string]string // key(ns|alias|domain[|owner|repo[|oauth:clientID]]) -> access token
	runner         cmdRunner
	makeContentAPI func(domain string) contentAPI
	// no alias forcing/defaulting; rely on explicit alias or inference

	// treeCache stores full repo tree entries fetched via the Trees API
	// keyed by domain|owner|repo for recursive root listings.
	treeMu    sync.RWMutex
	treeCache map[string]treeCacheEntry

	// elicit guards to avoid spamming multiple prompts for the same ns/alias/domain
	elicitMu sync.Mutex
	elicited map[string]time.Time
	// global dedup across sessions per alias/domain/namespace
	elicitedGlobal map[string]time.Time

	// token waiters per alias/domain
	waitMu  sync.Mutex
	waiters map[string][]chan struct{}

	// namespace-scoped singleflight-style locks for credential acquisition per alias/domain
	credMu    sync.Mutex
	credLocks map[string]*credLock

	// cached tunables
	tunWaitOnce sync.Once
	tunCoolOnce sync.Once
	tunWait     time.Duration
	tunCooldown time.Duration

	// secrets persistence
	secretsBase string

	// in-memory shared snapshot cache for small zips (keyed by domain|owner|repo|sha)
	memSnapMu        sync.RWMutex
	memSnapCache     map[string]memSnapshotEntry
	memSnapTTL       time.Duration
	sharedCleanOlder time.Duration
	sedDiffBytes     int
	sedMaxEdits      int

	// shared snapshot store across namespaces: storageDir/gh_snapshots_shared/{domain}/{owner}/{repo}/{sha}.zip
	sharedMu sync.RWMutex

	// permission cache: token-hash + repo -> allowed until
	permMu    sync.RWMutex
	permCache map[string]time.Time
	permTTL   time.Duration

	// repo visibility cache: domain|owner|repo -> public flag with expiry
	visMu    sync.RWMutex
	visCache map[string]visEntry

	// Out-of-band manager (optional) to coordinate pending authorization per namespace
	oobMgr *oob.Manager[AuthOOBData]

	// Optional namespace binding override for this service instance
	boundNamespace string
}

/* moved to internal_types.go */

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	useText := !cfg.UseData
	s := &Service{
		baseURL:        cfg.CallbackBaseURL,
		useText:        useText,
		pending:        NewPendingAuths(),
		auth:           oa.New(),
		clientID:       cfg.ClientID,
		storageDir:     cfg.StorageDir,
		tokens:         map[string]string{},
		runner:         defaultCmdRunner{},
		makeContentAPI: func(domain string) contentAPI { return adapter.New(domain) },
		treeCache:      map[string]treeCacheEntry{},
		elicited:       map[string]time.Time{},
		elicitedGlobal: map[string]time.Time{},
		waiters:        map[string][]chan struct{}{},
		credLocks:      map[string]*credLock{},
		secretsBase:    strings.TrimRight(os.ExpandEnv(cfg.SecretsBase), "/"),
		memSnapCache:   map[string]memSnapshotEntry{},
		permCache:      map[string]time.Time{},
		visCache:       map[string]visEntry{},
	}
	// Initialize shared namespace provider: prefer identity (email/sub), fallback to token-hash with tkn- prefix
	s.ns = nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}})
	ttlSecs := 900 // 15m
	if cfg.SnapshotMemTTLSeconds > 0 {
		ttlSecs = cfg.SnapshotMemTTLSeconds
	}
	s.memSnapTTL = time.Duration(ttlSecs) * time.Second
	s.permTTL = 15 * time.Minute
	// Shared repo cache cleanup horizon
	cleanHours := 12
	if cfg.SnapshotSharedCleanupHours > 0 {
		cleanHours = cfg.SnapshotSharedCleanupHours
	}
	s.sharedCleanOlder = time.Duration(cleanHours) * time.Hour
	// Sed defaults
	if cfg.SedDiffBytes > 0 {
		s.sedDiffBytes = cfg.SedDiffBytes
	}
	if cfg.SedMaxEditsPerFile > 0 {
		s.sedMaxEdits = cfg.SedMaxEditsPerFile
	}
	// Apply tunables with sensible defaults if provided via config.
	if cfg.WaitTimeoutSeconds > 0 {
		s.tunWait = time.Duration(cfg.WaitTimeoutSeconds) * time.Second
	}
	if s.tunWait == 0 {
		s.tunWait = 300 * time.Second
	}
	if cfg.ElicitCooldownSeconds > 0 {
		s.tunCooldown = time.Duration(cfg.ElicitCooldownSeconds) * time.Second
	}
	if s.tunCooldown == 0 {
		s.tunCooldown = 60 * time.Second
	}
	return s
}

// AuthOOBData carries optional data for OOB interactions (e.g., device code hints).
type AuthOOBData struct {
	Alias     string
	Domain    string
	Owner     string
	Repo      string
	VerifyURL string
	UserCode  string
}

// SetOOBManager sets the out-of-band manager used for pending auth flows.
func (s *Service) SetOOBManager(m *oob.Manager[AuthOOBData]) { s.oobMgr = m }

// Bound returns a shallow copy of the service bound to the provided namespace.
// Internal registries and caches are shared; tokens/waiters/dedupe are namespaced by keys.
func (s *Service) Bound(namespace string) *Service {
	if s == nil {
		return nil
	}
	cp := *s
	cp.boundNamespace = strings.TrimSpace(namespace)
	return &cp
}

type contentAPI interface {
	ListContents(ctx context.Context, token, owner, name, path, ref string) ([]adapter.ContentItem, error)
	GetFileContent(ctx context.Context, token, owner, name, path, ref string) ([]byte, error)
}

// RegisterHTTP moved to auth_http.go

// snapshotKey builds a cache key for a snapshot zip scoped to ns/alias/domain/owner/name/ref.
/* moved to snapshots.go */
func (s *Service) authBasic(token string) string {
	if strings.Contains(token, ":") {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
	}
	creds := "x-access-token:" + token
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// effectiveRef returns ref if non-empty; otherwise attempts to resolve the repo's default branch.
func (s *Service) effectiveRef(ctx context.Context, domain, owner, name, ref, token string) string {
	r := strings.TrimSpace(ref)
	if r != "" {
		return r
	}
	def, err := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name)
	if err == nil && strings.TrimSpace(def) != "" {
		return def
	}
	return ref
}

/* moved to snapshots.go */

// GetOrFetchSnapshotZip returns a path to a repo snapshot zip for (owner/name@ref),
// caching to disk for 30 minutes if the size is >= 100MB.
// It uses the GitHub zipball API and follows redirects.
/* moved to snapshots.go */
func (s *Service) DownloadRepoFile(ctx context.Context, in *DownloadInput, prompt func(string)) (*DownloadOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("input is nil")
	}
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo, Ref: in.Ref}
	domain, owner, name, ref, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := s.makeContentAPI(domain)
	data, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]byte, error) {
		// Resolve ref to default if empty using authenticated call
		useRef := s.effectiveRef(ctx, domain, owner, name, ref, token)
		// If a specific ref was provided and appears invalid/inaccessible, fall back to the default branch.
		if strings.TrimSpace(ref) != "" {
			cliRef := adapter.New(domain)
			if vErr := cliRef.ValidateRef(ctx, token, owner, name, useRef); vErr != nil {
				if def, derr := cliRef.GetRepoDefaultBranch(ctx, token, owner, name); derr == nil && def != "" && def != useRef {
					// debug logs removed
					useRef = def
				}
			}
		}
		// removed log.Printf diagnostics
		p := strings.TrimPrefix(in.Path, "/")
		// First try contents API
		t0 := time.Now()
		cid := CID(ctx)
		if data, err := cli.GetFileContent(ctx, token, owner, name, p, useRef); err == nil {
			fmt.Printf("[GITHUB] DL content ok cid=%s domain=%s owner=%s repo=%s ref=%s path=%s dur=%s\n", cid, domain, owner, name, useRef, p, time.Since(t0))
			return data, nil
		}
		fmt.Printf("[GITHUB] DL content miss cid=%s domain=%s owner=%s repo=%s ref=%s path=%s dur=%s (fallback)\n", cid, domain, owner, name, useRef, p, time.Since(t0))
		// Fallback: list parent directory via contents on the same ref to obtain file SHA, then fetch blob by SHA.
		parent := p
		if idx := strings.LastIndex(parent, "/"); idx >= 0 {
			parent = parent[:idx]
		} else {
			parent = ""
		}
		// Try listing on the effective ref first; if that fails, fall back to default branch.
		t1 := time.Now()
		items, err := cli.ListContents(ctx, token, owner, name, parent, useRef)
		if err != nil {
			if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil && def != "" {
				items, err = cli.ListContents(ctx, token, owner, name, parent, def)
				fmt.Printf("[GITHUB] DL parent list default cid=%s domain=%s owner=%s repo=%s defRef=%s parent=%s dur=%s err=%v\n", cid, domain, owner, name, def, parent, time.Since(t1), err)
			}
			if err != nil {
				return nil, err
			}
		} else {
			fmt.Printf("[GITHUB] DL parent list ref cid=%s domain=%s owner=%s repo=%s ref=%s parent=%s dur=%s\n", cid, domain, owner, name, useRef, parent, time.Since(t1))
		}
		var sha string
		for _, it := range items {
			if it.Path == p && it.Sha != "" {
				sha = it.Sha
				break
			}
		}
		if sha == "" {
			return nil, fmt.Errorf("get content failed: %s", "sha not found in parent listing on ref")
		}
		t2 := time.Now()
		blob, berr := adapter.New(domain).GetBlob(ctx, token, owner, name, sha)
		fmt.Printf("[GITHUB] DL blob cid=%s domain=%s owner=%s repo=%s sha=%s dur=%s err=%v\n", cid, domain, owner, name, sha, time.Since(t2), berr)
		return blob, berr
	})
	if err != nil {
		return nil, err
	}
	// Auto-detect text vs binary. Populate only one of Text or Content.
	if isProbablyText(data) {
		out := &DownloadOutput{Text: string(data)}
		// Optional sed preview/transform using Go.Sed
		if len(in.SedScripts) > 0 {
			maxEdits := in.MaxEditsPerFile
			if maxEdits <= 0 && s.sedMaxEdits > 0 {
				maxEdits = s.sedMaxEdits
			}
			diffCap := s.sedDiffBytes
			if diffCap <= 0 {
				diffCap = 8192
			}
			edits, diff := applySedPreview(out.Text, in.SedScripts, maxEdits, diffCap)
			out.SedPreview = &SedResult{Edits: edits, Diff: diff}
			if edits > 0 {
				updated := applySedTransform(out.Text, in.SedScripts)
				out.TransformedText = updated
				if in.ApplySedToOutput {
					out.Text = updated
					out.TransformedText = ""
				}
			}
		}
		return out, nil
	}
	return &DownloadOutput{Content: data}, nil
}

func (s *Service) UseTextField() bool { return s.useText }

// isProbablyText reports whether b looks like UTF-8 text with a low ratio of control characters.
/* moved to snapshots.go */
func (s *Service) normalizeAlias(a string) string { return a }
