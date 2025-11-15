package service

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/viant/mcp-toolbox/github/adapter"
)

// Snapshot keys and paths
func (s *Service) snapshotKey(ns, alias, domain, owner, name, ref string) string {
	if domain == "" {
		domain = "github.com"
	}
	if ns == "" {
		ns = "default"
	}
	return joinKey(ns, alias, domain, owner, name, ref)
}
func (s *Service) snapshotPath(ns, alias, domain, owner, name, ref string) string {
	base := os.ExpandEnv(s.storageDir)
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	segs := []string{base, "gh_snapshots", safePart(ns), safePart(alias), safePart(domain), safePart(owner) + "_" + safePart(name) + "_" + safePart(ref) + ".zip"}
	return filepath.Join(segs...)
}
func (s *Service) sharedSnapshotPath(domain, owner, name, sha string) string {
	base := os.ExpandEnv(s.storageDir)
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	segs := []string{base, "gh_snapshots_shared", safePart(domain), safePart(owner), safePart(name), safePart(sha) + ".zip"}
	return filepath.Join(segs...)
}
func (s *Service) sharedMemKey(domain, owner, name, sha string) string {
	return strings.ToLower(strings.Join([]string{safePart(domain), safePart(owner), safePart(name), safePart(sha)}, "|"))
}

const snapshotLargeThreshold = int64(100 * 1024 * 1024) // 100MB
var snapshotTTL = 30 * time.Minute

// GetOrFetchSnapshotZip fetches or returns a cached snapshot zip path for owner/name@ref
func (s *Service) GetOrFetchSnapshotZip(ctx context.Context, ns, alias, domain, owner, name, ref, token string) (string, int64, bool, string, error) {
	// Resolve ref to a SHA if needed
	resolvedSHA := ref
	if !looksLikeSHA(ref) {
		if sha := s.resolveZipballSHA(ctx, domain, owner, name, ref, token); sha != "" {
			resolvedSHA = sha
		}
	}
	if resolvedSHA == "" {
		resolvedSHA = ref
	}
	shared := s.sharedSnapshotPath(domain, owner, name, resolvedSHA)
	memKey := s.sharedMemKey(domain, owner, name, resolvedSHA)

	// In-memory shared cache
	s.memSnapMu.RLock()
	if m, ok := s.memSnapCache[memKey]; ok && time.Now().Before(m.expireAt) && m.size > 0 {
		s.memSnapMu.RUnlock()
		return "", m.size, true, resolvedSHA, nil
	}
	s.memSnapMu.RUnlock()

	// Shared file if accessible
	if fi, e := os.Stat(shared); e == nil && fi.Mode().IsRegular() {
		if s.canUseSharedSnapshot(ctx, domain, owner, name, token) {
			_ = os.Chtimes(shared, time.Now(), time.Now())
			return shared, fi.Size(), true, resolvedSHA, nil
		}
	}

	// Download from zipball API
	apiBase := "https://api.github.com"
	if domain != "" && domain != "github.com" {
		apiBase = "https://" + domain + "/api/v3"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/zipball/%s", apiBase, owner, name, neturl.PathEscape(resolvedSHA))
	doFetch := func() (int64, error) {
		var written int64
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if strings.TrimSpace(token) != "" {
			req.Header.Set("Authorization", s.authBasic(token))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return 0, adapter.ErrUnauthorized
		}
		if resp.StatusCode >= 300 {
			return 0, fmt.Errorf("zipball fetch failed: %s", resp.Status)
		}
		if !looksLikeSHA(resolvedSHA) {
			if cand := s.extractSHAFromHTTP(resp); cand != "" {
				resolvedSHA = cand
				newShared := s.sharedSnapshotPath(domain, owner, name, resolvedSHA)
				if newShared != shared {
					_ = os.MkdirAll(filepath.Dir(newShared), 0o755)
					shared = newShared
				}
			}
		}
		_ = os.MkdirAll(filepath.Dir(shared), 0o755)
		tmp := shared + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			return 0, err
		}
		defer func() { _ = f.Close(); _ = os.Remove(tmp) }()
		cr := &countingReader{r: resp.Body, n: &written}
		if _, err := io.Copy(f, cr); err != nil {
			return 0, err
		}
		if err := os.Rename(tmp, shared); err != nil {
			return 0, err
		}
		return written, nil
	}
	n, err := doFetch()
	if err != nil {
		return "", 0, false, "", err
	}

	// Indexing/cleanup and cache population
	cacheDir := filepath.Dir(shared)
	cleanupOldSharedRepoFiles(cacheDir, s.sharedCleanOlder)
	if n >= snapshotLargeThreshold {
		// large: leave on disk only
	} else {
		data, _ := os.ReadFile(shared)
		s.memSnapMu.Lock()
		s.memSnapCache[s.sharedMemKey(domain, owner, name, resolvedSHA)] = memSnapshotEntry{data: data, size: int64(len(data)), expireAt: time.Now().Add(s.memSnapTTL)}
		s.memSnapMu.Unlock()
	}
	return shared, n, false, resolvedSHA, nil
}

// GetSnapshotBytes returns a memory-cached snapshot if available.
func (s *Service) GetSnapshotBytes(domain, owner, name, sha string) ([]byte, bool) {
	key := s.sharedMemKey(domain, owner, name, sha)
	s.memSnapMu.RLock()
	defer s.memSnapMu.RUnlock()
	if m, ok := s.memSnapCache[key]; ok && time.Now().Before(m.expireAt) && len(m.data) > 0 {
		return m.data, true
	}
	return nil, false
}

// Eviction helpers
func (s *Service) evictSnapshotNamespace(ns string, atLeast int) error {
	base := os.ExpandEnv(s.storageDir)
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "gh_snapshots", safePart(ns))
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	removed := 0
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(fi.ModTime()) > snapshotTTL {
			_ = os.Remove(filepath.Join(root, e.Name()))
			removed++
			if removed >= atLeast {
				break
			}
		}
	}
	return nil
}

func (s *Service) evictSharedSnapshots(atLeast int) error {
	base := os.ExpandEnv(s.storageDir)
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "gh_snapshots_shared")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	removed := 0
	now := time.Now()
	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		ownerDirs, _ := os.ReadDir(filepath.Join(root, dir.Name()))
		for _, od := range ownerDirs {
			repoDirs, _ := os.ReadDir(filepath.Join(root, dir.Name(), od.Name()))
			// Remove old or excess files within each repo
			for _, f := range repoDirs {
				if f.IsDir() {
					continue
				}
				fi, err := f.Info()
				if err != nil {
					continue
				}
				if now.Sub(fi.ModTime()) > snapshotTTL {
					_ = os.Remove(filepath.Join(root, dir.Name(), od.Name(), f.Name()))
					removed++
					if removed >= atLeast {
						return nil
					}
				}
			}
		}
	}
	return nil
}

// Permission/visibility checks for shared snapshots
func (s *Service) canUseSharedSnapshot(ctx context.Context, domain, owner, name, token string) bool {
	repoKey := joinKey(domain, owner, name)
	s.visMu.RLock()
	if ent, ok := s.visCache[repoKey]; ok && time.Now().Before(ent.expireAt) {
		isPublic := ent.public
		s.visMu.RUnlock()
		if isPublic {
			return true
		}
	} else {
		s.visMu.RUnlock()
	}

	tokHash := hashToken(token)
	if tokHash != "" {
		key := joinKey(domain, owner, name, tokHash)
		s.permMu.RLock()
		if exp, ok := s.permCache[key]; ok && time.Now().Before(exp) {
			s.permMu.RUnlock()
			return true
		}
		s.permMu.RUnlock()
	}
	info, err := adapter.New(domain).GetRepo(ctx, token, owner, name)
	if err != nil {
		return false
	}
	s.visMu.Lock()
	s.visCache[repoKey] = visEntry{public: !info.Private, expireAt: time.Now().Add(30 * time.Minute)}
	s.visMu.Unlock()
	if !info.Private {
		return true
	}
	if tokHash != "" {
		key := joinKey(domain, owner, name, tokHash)
		s.permMu.Lock()
		s.permCache[key] = time.Now().Add(s.permTTL)
		s.permMu.Unlock()
		return true
	}
	return false
}

func hashToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	var h uint64 = 1469598103934665603
	const prime64 = 1099511628211
	for i := 0; i < len(token); i++ {
		h ^= uint64(token[i])
		h *= prime64
	}
	return fmt.Sprintf("%x", h)
}

func cleanupOldSharedRepoFiles(dir string, olderThan time.Duration) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	now := time.Now()
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(fi.ModTime()) >= olderThan {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			removed++
		}
	}
	return removed
}

func (s *Service) findExistingSharedZip(domain, owner, name string) string {
	base := os.ExpandEnv(s.storageDir)
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	repoDir := filepath.Join(base, "gh_snapshots_shared", safePart(domain), safePart(owner), safePart(name))
	entries, err := os.ReadDir(repoDir)
	if err != nil {
		return ""
	}
	type pair struct {
		name string
		mod  time.Time
	}
	var found []pair
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		nm := e.Name()
		if !strings.HasSuffix(strings.ToLower(nm), ".zip") {
			continue
		}
		sha := strings.TrimSuffix(nm, ".zip")
		fi, err := e.Info()
		if err != nil {
			continue
		}
		found = append(found, pair{name: sha, mod: fi.ModTime()})
	}
	if len(found) == 0 {
		return ""
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod.After(found[j].mod) })
	return found[0].name
}

// read helpers and detectors
func readZipEntry(zipPath, repoPath string, maxBytes int64) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == repoPath {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			if maxBytes > 0 {
				var buf bytes.Buffer
				_, _ = io.CopyN(&buf, rc, maxBytes)
				return buf.Bytes(), nil
			}
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("file not found in zip: %s", repoPath)
}

// readZipEntryFromBytes reads a file from a zip byte slice.
func readZipEntryFromBytes(zipData []byte, repoPath string, maxBytes int64) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == repoPath {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			if maxBytes > 0 {
				var buf bytes.Buffer
				_, _ = io.CopyN(&buf, rc, maxBytes)
				return buf.Bytes(), nil
			}
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("file not found in zip: %s", repoPath)
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 && cr.n != nil {
		atomic.AddInt64(cr.n, int64(n))
	}
	return n, err
}

func extractSHAFromZipFile(p string) string {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return ""
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			top := strings.TrimSuffix(f.Name, "/")
			if idx := strings.IndexByte(top, '/'); idx >= 0 {
				top = top[:idx]
			}
			base := filepath.Base(top)
			parts := strings.Split(base, "-")
			if len(parts) > 0 {
				cand := parts[len(parts)-1]
				if looksLikeSHA(cand) {
					return strings.ToLower(cand)
				}
			}
			break
		}
	}
	for _, f := range zr.File {
		name := f.Name
		if name == "" {
			continue
		}
		top := name
		if idx := strings.IndexByte(name, '/'); idx >= 0 {
			top = name[:idx]
		}
		base := filepath.Base(top)
		parts := strings.Split(base, "-")
		if len(parts) == 0 {
			continue
		}
		cand := parts[len(parts)-1]
		if looksLikeSHA(cand) {
			return strings.ToLower(cand)
		}
		if l := len(cand); l >= 7 && l <= 40 {
			hex := true
			for i := 0; i < l; i++ {
				c := cand[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					hex = false
					break
				}
			}
			if hex {
				return strings.ToLower(cand)
			}
		}
		break
	}
	return ""
}

func (s *Service) resolveZipballSHA(ctx context.Context, domain, owner, name, ref, token string) string {
	apiBase := "https://api.github.com"
	if domain != "" && domain != "github.com" {
		apiBase = "https://" + domain + "/api/v3"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/zipball/%s", apiBase, owner, name, neturl.PathEscape(ref))
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", s.authBasic(token))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil {
		segs := strings.Split(strings.Trim(resp.Request.URL.Path, "/"), "/")
		if len(segs) > 0 {
			cand := segs[len(segs)-1]
			if looksLikeSHA(cand) {
				return strings.ToLower(cand)
			}
		}
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if i := strings.LastIndex(cd, "-"); i > 0 {
			if j := strings.LastIndex(strings.ToLower(cd), ".zip"); j > i {
				cand := strings.Trim(cd[i+1:j], `"'`)
				if looksLikeSHA(cand) {
					return strings.ToLower(cand)
				}
			}
		}
	}
	return ""
}

// looksLikeSHA reports whether s is a 40-hex SHA1 string.
func looksLikeSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func (s *Service) extractSHAFromHTTP(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if resp.Request != nil && resp.Request.URL != nil {
		segs := strings.Split(strings.Trim(resp.Request.URL.Path, "/"), "/")
		if len(segs) > 0 {
			cand := segs[len(segs)-1]
			if looksLikeSHA(cand) {
				return strings.ToLower(cand)
			}
		}
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if i := strings.LastIndex(cd, "-"); i > 0 {
			if j := strings.LastIndex(strings.ToLower(cd), ".zip"); j > i {
				cand := strings.Trim(cd[i+1:j], `"'`)
				if looksLikeSHA(cand) {
					return strings.ToLower(cand)
				}
			}
		}
	}
	return ""
}

// Content scanning on snapshots
func (s *Service) scanZipContent(zipPath string, candidates map[string]bool, include, exclude []string, caseInsensitive, skipBinary bool, maxSize int64) (map[string]bool, map[string]bool) {
	matched := map[string]bool{}
	excluded := map[string]bool{}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return matched, excluded
	}
	defer zr.Close()
	lower := func(b []byte) []byte {
		if caseInsensitive {
			return bytes.ToLower(b)
		}
		return b
	}
	toLower := func(s string) string {
		if caseInsensitive {
			return strings.ToLower(s)
		}
		return s
	}
	incl := make([]string, 0, len(include))
	excl := make([]string, 0, len(exclude))
	for _, p := range include {
		if strings.TrimSpace(p) != "" {
			incl = append(incl, toLower(p))
		}
	}
	for _, p := range exclude {
		if strings.TrimSpace(p) != "" {
			excl = append(excl, toLower(p))
		}
	}
	for _, f := range zr.File {
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		if !candidates[name] {
			continue
		}
		if maxSize > 0 && f.UncompressedSize64 > uint64(maxSize) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		if maxSize > 0 {
			_, _ = io.CopyN(&buf, rc, maxSize)
		} else {
			_, _ = io.Copy(&buf, rc)
		}
		_ = rc.Close()
		data := buf.Bytes()
		if skipBinary && !isProbablyText(data) {
			continue
		}
		s := toLower(string(lower(data)))
		for _, q := range incl {
			if strings.Contains(s, q) {
				matched[name] = true
				break
			}
		}
		for _, q := range excl {
			if strings.Contains(s, q) {
				excluded[name] = true
				break
			}
		}
	}
	return matched, excluded
}

func (s *Service) scanZipFind(zipPath string, candidates map[string]bool, query string, skipBinary bool, maxSize int64, ci bool) map[string]bool {
	out := map[string]bool{}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return out
	}
	defer zr.Close()
	isRegex, pat, flags := parseDelimitedRegex(query)
	var re *regexp.Regexp
	if isRegex {
		if strings.Contains(flags, "i") {
			pat = "(?i)" + pat
		}
		re, err = regexp.Compile(pat)
		if err != nil {
			return out
		}
	} else {
		pat = strings.TrimSpace(query)
	}
	patBytes := []byte(pat)
	var patLower []byte
	if !isRegex && ci {
		patLower = bytes.ToLower(patBytes)
	}
	for _, f := range zr.File {
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		if !candidates[name] {
			continue
		}
		if maxSize > 0 && f.UncompressedSize64 > uint64(maxSize) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		if maxSize > 0 {
			_, _ = io.CopyN(&buf, rc, maxSize)
		} else {
			_, _ = io.Copy(&buf, rc)
		}
		_ = rc.Close()
		data := buf.Bytes()
		if skipBinary && !isProbablyText(data) {
			continue
		}
		if isRegex {
			if re.Match(data) {
				out[name] = true
			}
		} else {
			if ci {
				if bytes.Contains(bytes.ToLower(data), patLower) {
					out[name] = true
				}
			} else {
				if bytes.Contains(data, patBytes) {
					out[name] = true
				}
			}
		}
	}
	return out
}

func (s *Service) scanZipFindFromBytes(data []byte, candidates map[string]bool, query string, skipBinary bool, maxSize int64, ci bool) map[string]bool {
	out := map[string]bool{}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return out
	}
	isRegex, pat, flags := parseDelimitedRegex(query)
	var re *regexp.Regexp
	if isRegex {
		if strings.Contains(flags, "i") {
			pat = "(?i)" + pat
		}
		re, err = regexp.Compile(pat)
		if err != nil {
			return out
		}
	} else {
		pat = strings.TrimSpace(query)
	}
	patBytes := []byte(pat)
	var patLower []byte
	if !isRegex && ci {
		patLower = bytes.ToLower(patBytes)
	}
	for _, f := range zr.File {
		name := f.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		if !candidates[name] {
			continue
		}
		if maxSize > 0 && f.UncompressedSize64 > uint64(maxSize) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		if maxSize > 0 {
			_, _ = io.CopyN(&buf, rc, maxSize)
		} else {
			_, _ = io.Copy(&buf, rc)
		}
		_ = rc.Close()
		b := buf.Bytes()
		if skipBinary && !isProbablyText(b) {
			continue
		}
		if isRegex {
			if re.Match(b) {
				out[name] = true
			}
		} else {
			if ci {
				if bytes.Contains(bytes.ToLower(b), patLower) {
					out[name] = true
				}
			} else {
				if bytes.Contains(b, patBytes) {
					out[name] = true
				}
			}
		}
	}
	return out
}

func (s *Service) buildContentSets(zipPath string, candidates map[string]bool, includes, excludes []string, skipBinary bool, maxSize int64, ci bool) (map[string]bool, map[string]bool) {
	var inc map[string]bool
	var exc map[string]bool
	for _, q := range includes {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		m := s.scanZipFind(zipPath, candidates, q, skipBinary, maxSize, ci)
		if inc == nil {
			inc = map[string]bool{}
		}
		for k := range m {
			inc[k] = true
		}
	}
	for _, q := range excludes {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		m := s.scanZipFind(zipPath, candidates, q, skipBinary, maxSize, ci)
		if exc == nil {
			exc = map[string]bool{}
		}
		for k := range m {
			exc[k] = true
		}
	}
	return inc, exc
}

func (s *Service) buildContentSetsFromBytes(data []byte, candidates map[string]bool, includes, excludes []string, skipBinary bool, maxSize int64, ci bool) (map[string]bool, map[string]bool) {
	var inc map[string]bool
	var exc map[string]bool
	for _, q := range includes {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		m := s.scanZipFindFromBytes(data, candidates, q, skipBinary, maxSize, ci)
		if inc == nil {
			inc = map[string]bool{}
		}
		for k := range m {
			inc[k] = true
		}
	}
	for _, q := range excludes {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		m := s.scanZipFindFromBytes(data, candidates, q, skipBinary, maxSize, ci)
		if exc == nil {
			exc = map[string]bool{}
		}
		for k := range m {
			exc[k] = true
		}
	}
	return inc, exc
}

func filterContentPatterns(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, q := range in {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		out = append(out, q)
	}
	return out
}

func isProbablyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	var control, total int
	for len(sample) > 0 {
		r, size := utf8.DecodeRune(sample)
		sample = sample[size:]
		total++
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			control++
			if control > 8 {
				return false
			}
		}
	}
	return true
}

// Preview utilities
func countMatches(b []byte, patterns []string, ci bool) int {
	if len(patterns) == 0 || len(b) == 0 {
		return 0
	}
	total := 0
	lower := b
	for _, q := range patterns {
		if q == "" {
			continue
		}
		if ok, pat, flags := parseDelimitedRegex(q); ok {
			if strings.Contains(flags, "i") {
				pat = "(?i)" + pat
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			total += len(re.FindAllIndex(b, -1))
			continue
		}
		qb := []byte(q)
		if ci {
			if &lower == &b {
				lower = bytes.ToLower(b)
			}
			qb = bytes.ToLower(qb)
		}
		idx := 0
		for {
			loc := bytes.Index(lower[idx:], qb)
			if loc < 0 {
				break
			}
			total++
			idx += loc + len(qb)
			if idx >= len(lower) {
				break
			}
		}
	}
	return total
}

func buildMatchSnippetsCompact(b []byte, patterns []string, ci bool, contextLines, previewBytes, maxBlocks int) ([]PreviewSnippet, bool, int, int) {
	total := countMatches(b, patterns, ci)
	if total == 0 {
		return nil, false, 0, 0
	}
	ranges := findMatchRanges(b, patterns, ci)
	if len(ranges) == 0 {
		return nil, false, 0, total
	}
	lineStarts, lines := indexLines(b)
	windows := expandMatchWindows(ranges, lineStarts, contextLines, len(lines))
	windows = mergeWindows(windows)
	if maxBlocks > 0 && len(windows) > maxBlocks {
		windows = windows[:maxBlocks]
	}
	covered := 0
	for _, r := range ranges {
		if matchCoveredByWindows(r, lineStarts, windows) {
			covered++
		}
	}
	perLine := make(map[int][][2]int)
	for _, r := range ranges {
		start, end := r[0], r[1]
		sLine := findLineForOffset(lineStarts, start)
		eLine := findLineForOffset(lineStarts, end-1)
		if sLine < 0 || eLine < 0 {
			continue
		}
		for li := sLine; li <= eLine; li++ {
			ls := lineStarts[li]
			le := lineEndOffset(lineStarts, li, len(b))
			a := maxInt(start, ls)
			z := minInt(end, le)
			perLine[li] = append(perLine[li], [2]int{a - ls, z - ls})
		}
	}
	var out []PreviewSnippet
	used := 0
	truncated := false
	for _, w := range windows {
		var sb strings.Builder
		hits := make([][2]int, 0, 8)
		base := 0
		for li := w[0]; li <= w[1]; li++ {
			line := lines[li]
			if rs := perLine[li]; len(rs) > 0 {
				for _, r := range rs {
					hits = append(hits, [2]int{base + r[0], base + r[1]})
				}
			}
			sb.Write(line)
			if li < w[1] {
				sb.WriteByte('\n')
			}
			base = sb.Len()
			if previewBytes > 0 && used+base > previewBytes {
				break
			}
		}
		text := sb.String()
		if previewBytes > 0 && used+len(text) > previewBytes {
			remain := previewBytes - used
			if remain < 0 {
				remain = 0
			}
			if remain < len(text) {
				text = text[:remain]
				truncated = true
			}
		}
		out = append(out, PreviewSnippet{Start: w[0] + 1, End: w[1] + 1, Text: text, Hits: hits})
		used += len(text)
		if previewBytes > 0 && used >= previewBytes {
			truncated = true
			break
		}
	}
	if truncated && len(out) > 0 {
		out[len(out)-1].Cut = true
	}
	return out, truncated, covered, total
}

func findMatchRanges(b []byte, patterns []string, ci bool) [][2]int {
	if len(patterns) == 0 || len(b) == 0 {
		return nil
	}
	var out [][2]int
	var lower []byte
	for _, q := range patterns {
		q = strings.TrimSpace(q)
		if q == "" {
			continue
		}
		if ok, pat, flags := parseDelimitedRegex(q); ok {
			if strings.Contains(flags, "i") {
				pat = "(?i)" + pat
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			locs := re.FindAllIndex(b, -1)
			for _, loc := range locs {
				if len(loc) == 2 {
					out = append(out, [2]int{loc[0], loc[1]})
				}
			}
			continue
		}
		qb := []byte(q)
		hay := b
		if ci {
			if lower == nil {
				lower = bytes.ToLower(b)
			}
			hay = lower
			qb = bytes.ToLower(qb)
		}
		idx := 0
		for {
			loc := bytes.Index(hay[idx:], qb)
			if loc < 0 {
				break
			}
			s := idx + loc
			e := s + len(qb)
			out = append(out, [2]int{s, e})
			idx = e
			if idx >= len(hay) {
				break
			}
		}
	}
	if len(out) == 0 {
		return out
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] == out[j][0] {
			return out[i][1] < out[j][1]
		}
		return out[i][0] < out[j][0]
	})
	// merge
	merged := make([][2]int, 0, len(out))
	cur := out[0]
	for i := 1; i < len(out); i++ {
		r := out[i]
		if r[0] <= cur[1] {
			if r[1] > cur[1] {
				cur[1] = r[1]
			}
		} else {
			merged = append(merged, cur)
			cur = r
		}
	}
	merged = append(merged, cur)
	return merged
}

func indexLines(b []byte) ([]int, [][]byte) {
	if len(b) == 0 {
		return []int{0}, [][]byte{{}}
	}
	starts := []int{0}
	var lines [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			end := i
			if end > start && b[end-1] == '\r' {
				end--
			}
			lines = append(lines, b[start:end])
			starts = append(starts, i+1)
			start = i + 1
		}
	}
	if start <= len(b) {
		end := len(b)
		if !(end > start && end-1 >= 0 && b[end-1] == '\n') {
			lines = append(lines, b[start:end])
		}
	}
	return starts, lines
}

func lineEndOffset(starts []int, lineIdx int, total int) int {
	if lineIdx+1 < len(starts) {
		end := starts[lineIdx+1]
		return end - 1
	}
	return total
}

func findLineForOffset(starts []int, off int) int {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] > off })
	return i - 1
}

func expandMatchWindows(ranges [][2]int, starts []int, context, totalLines int) [][2]int {
	if len(ranges) == 0 {
		return nil
	}
	out := make([][2]int, 0, len(ranges))
	for _, r := range ranges {
		sLine := findLineForOffset(starts, r[0])
		eLine := findLineForOffset(starts, r[1]-1)
		if sLine < 0 {
			sLine = 0
		}
		if eLine < 0 {
			eLine = 0
		}
		sLine = maxInt(0, sLine-context)
		eLine = minInt(totalLines-1, eLine+context)
		out = append(out, [2]int{sLine, eLine})
	}
	return out
}

func mergeWindows(wins [][2]int) [][2]int {
	if len(wins) == 0 {
		return wins
	}
	sort.Slice(wins, func(i, j int) bool {
		if wins[i][0] == wins[j][0] {
			return wins[i][1] < wins[j][1]
		}
		return wins[i][0] < wins[j][0]
	})
	merged := make([][2]int, 0, len(wins))
	cur := wins[0]
	for i := 1; i < len(wins); i++ {
		w := wins[i]
		if w[0] <= cur[1]+1 {
			if w[1] > cur[1] {
				cur[1] = w[1]
			}
		} else {
			merged = append(merged, cur)
			cur = w
		}
	}
	merged = append(merged, cur)
	return merged
}

func matchCoveredByWindows(r [2]int, starts []int, wins [][2]int) bool {
	sLine := findLineForOffset(starts, r[0])
	eLine := findLineForOffset(starts, r[1]-1)
	for _, w := range wins {
		if sLine >= w[0] && sLine <= w[1] {
			return true
		}
		if eLine >= w[0] && eLine <= w[1] {
			return true
		}
		if sLine < w[0] && eLine > w[1] {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
