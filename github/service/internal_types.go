package service

import (
	"github.com/viant/mcp-toolbox/github/adapter"
	"time"
)

// treeCacheEntry holds cached tree entries with expiration.
type treeCacheEntry struct {
	entries  []adapter.TreeEntry
	expireAt time.Time
}

// credLock coordinates a single credential acquisition per ns+alias+domain.
// Waiters block on done until the owner releases.
type credLock struct{ done chan struct{} }

// snapshotEntry holds cached snapshot zip metadata.
type snapshotEntry struct {
	path     string
	size     int64
	expireAt time.Time
}

type memSnapshotEntry struct {
	data     []byte
	size     int64
	expireAt time.Time
}

type visEntry struct {
	public   bool
	expireAt time.Time
}
