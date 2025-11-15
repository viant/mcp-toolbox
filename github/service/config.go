package service

type Config struct {
	ClientID        string `json:"clientID"`
	StorageDir      string `json:"storageDir,omitempty"`
	CallbackBaseURL string `json:"callbackBaseURL,omitempty"`
	UseData         bool   `json:"useData,omitempty"`
	UseText         bool   `json:"useText,omitempty"`
	// SecretsBase is an AFS/scy URL root for persisting credentials per namespace.
	// Examples: mem://localhost/mcp-github, file://~/.mcp/github, gs://bucket/path
	SecretsBase string `json:"secretsBase,omitempty"`

	// WaitTimeoutSeconds caps how long to wait for credentials during tooling calls (default 300s).
	WaitTimeoutSeconds int `json:"waitTimeoutSeconds,omitempty"`
	// ElicitCooldownSeconds sets the minimal gap between repeated OOB prompts per namespace+alias+domain (default 60s).
	ElicitCooldownSeconds int `json:"elicitCooldownSeconds,omitempty"`

	// SnapshotMemThresholdBytes controls the max size for in-memory snapshot caching (default 100MB).
	SnapshotMemThresholdBytes int64 `json:"snapshotMemThresholdBytes,omitempty"`
	// SnapshotMemTTLSeconds controls in-memory snapshot TTL (default 900 = 15 minutes).
	SnapshotMemTTLSeconds int `json:"snapshotMemTtlSeconds,omitempty"`
	// SnapshotSharedCleanupHours controls how old shared snapshot files must be to be removed on pre-clean (default 12 hours).
	SnapshotSharedCleanupHours int `json:"snapshotSharedCleanupHours,omitempty"`
	// SedDiffBytes caps unified diff size for sed previews (default uses previewBytes for findFilesPreview; 8192 for download).
	SedDiffBytes int `json:"sedDiffBytes,omitempty"`
	// SedMaxEditsPerFile provides a default edits cap when input doesn't specify it.
	SedMaxEditsPerFile int `json:"sedMaxEditsPerFile,omitempty"`
}
