package graph

// ResetResult describes local Outlook auth state cleared by ResetAuth.
type ResetResult struct {
	ClearedAuthRecord     bool     `json:"clearedAuthRecord"`
	ClearedMemory         bool     `json:"clearedMemory"`
	PurgedPersistentCache bool     `json:"purgedPersistentCache"`
	PersistentCacheName   string   `json:"persistentCacheName,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
}
