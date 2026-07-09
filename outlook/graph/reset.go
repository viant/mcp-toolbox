package graph

// ResetResult describes local Outlook auth state cleared by ResetAuth.
type ResetResult struct {
	ClearedAuthRecord     bool     `json:"clearedAuthRecord"`
	ClearedOAuthToken     bool     `json:"clearedOAuthToken"`
	ClearedMemory         bool     `json:"clearedMemory"`
	PurgedPersistentCache bool     `json:"purgedPersistentCache"`
	PersistentCacheName   string   `json:"persistentCacheName,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
}
