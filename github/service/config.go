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
}
