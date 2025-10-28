package service

import (
    mcpservice "github.com/viant/mcp-toolbox/outlook/mcp"
)

// Service mirrors the Outlook MCP service to align package layout with github/service.
// This is a type alias to avoid duplicate implementations and preserve compatibility.
type Service = mcpservice.Service

// Config aliases the MCP service config for constructor parity.
type Config = mcpservice.Config

// NewService constructs the Outlook service; delegates to outlook/mcp.NewService.
func NewService(cfg *Config) *Service { return mcpservice.NewService(cfg) }

