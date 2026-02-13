GitHub MCP

- Binary: `github/cmd/github-mcp`
- Service package: `github/service`
- MCP tools: `github/mcp`

Run:
  go run ./github/cmd/github-mcp -a :7789 

Notes on auth scoping:
- Tokens are scoped by namespace (derived from identity when available, otherwise token-hash).
- Sharing tokens within the same user/namespace is an intentional tradeoff to reduce repeated prompts.
- If you need stricter isolation, ensure callers use distinct identities/namespaces.
