# mcp-toolbox – Model Context Protocol services and tools

This repository provides ready-to-run MCP services and reusable packages that connect LLM/MCP clients to external systems. It currently includes GitHub and Microsoft Outlook services, plus a small auth helper.

- Motivation
- What’s Included
- Quick Start
- Configuration
- Development
- Contributing
- License
- Authors

## Motivation

The goal of this project is to make it straightforward to expose common developer and productivity systems to MCP-compatible clients. Each service:
- Implements an MCP server with a compact HTTP endpoint.
- Handles OAuth/device login flows with clear, user-friendly prompts.
- Exposes practical tools and operations tailored to the target system.

## What’s Included

- GitHub MCP
  - Binary: `github/cmd/github-mcp`
  - Service package: `github/service`
  - MCP tools: `github/mcp`

- Outlook MCP
  - Binary: `outlook/cmd/outlook-mcp`
  - Service + tools: `outlook/mcp`, `outlook/service`, `outlook/graph`

- Shared
  - Auth helper: `auth` (derives caller namespace from JWT in context)

Note: Some local or experimental modules may exist in the repository but are intentionally not part of this distribution overview.

## Quick Start

Prerequisites:
- Go 1.25+

### GitHub MCP

Runs an MCP server with endpoints for GitHub operations and an auth flow using GitHub Device Code. Client ID is optional; when omitted, you can still POST tokens via HTTP.

Run:

```
go run ./github/cmd/github-mcp \
  -addr :7789 \
  -client-id YOUR_GITHUB_CLIENT_ID \
  -storage "$HOME/.config/mcp-github"
```

Endpoints (selected):
- `GET /` – root redirect/info
- `POST /mcp/call` – MCP RPC endpoint
- `POST /github/auth/start` – start Device Code flow (returns verify URL and code)
- `POST /github/auth/token` – ingest a personal access token or OAuth token
- `GET  /github/auth/pending` – list pending codes for the current namespace
- `POST /github/auth/pending/clear` – clear pending codes for the current namespace

Common tools registered by the server include listing repositories, issues/PRs, creating issues/PRs, commenting, searching issues, checking out repos, listing repo paths, and downloading files.

### Outlook MCP

Runs an MCP server integrated with Microsoft Graph using Device Code flow. You can pass Azure client details directly or load them via a `scy` EncodedResource.

Run with flags:

```
go run ./outlook/cmd/outlook-mcp \
  -addr :7788 \
  -client-id "00000000-0000-0000-0000-000000000000" \
  -tenant-id "organizations" \
  -storage "$HOME/.config/mcp-outlook" \
  -azure-ref "gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default"
```

Or environment variables:

```
export OUTLOOK_CLIENT_ID=00000000-0000-0000-0000-000000000000
# Optional: OUTLOOK_TENANT_ID defaults to "organizations" if not set.
# export OUTLOOK_TENANT_ID=organizations
export OUTLOOK_AZURE_REF='gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default'
go run ./outlook/cmd/outlook-mcp -addr :7788 -storage "$HOME/.config/mcp-outlook"
```

For more on Outlook configuration, see `outlook/mcp/README.md`.

## Configuration

Both servers derive a public callback base URL from `-addr` automatically (e.g., `http://localhost:7789`). Storage directories default to a subfolder in the user config directory.

- GitHub
  - Flags: `-addr`, `-client-id`, `-storage`
  - Env (optional):
    - `GITHUB_MCP_DEBUG`: set to enable verbose service logs
    - `GITHUB_MCP_WAIT_SECS`: max wait for credentials (default 300s)
    - `GITHUB_MCP_ELICIT_COOLDOWN_SECS`: cooldown between repeated credential prompts (default 60s)

- Outlook
  - Flags: `-addr`, `-client-id`, `-tenant-id`, `-storage`, `-azure-ref`
  - Env: `OUTLOOK_CLIENT_ID`, `OUTLOOK_TENANT_ID`, `OUTLOOK_AZURE_REF`
  - `-azure-ref`/`OUTLOOK_AZURE_REF` uses `scy` EncodedResource to load `cred.Azure` secrets (supports file/GCP/AWS backends with KMS like `blowfish://default`).

## Development

- Build a server:
  - `go build ./github/cmd/github-mcp`
  - `go build ./outlook/cmd/outlook-mcp`
- Run in place using `go run` as shown in Quick Start.
- The MCP HTTP server is provided by `github.com/viant/mcp/server` and speaks the `github.com/viant/mcp-protocol`.

## Contributing

Contributions are welcome! Please open issues or pull requests with clear reproduction details and proposed changes.

## License

The source code is available under the Apache License 2.0. See `LICENSE` for details.

## Authors

- Adrian Witas
- Viant Contributors

