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
  -a :7789 \
  -o "ipd_xxx.enc|blowfish://default" -i
  
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
  --a :7788 \
  --azure-ref "azure-cred|blowfish://default"
   -o "ipd_xxx.enc|blowfish://default" -i
```




Or environment variables:

```
export OUTLOOK_CLIENT_ID=00000000-0000-0000-0000-000000000000
# Optional: OUTLOOK_TENANT_ID defaults to "organizations" if not set.
# export OUTLOOK_TENANT_ID=organizations
export OUTLOOK_AZURE_REF='gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default'
go run ./outlook/cmd/outlook-mcp -addr :7788 --secretsBase mem://localhost/mcp-outlook
```

For more on Outlook configuration, see `outlook/mcp/README.md`.

## Configuration

Both servers derive a public callback base URL from `-addr` automatically (e.g., `http://localhost:7789`). Storage directories default to a subfolder in the user config directory.

- GitHub
  - Flags: `-addr`, `-client-id`, `-storage`, `-o/--oauth2config`, `-i/--use-id-token`, `--secretsBase`
  - Env (optional):
    - `GITHUB_MCP_DEBUG`: set to enable verbose service logs
    - `GITHUB_MCP_WAIT_SECS`: max wait for credentials (default 300s)
    - `GITHUB_MCP_ELICIT_COOLDOWN_SECS`: cooldown between repeated credential prompts (default 60s)

- Outlook
  - Flags: `-addr`, `-client-id`, `-tenant-id`, `-azure-ref`, `-o/--oauth2config`, `-i/--use-id-token`, `--secretsBase`
  - Env: `OUTLOOK_CLIENT_ID`, `OUTLOOK_TENANT_ID`, `OUTLOOK_AZURE_REF`
  - `-azure-ref`/`OUTLOOK_AZURE_REF` uses `scy` EncodedResource to load `cred.Azure` secrets (supports file/GCP/AWS backends with KMS like `blowfish://default`).

## Namespace Isolation

MCP requests and stored credentials are isolated by a “namespace” derived from the caller’s identity:

- With server auth enabled (`-o/--oauth2config`), the authorizer places a token in the request context. We extract `email` or `sub` (subject) from that token to form the namespace. If neither can be extracted, we fall back to a stable token hash namespace `tkn-<md5>` to prevent cross-user leakage.
- Without server auth, if the caller supplies `Authorization: Bearer <jwt>`, we still derive namespace from claims or fall back to `tkn-<md5>`; otherwise, the namespace defaults to `default`.

Per-namespace separation in this repo:
- GitHub: tokens, wait/wakeup keys, and repo tree caches are keyed by namespace. Debug logs show `ns=...` when saving.
- Outlook: authentication records (disk/AFS), azidentity caches, in-memory clients/creds are keyed by namespace. Debug logs show `ns=...` and record URL when saving.

Important for remote deployments:
- To guarantee isolation across concurrently connected users, run with both `-o` and `-i` (ID tokens) and ensure the client completes the BFF/auth flow. Otherwise, auth tokens or connections obtained under a weaker namespace (e.g., `default`) could be visible to other users via fallback behavior.
- If you intentionally share credentials (e.g., a team-wide token), you may omit `-o/-i` and rely on the `default` namespace, but be aware this is shared across users.

HTTP auth endpoints and BFF:
- JSON-RPC (`/mcp`) calls are always mediated by the authorizer when `-o` is set.
- Custom HTTP auth endpoints (e.g., `/github/auth/*`, `/outlook/auth/*`) can either be wrapped with the authorizer or accept `Authorization: Bearer <id_token>` so that secret writes land in the correct namespace.

## Secrets Storage Backends

Both GitHub and Outlook can persist credentials to a storage backend via `--secretsBase` (AFS/scy URL):

- mem:// – in-memory storage for the life of the process (great for local dev/tests)
  - Example: `--secretsBase mem://localhost/mcp-github`
  - Example: `--secretsBase mem://localhost/mcp-outlook`
- file:// – local filesystem paths
  - Example: `--secretsBase file://~/.mcp/github`
  - Example: `--secretsBase file://~/.mcp/outlook`
- Cloud/KMS – use scy EncodedResource patterns to load secrets and pair with AFS URLs for storage
  - Example: `-o gcp://secretmanager/projects/<proj>/secrets/idp|blowfish://default`

Layout is namespaced to enforce user isolation:
- GitHub tokens: `<secretsBase>/github/<ns>/<alias>/<domain>[/<owner>/<repo>]/token`
- Outlook auth record: `<secretsBase>/outlook/<ns>/<alias>/auth_record.json`

BFF notes
- The servers use the default Backend‑For‑Frontend (BFF) header (`X-Authorization-Exchange`) and cookie (`BFF-Auth-Session`) just like mcp-sqlkit. No custom redirect URI is required; clients should follow the initial 401 challenge, complete the exchange, and retain the cookie for subsequent `/mcp` calls.

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
