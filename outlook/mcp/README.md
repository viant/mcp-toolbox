# Outlook MCP – Configuration

This service supports loading Azure OAuth2 client configuration from a scy resource using an EncodedResource string.

## Config fields

- `clientID`: Fallback Azure application (client) ID.
- `tenantID`: Fallback tenant ID.
- `storageDir`: Directory for auth records per account alias.
- `callbackBaseURL`: Base URL for device login page rendering.
- `useData` / `useText`: Output formatting flags.
- `azureRef`: scy EncodedResource to load `cred.Azure`.

## `azureRef` – EncodedResource

Format: `<URL>|<kmsKey>` where `<kmsKey>` is optional.

Examples:
- File: "~/.secret/azure.json|blowfish://default"
- GCP Secret Manager: "gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default"
- AWS Secrets Manager: "aws://secretmanager/us-west-2/secret/prod/azure-cred|blowfish://default"

The referenced content must unmarshal into `github.com/viant/scy/cred.Azure`.

## `cred.Azure` JSON schema

Use these JSON fields:
- `ClientID`: Azure app (client) ID.
- `TenantID`: Directory tenant ID (or `common`/`organizations`).
- `EncryptedClientSecret`: Base64 ciphertext of the client secret (optional). Use `ClientSecret` if not encrypted yet.

Examples:

Encrypted secret:
```json
{
  "ClientID": "00000000-0000-0000-0000-000000000000",
  "TenantID": "11111111-1111-1111-1111-111111111111",
  "EncryptedClientSecret": "BASE64_CIPHERTEXT"
}
```

Plain secret (only for initial storage/encryption):
```json
{
  "ClientID": "00000000-0000-0000-0000-000000000000",
  "TenantID": "11111111-1111-1111-1111-111111111111",
  "ClientSecret": "your-plaintext-secret"
}
```

YAML uses `tenantId` and `EncryptedSecret` instead of `TenantID`/`EncryptedClientSecret`.

## Start the server

Using flags:

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
# Optional: Tenant ID will be taken from the azureRef secret if not provided or if set to "organizations".
# export OUTLOOK_TENANT_ID=organizations
export OUTLOOK_AZURE_REF='gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default'
go run ./outlook/cmd/outlook-mcp -addr :7788 -storage "$HOME/.config/mcp-outlook"
```

## Behavior

- On startup, if `azureRef` is set, the service loads the secret via scy and applies `ClientID` from the secret. If absent, it uses `clientID` from config.
- If `tenantID` flag/env is empty or set to `organizations`, the server will use `TenantID` from the `azureRef` secret when available.
- Device Code flow is used for Microsoft Graph and auth records are saved under `storageDir`.

## Notes

- scy supports `file://`, `gcp://secretmanager`, and `aws://secretmanager` URLs out of the box. Azure Key Vault URLs are not yet available via scy; store the JSON in file/GCP/AWS.
- To encrypt the client secret, use scy with a KMS key (e.g., `blowfish://default`) and store the encrypted payload as shown above.

### Ship the config via scy CLI

1) Prepare `azure.json` per the schema above.

2) Encrypt and store using scy (target `azure`):

```
scy secure -s azure.json \
  -d gcp://secretmanager/projects/myproj/secrets/azure-cred \
  -k blowfish://default \
  -t azure
```

3) Reference it in the server flag or `OUTLOOK_AZURE_REF` env var:

```
-azure-ref "gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default"
```
