# SendGrid MCP

`sendgrid-mcp` is an independent outbound-email MCP server. It does not import,
modify, or share provider state with `outlook-mcp`.

## Prerequisites

- A SendGrid API key with Mail Send permission.
- A sender address or domain verified in SendGrid. The `from` value supplied to
  the tool must use that verified identity.
- The `scy` CLI when creating a local encrypted API-key resource.

## SendGrid API key

The API key must be supplied through the `--api-key-ref` flag as an encrypted
[`scy.EncodedResource`](https://github.com/viant/scy):

```text
<source URL>|<KMS key>
```

Both parts are mandatory. There is no `SENDGRID_API_KEY` environment-variable
support and no plaintext fallback.

### Create the local encrypted key

The following command creates an encrypted resource in the current user's home
directory. `scy secure` reads the API key interactively without echoing it and
asks for it twice:

```bash
mkdir -p "${HOME}/.secret"
chmod 700 "${HOME}/.secret"

scy secure \
  --dest "file://${HOME}/.secret/sendgrid-api-key.enc" \
  --key 'blowfish://default' \
  --target raw

chmod 600 "${HOME}/.secret/sendgrid-api-key.enc"
```

Do not pass the API key as a command argument, keep it in a temporary plaintext
file, or use `scy reveal` merely to verify it. Those approaches can expose the
secret through shell history, process listings, files, or terminal logs.

## Run locally

Run this command from the `mcp-toolbox` repository root:

```bash
go run ./sendgrid/cmd/sendgrid-mcp \
  --addr :7792 \
  --api-key-ref "file://${HOME}/.secret/sendgrid-api-key.enc|blowfish://default" \
  --region global \
  --oauth2config 'oauth2-config.enc|blowfish://default' \
  --use-id-token \
  --scratchpad-root-uri 'file://$HOME/.local/share/mcp-toolbox/scratchpad/${userID}' \
  --attachment-source-schemes scratchpad \
  --namespace-claim-keys sub,email
```

The streamable HTTP endpoint is:

```text
http://localhost:7792/mcp
```

An active HTTP listener requires both `--oauth2config` and `--use-id-token`.
The OAuth/BFF configuration authenticates the MCP caller and supplies the
identity used for per-user scratchpad paths. The API key loaded through
`--api-key-ref` authenticates only the server-to-SendGrid request.

ID-token signatures, issuer, audience, expiry, issued-at, subject,
authorized-party, and not-before claims are verified before tool or scratchpad
access. The issuer and JWKS URL normally come from OIDC discovery.
`--jwt-issuer`, `--jwt-jwks-url`, and `--jwt-audience` can provide explicit
overrides where required. `--jwt-algorithms` controls the comma-separated
allowlist of signing algorithms and defaults to `RS256`.

## Configuration

Important flags:

| Flag | Purpose | Default |
| --- | --- | --- |
| `--addr` | HTTP listen address; an empty value disables HTTP | empty |
| `--api-key-ref` | Encrypted SendGrid API-key resource | required |
| `--credential-diagnostics` | Enable secret-safe API-key metadata in startup logs and rejected provider responses | `false` |
| `--disable-credential-diagnostics` | Explicitly disable secret-safe API-key metadata in startup logs and rejected provider responses | `false` |
| `--region` | SendGrid data-residency endpoint: `global` or `eu` | `global` |
| `--oauth2config` | OAuth2/BFF configuration as a `scy.EncodedResource` | required with active HTTP |
| `--use-id-token` | Use and verify the ID token for caller identity | required with active HTTP |
| `--jwt-issuer` | Expected ID-token issuer override | OIDC discovery value |
| `--jwt-jwks-url` | JWKS endpoint override | OIDC discovery value |
| `--jwt-audience` | Expected ID-token audience override | configured OAuth client ID |
| `--jwt-algorithms` | Comma-separated ID-token signing-algorithm allowlist | `RS256` |
| `--scratchpad-root-uri` | Per-user scratchpad root containing `${userID}` | empty |
| `--attachment-source-schemes` | Allowed attachment `sourceURL` schemes | none |
| `--scratchpad-target-schemes` | Optional allowlist for underlying scratchpad artifact URLs | all registered AFS provider schemes |
| `--namespace-claim-keys` | Identity-claim lookup order | `email,sub` |
| `--max-concurrent-sends` | Maximum concurrent resolve/build/send operations | `4` |
| `--send-timeout` | Timeout covering queueing, attachments, and SendGrid | `60s` |

Use `--region eu` for a SendGrid EU Data Residency account. The region is
configured only by the flag; `SENDGRID_REGION` is not supported.

## Secret sources and KMS

The server does not maintain its own allowlist of secret-source or KMS schemes.
It accepts implementations registered with AFS/scy at runtime. Standard AFS
file, HTTP(S), AWS, GCP, GS, and S3 source providers are registered by this
server. The shipped command currently registers `blowfish` as its KMS
implementation. Using another KMS requires registering its implementation in a
custom build. Unsupported or unavailable providers, malformed ciphertext, a
missing source URL or KMS part, and an empty decrypted value stop startup.

Examples:

```text
file:///home/example-user/.secret/sendgrid-api-key.enc|blowfish://default
gcp://secretmanager/projects/<gcp-project-id>/secrets/<secret-name>|blowfish://default
aws://secretmanager/<aws-region>/secret/<secret-name>|blowfish://default
```

The source is a deployment choice. For example, HTTP(S) is technically accepted
when its payload is encrypted, but the operator remains responsible for
transport security, access control, availability, auditability, and the chosen
KMS. `blowfish://default` is the KMS available in the shipped command. Protect
its key material and the encrypted resource with appropriate filesystem and
deployment controls. A production deployment can use a managed KMS only after
that KMS implementation has been registered in the built server.

To rotate the API key, run `scy secure` again for the destination or publish a
new secret version, then restart `sendgrid-mcp`. The decrypted key remains
private to the service process and is redacted from provider errors.

### Opt-in credential diagnostics

When credential diagnostics are enabled, the server writes the following stable
format to its startup log and appends the identical diagnostic to errors for
provider responses other than HTTP 202:

```text
credential_diagnostics loaded=true prefix_valid=true length=<bytes> fingerprint=sha256:<16 lowercase hex characters>
```

The fingerprint is calculated from the exact decrypted value used by the
SendGrid SDK after `strings.TrimSpace` normalization. It is the first 16
hexadecimal characters of the full SHA-256 digest. No characters from the API
key are included. Nevertheless, the fingerprint, length, and prefix result are
stable metadata that can correlate the same credential across logs and tool
results. Restrict access to those outputs. Credential diagnostics are disabled
by default. To enable generation and emission, pass the opt-in flag:

```bash
go run ./sendgrid/cmd/sendgrid-mcp \
  --api-key-ref "file://${HOME}/.secret/sendgrid-api-key.enc|blowfish://default" \
  --credential-diagnostics
```

Omitting both diagnostic flags leaves diagnostics disabled.
`--disable-credential-diagnostics` remains available as an explicit opt-out. If
both flags are supplied,
`--disable-credential-diagnostics` takes precedence and no diagnostic metadata
is generated or emitted. The `service.Config` zero value also keeps credential
diagnostics disabled, and programmatic callers must set
`CredentialDiagnostics: true` explicitly to enable them.

To compare a candidate key safely, run the following in an interactive shell.
The key is read without terminal echo and is sent to the Go program over stdin;
it is not placed in shell history, command arguments, the environment, or a
plaintext file. The program uses the same Go `strings.TrimSpace` operation as
the server:

```bash
fingerprint_dir=$(mktemp -d)
fingerprint_program="${fingerprint_dir}/main.go"
trap 'unset sendgrid_api_key; rm -rf "$fingerprint_dir"' EXIT

cat >"$fingerprint_program" <<'EOF'
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal("failed to read key")
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		log.Fatal("key is empty")
	}
	digest := sha256.Sum256([]byte(key))
	fmt.Printf(
		"credential_diagnostics loaded=true prefix_valid=%t length=%d fingerprint=sha256:%s\n",
		strings.HasPrefix(key, "SG."),
		len(key),
		hex.EncodeToString(digest[:])[:16],
	)
}
EOF

printf 'SendGrid API key: ' >&2
IFS= read -r -s sendgrid_api_key
printf '\n' >&2
printf '%s' "$sendgrid_api_key" | go run "$fingerprint_program"
unset sendgrid_api_key
rm -rf "$fingerprint_dir"
trap - EXIT
```

## Attachments and scratchpad

Attachment URL schemes are default-deny:

- `dataBase64` attachments do not require a source scheme.
- Every attachment `sourceURL` scheme must be listed in
  `--attachment-source-schemes`.
- `--attachment-source-schemes scratchpad` independently permits outer
  `scratchpad://` attachment URLs. Omitting `--scratchpad-target-schemes`, or
  passing `--scratchpad-target-schemes ""`, allows their artifacts to use any
  underlying `sourceURL` scheme supported by a registered AFS provider.
- For optional hardening, pass a non-empty target allowlist such as
  `--scratchpad-target-schemes file,gs`; artifact sources outside that list are
  rejected.
- A maximum of 10 attachments is accepted.
- Decoded attachments are limited to 21,000,000 bytes in total.
- The serialized SendGrid payload must be smaller than 29,000,000 bytes.

The authenticated identity is applied to `${userID}`, isolating scratchpad
artifacts between callers.

## Tool

The server exposes `sendgridSendMail`. At least one recipient source is
required: explicit addresses in `to`, the verified OIDC caller email through
`toCurrentUser: true`, or both. The server combines both sources and removes
case-insensitive duplicates before validation. At least one of `bodyText` or
`bodyHtml` is required. `importance` accepts `Low`, `Normal`, or `High`.

Example with a scratchpad attachment:

```json
{
  "from": "verified-sender@example.com",
  "fromName": "Example Service",
  "to": ["recipient@example.com"],
  "subject": "SendGrid attachment test",
  "bodyText": "Hello, please find the report attached.",
  "importance": "Normal",
  "attachments": [
    {
      "name": "report.pdf",
      "contentType": "application/pdf",
      "sourceURL": "scratchpad://artifact/report-123"
    }
  ]
}
```

A successful call returns `status: accepted` after SendGrid responds with HTTP
202, together with the resolved sender and recipient addresses. Acceptance does
not guarantee final delivery.
