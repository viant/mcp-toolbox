package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const credentialDiagnosticsName = "credential_diagnostics"

// credentialDiagnostic contains only one-way or aggregate information about
// the normalized API key. It deliberately has no field or method that exposes
// the plaintext credential.
type credentialDiagnostic struct {
	loaded      bool
	prefixValid bool
	length      int
	fingerprint string
}

func newCredentialDiagnostic(apiKey string) *credentialDiagnostic {
	digest := sha256.Sum256([]byte(apiKey))
	return &credentialDiagnostic{
		loaded:      true,
		prefixValid: strings.HasPrefix(apiKey, "SG."),
		length:      len(apiKey),
		fingerprint: "sha256:" + hex.EncodeToString(digest[:])[:16],
	}
}

func (d *credentialDiagnostic) String() string {
	if d == nil {
		return ""
	}
	return fmt.Sprintf(
		"%s loaded=%t prefix_valid=%t length=%d fingerprint=%s",
		credentialDiagnosticsName,
		d.loaded,
		d.prefixValid,
		d.length,
		d.fingerprint,
	)
}
