package mcp

import (
	"context"
	"fmt"
	"strings"

	sendgridauth "github.com/viant/mcp-toolbox/sendgrid/auth"
	nsprov "github.com/viant/mcp/server/namespace"
)

type verifiedIdentityProvider struct {
	claimKeys []string
}

// NewVerifiedIdentityProvider creates a strict namespace provider that reads
// only claims placed in context after OIDC verification. It never parses the
// raw bearer token.
func NewVerifiedIdentityProvider(claimKeys []string) nsprov.Provider {
	return &verifiedIdentityProvider{
		claimKeys: NormalizeNamespaceClaimKeys(claimKeys),
	}
}

func (p *verifiedIdentityProvider) Namespace(ctx context.Context) (nsprov.Descriptor, error) {
	claims, ok := sendgridauth.VerifiedClaimsFromContext(ctx)
	if !ok {
		return nsprov.Descriptor{}, fmt.Errorf("verified caller claims are required")
	}
	for _, key := range p.claimKeys {
		value, ok := claims[key].(string)
		value = strings.TrimSpace(value)
		if ok && value != "" {
			return nsprov.Descriptor{Name: value, Kind: nsprov.KindIdentity}, nil
		}
	}
	return nsprov.Descriptor{}, fmt.Errorf("verified caller claims do not contain an identity")
}
