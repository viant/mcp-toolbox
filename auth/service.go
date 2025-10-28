package auth

import (
    "context"
    "fmt"

    "github.com/golang-jwt/jwt/v5"
    "github.com/viant/mcp-protocol/authorization"
)

// Service derives the caller namespace from a JWT carried in context.
// It falls back to DefaultNamespace when no token is present or extraction fails.
type Service struct {
    // DefaultNamespace is returned when no token is present or extractor fails.
    DefaultNamespace string
    // Parse turns a token string into jwt.MapClaims (unverified parse by default).
    Parse func(token string) (jwt.MapClaims, error)
    // Extract returns the namespace from claims; bool indicates success.
    Extract func(jwt.MapClaims) (string, bool)
}

// Namespace extracts the subject/email from an auth token placed in context by MCP auth middleware.
func (s *Service) Namespace(ctx context.Context) (string, error) {
    if s == nil {
        return "default", nil
    }
    tokenValue := ctx.Value(authorization.TokenKey)
    if tokenValue == nil {
        return s.DefaultNamespace, nil
    }
    var tokenString string
    switch tv := tokenValue.(type) {
    case string:
        tokenString = tv
    case *authorization.Token:
        tokenString = tv.Token
    default:
        return "", fmt.Errorf("unsupported token type %T", tokenValue)
    }
    if s.Parse != nil && s.Extract != nil {
        if claims, err := s.Parse(tokenString); err == nil {
            if ns, ok := s.Extract(claims); ok && ns != "" {
                return ns, nil
            }
        }
    }
    return s.DefaultNamespace, nil
}

// New returns a default Service that extracts "email" or "sub" without verification.
func New() *Service {
    return &Service{
        DefaultNamespace: "default",
        Parse: func(tokenString string) (jwt.MapClaims, error) {
            var claimMap jwt.MapClaims
            _, _, err := new(jwt.Parser).ParseUnverified(tokenString, &claimMap)
            return claimMap, err
        },
        Extract: func(mc jwt.MapClaims) (string, bool) {
            if email, _ := mc["email"].(string); email != "" {
                return email, true
            }
            if sub, _ := mc["sub"].(string); sub != "" {
                return sub, true
            }
            return "", false
        },
    }
}
