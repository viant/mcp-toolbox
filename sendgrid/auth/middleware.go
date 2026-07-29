package auth

import (
	"context"
	"net/http"
	"strings"
)

type verifiedClaimsContextKey struct{}

// ContextWithVerifiedClaims records claims that have already passed signature
// and standard OIDC validation.
func ContextWithVerifiedClaims(ctx context.Context, claims map[string]any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(claims) == 0 {
		return ctx
	}
	return context.WithValue(ctx, verifiedClaimsContextKey{}, cloneClaims(claims))
}

// VerifiedClaimsFromContext returns claims established by the strict bearer
// middleware. Raw bearer tokens are intentionally not parsed here.
func VerifiedClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(verifiedClaimsContextKey{}).(map[string]any)
	if !ok || len(claims) == 0 {
		return nil, false
	}
	return cloneClaims(claims), true
}

// VerifiedBearerMiddleware validates any bearer header supplied by the caller
// or injected by the BFF middleware. Requests without a header continue so the
// outer OAuth middleware can initiate its normal authorization challenge.
func VerifiedBearerMiddleware(verifier TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			header := strings.TrimSpace(request.Header.Get("Authorization"))
			if header == "" {
				next.ServeHTTP(response, request)
				return
			}
			rawToken, ok := bearerToken(header)
			if !ok || verifier == nil {
				writeUnauthorized(response)
				return
			}
			claims, err := verifier.Verify(request.Context(), rawToken)
			if err != nil {
				writeUnauthorized(response)
				return
			}
			ctx := ContextWithVerifiedClaims(request.Context(), claims)
			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func writeUnauthorized(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	http.Error(response, "Unauthorized", http.StatusUnauthorized)
}

func cloneClaims(claims map[string]any) map[string]any {
	result := make(map[string]any, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result
}
