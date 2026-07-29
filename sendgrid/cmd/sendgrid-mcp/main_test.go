package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	flags "github.com/jessevdk/go-flags"
	sendgridauth "github.com/viant/mcp-toolbox/sendgrid/auth"
	sendgridsvc "github.com/viant/mcp-toolbox/sendgrid/service"
)

func TestValidateAuthMode(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{name: "inactive without oauth", opts: Options{}},
		{name: "active without oauth", opts: Options{HTTPAddr: ":7792"}, wantErr: true},
		{name: "active OAuth without ID token", opts: Options{HTTPAddr: ":7792", Oauth2Config: "oauth.enc"}, wantErr: true},
		{name: "active with verified ID token", opts: Options{HTTPAddr: ":7792", Oauth2Config: "oauth.enc", UseIdToken: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAuthMode(test.opts)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateAuthMode error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHardenSendGridHTTPServerConfiguresTimeouts(t *testing.T) {
	server := &http.Server{Handler: http.NotFoundHandler()}
	if got := hardenSendGridHTTPServer(server); got != server {
		t.Fatal("hardenSendGridHTTPServer returned a different server")
	}
	if server.ReadHeaderTimeout != sendGridReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", server.ReadHeaderTimeout, sendGridReadHeaderTimeout)
	}
	if server.ReadTimeout != sendGridReadTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", server.ReadTimeout, sendGridReadTimeout)
	}
	if server.IdleTimeout != sendGridIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", server.IdleTimeout, sendGridIdleTimeout)
	}
	if sendGridMaxRequestBodyBytes <= int64(base64.StdEncoding.EncodedLen(21_000_000)) {
		t.Fatalf("request body limit %d does not accommodate the maximum base64 attachment", sendGridMaxRequestBodyBytes)
	}
}

func TestSendGridRequestBodyLimitRejectsOversizedPOST(t *testing.T) {
	t.Run("known Content-Length", func(t *testing.T) {
		var called bool
		handler := sendGridRequestBodyLimit(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			called = true
			response.WriteHeader(http.StatusNoContent)
		}))
		request := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		request.ContentLength = sendGridMaxRequestBodyBytes + 1
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", response.Code)
		}
		if called {
			t.Fatal("oversized request reached the downstream OAuth/MCP handler")
		}
	})

	t.Run("unknown Content-Length", func(t *testing.T) {
		handler := sendGridRequestBodyLimit(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			_, err := io.Copy(io.Discard, request.Body)
			var maxBytesError *http.MaxBytesError
			if !errors.As(err, &maxBytesError) {
				t.Fatalf("request body read error = %v, want *http.MaxBytesError", err)
			}
			http.Error(response, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		}))
		body := io.LimitReader(zeroReader{}, sendGridMaxRequestBodyBytes+1)
		request := httptest.NewRequest(http.MethodPost, "/mcp", body)
		request.ContentLength = -1
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", response.Code)
		}
	})
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestVerifiedOAuthMiddlewareValidatesBFFInjectedToken(t *testing.T) {
	outerOAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			request.Header.Set("Authorization", "Bearer bff-id-token")
			next.ServeHTTP(response, request)
		})
	}
	verifier := &commandTokenVerifier{claims: map[string]any{"sub": "verified-user"}}
	handler := verifiedOAuthMiddleware(outerOAuth, verifier)(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		claims, ok := sendgridauth.VerifiedClaimsFromContext(request.Context())
		if !ok || claims["sub"] != "verified-user" {
			t.Fatalf("missing verified claims: %#v", claims)
		}
		response.WriteHeader(http.StatusNoContent)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if response.Code != http.StatusNoContent || verifier.token != "bff-id-token" {
		t.Fatalf("unexpected result: status=%d token=%q", response.Code, verifier.token)
	}
}

type commandTokenVerifier struct {
	claims map[string]any
	token  string
}

func (v *commandTokenVerifier) Verify(_ context.Context, token string) (map[string]any, error) {
	v.token = token
	return v.claims, nil
}

func TestApplyOptionDefaultsIgnoresSendGridRegionEnvironment(t *testing.T) {
	t.Setenv("SENDGRID_REGION", "eu")
	opts := Options{}
	applyOptionDefaults(&opts)
	if opts.Region != "global" {
		t.Fatalf("region = %q, want global", opts.Region)
	}

	opts.Region = "eu"
	applyOptionDefaults(&opts)
	if opts.Region != "eu" {
		t.Fatalf("explicit region was overwritten: %q", opts.Region)
	}
}

func TestServiceConfigFromOptions(t *testing.T) {
	t.Setenv("SENDGRID_API_KEY", " SG.test ")
	t.Setenv("HOME", filepath.Join(string(os.PathSeparator), "tmp", "sendgrid-home"))
	opts := Options{
		APIKeyRef:               "file:///tmp/sendgrid-api-key.enc|blowfish://default",
		Region:                  "global",
		ScratchpadRootURI:       "file://$HOME/scratchpad/${userID}",
		AttachmentSourceSchemes: "scratchpad,gs,scratchpad",
		ScratchpadTargetSchemes: "file,gs",
		MaxConcurrentSends:      3,
		SendTimeout:             "45s",
	}
	cfg, err := serviceConfigFromOptions(opts)
	if err != nil {
		t.Fatalf("serviceConfigFromOptions failed: %v", err)
	}
	if string(cfg.APIKeyRef) != opts.APIKeyRef || cfg.Region != "global" || cfg.MaxConcurrentSends != 3 || cfg.SendTimeout != 45*time.Second {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if len(cfg.AttachmentSourceSchemes) != 2 || cfg.AttachmentSourceSchemes[0] != "scratchpad" || cfg.AttachmentSourceSchemes[1] != "gs" {
		t.Fatalf("unexpected source schemes: %#v", cfg.AttachmentSourceSchemes)
	}
	if cfg.ScratchpadRootURI != "file:///tmp/sendgrid-home/scratchpad/${userID}" {
		t.Fatalf("scratchpad root = %q", cfg.ScratchpadRootURI)
	}

	opts.SendTimeout = "invalid"
	if _, err := serviceConfigFromOptions(opts); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}

func TestServiceConfigIgnoresLegacyAPIKeyEnvironment(t *testing.T) {
	t.Setenv("SENDGRID_API_KEY", "SG.legacy-plaintext")
	cfg, err := serviceConfigFromOptions(Options{SendTimeout: "60s"})
	if err != nil {
		t.Fatalf("serviceConfigFromOptions failed: %v", err)
	}
	if cfg.APIKeyRef != "" {
		t.Fatalf("legacy environment unexpectedly populated api-key-ref")
	}
	_, err = sendgridsvc.NewService(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "api-key-ref is required") {
		t.Fatalf("NewService error = %v, want mandatory api-key-ref", err)
	}
}

func TestOptionsParseIndependentSendGridFlags(t *testing.T) {
	var opts Options
	args := []string{
		"--addr", ":7792",
		"--api-key-ref", "file:///tmp/sendgrid-api-key.enc|blowfish://default",
		"--oauth2config", "oauth.enc",
		"--use-id-token",
		"--jwt-issuer", "https://issuer.example",
		"--jwt-jwks-url", "https://issuer.example/jwks",
		"--jwt-audience", "sendgrid-client",
		"--jwt-algorithms", "RS256,RS512",
		"--region", "eu",
		"--namespace-claim-keys", "sub,email",
		"--max-concurrent-sends", "7",
		"--send-timeout", "30s",
	}
	if _, err := flags.NewParser(&opts, flags.Default).ParseArgs(args); err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if opts.HTTPAddr != ":7792" || opts.APIKeyRef != "file:///tmp/sendgrid-api-key.enc|blowfish://default" ||
		opts.Oauth2Config != "oauth.enc" || !opts.UseIdToken || opts.Region != "eu" ||
		opts.JWTIssuer != "https://issuer.example" || opts.JWTJWKSURL != "https://issuer.example/jwks" ||
		opts.JWTAudience != "sendgrid-client" || opts.JWTAlgorithms != "RS256,RS512" ||
		opts.NamespaceClaimKeys != "sub,email" || opts.MaxConcurrentSends != 7 || opts.SendTimeout != "30s" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}
