package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	mcpsrv "github.com/viant/mcp/server"
	serverauth "github.com/viant/mcp/server/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
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

func TestParseCommandLineRedactsParserErrors(t *testing.T) {
	const marker = "parse-error-marker"
	var (
		opts    *Options
		failure *startupFailure
	)
	parserOutput := captureStderr(t, func() {
		opts, failure = parseCommandLine([]string{"--max-concurrent-sends", marker}, io.Discard)
	})

	if opts != nil {
		t.Fatalf("options = %#v, want nil after parse failure", opts)
	}
	if parserOutput != "" {
		t.Fatalf("parser wrote an unsafe diagnostic: %q", parserOutput)
	}
	if failure == nil || failure.stage != startupStageConfig {
		t.Fatalf("failure = %#v, want config stage", failure)
	}
	if failure.Error() != "invalid command-line configuration" {
		t.Fatalf("failure error = %q, want generic diagnostic", failure.Error())
	}
	if strings.Contains(failure.Error(), marker) {
		t.Fatalf("classified failure exposed parse marker: %q", failure)
	}

	var output bytes.Buffer
	logStartupFailure(log.New(&output, "", 0), failure)
	logged := output.String()
	if !strings.Contains(logged, `startup_failed service="sendgrid-mcp" version="0.1.0" stage=config error="invalid command-line configuration"`) {
		t.Fatalf("missing classified startup failure:\n%s", logged)
	}
	if strings.Contains(logged, marker) {
		t.Fatalf("startup failure exposed parse marker:\n%s", logged)
	}
}

func TestParseCommandLineHelpRemainsUsable(t *testing.T) {
	var (
		help    bytes.Buffer
		opts    *Options
		failure *startupFailure
	)
	parserOutput := captureStderr(t, func() {
		opts, failure = parseCommandLine([]string{"--help"}, &help)
	})

	if opts != nil || failure != nil {
		t.Fatalf("help returned options=%#v failure=%#v", opts, failure)
	}
	if parserOutput != "" {
		t.Fatalf("help wrote to stderr: %q", parserOutput)
	}
	if !strings.Contains(help.String(), "Usage:") || !strings.Contains(help.String(), "--region") {
		t.Fatalf("help output is incomplete:\n%s", help.String())
	}
	if strings.Contains(help.String(), "startup_failed") {
		t.Fatalf("help was treated as a startup failure:\n%s", help.String())
	}
}

func TestParseCommandLineScratchpadTargetSchemes(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantTargets string
		wantFailure bool
	}{
		{
			name: "omitted with scratchpad source",
			args: []string{"--attachment-source-schemes", "scratchpad"},
		},
		{
			name: "explicit empty",
			args: []string{"--attachment-source-schemes", "scratchpad", "--scratchpad-target-schemes", ""},
		},
		{
			name:        "restricted",
			args:        []string{"--attachment-source-schemes", "scratchpad", "--scratchpad-target-schemes", "file,gs"},
			wantTargets: "file,gs",
		},
		{
			name:        "bare flag",
			args:        []string{"--scratchpad-target-schemes"},
			wantFailure: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts, failure := parseCommandLine(test.args, io.Discard)
			if test.wantFailure {
				if opts != nil || failure == nil || failure.stage != startupStageConfig {
					t.Fatalf("parse result options=%#v failure=%#v, want config failure", opts, failure)
				}
				return
			}
			if failure != nil {
				t.Fatalf("parse failed: %v", failure)
			}
			if opts == nil || opts.ScratchpadTargetSchemes != test.wantTargets {
				t.Fatalf("target schemes = %q, want %q", opts.ScratchpadTargetSchemes, test.wantTargets)
			}
		})
	}
}

func TestStartupConfigLoggingNormalizesAndRedacts(t *testing.T) {
	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	deps := stubStartupDependencies()
	deps.loadOAuthConfig = func(context.Context, string) (*cred.Oauth2Config, error) {
		config := &cred.Oauth2Config{}
		config.ClientID = "oauth-client-id-marker"
		config.ClientSecret = "oauth-client-secret-marker"
		config.Endpoint.AuthURL = "https://authorization-url-marker.example/auth"
		config.Endpoint.TokenURL = "https://token-url-marker.example/token"
		return config, nil
	}

	failure := runWithDependencies(context.Background(), Options{
		APIKeyRef:               " file:///api-key-ref-marker|kms://api-kms-marker ",
		Oauth2Config:            " file:///oauth-ref-marker|kms://oauth-kms-marker ",
		UseIdToken:              true,
		JWTIssuer:               " https://issuer-marker.example ",
		JWTJWKSURL:              " https://jwks-marker.example/keys ",
		JWTAudience:             " audience-marker ",
		Region:                  " EU ",
		ScratchpadRootURI:       " GS://scratchpad-root-marker/users/${userID} ",
		AttachmentSourceSchemes: " ScratchPad, GS, scratchpad ",
		ScratchpadTargetSchemes: " FILE, gs, file ",
		NamespaceClaimKeys:      " sub, email,sub ",
		MaxConcurrentSends:      9,
		SendTimeout:             " 45s ",
	}, logger, deps)
	if failure != nil {
		t.Fatalf("runWithDependencies failed: %v", failure)
	}

	logged := output.String()
	want := strings.Join([]string{
		`startup_config service="sendgrid-mcp" version="0.1.0" listen_addr="" endpoint="/mcp" region="eu"`,
		`startup_auth enabled=true use_id_token=true`,
		`startup_scratchpad enabled=true scheme="gs" source_schemes="scratchpad,gs" target_schemes="file,gs" namespace_claim_keys="sub,email"`,
		`startup_limits max_concurrent_sends=9 send_timeout="45s"`,
	}, "\n")
	if got := strings.TrimSpace(logged); got != want {
		t.Errorf("startup configuration log mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	for _, event := range []string{"startup_config", "startup_auth", "startup_scratchpad", "startup_limits"} {
		if count := strings.Count(logged, event+" "); count != 1 {
			t.Errorf("%s count = %d, want 1:\n%s", event, count, logged)
		}
	}
	if strings.Contains(logged, "startup_ready") {
		t.Errorf("empty listen address emitted ready log:\n%s", logged)
	}
	for _, removed := range []string{"api_key_ref_configured", "oauth_configured"} {
		if strings.Contains(logged, removed) {
			t.Errorf("startup log contains removed field %q:\n%s", removed, logged)
		}
	}
	for _, secret := range []string{
		"api-key-ref-marker",
		"api-kms-marker",
		"oauth-ref-marker",
		"oauth-kms-marker",
		"scratchpad-root-marker",
		"oauth-client-id-marker",
		"oauth-client-secret-marker",
		"authorization-url-marker",
		"token-url-marker",
		"issuer-marker",
		"jwks-marker",
		"audience-marker",
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("startup log exposed %q:\n%s", secret, logged)
		}
	}
}

func TestStartupConfigLoggingEmitsDisabledScratchpad(t *testing.T) {
	var output bytes.Buffer
	failure := runWithDependencies(context.Background(), Options{
		APIKeyRef: "configured-api-key-ref",
	}, log.New(&output, "", 0), stubStartupDependencies())
	if failure != nil {
		t.Fatalf("runWithDependencies failed: %v", failure)
	}

	logged := output.String()
	want := strings.Join([]string{
		`startup_config service="sendgrid-mcp" version="0.1.0" listen_addr="" endpoint="/mcp" region="global"`,
		`startup_auth enabled=false use_id_token=false`,
		`startup_scratchpad enabled=false scheme="" source_schemes="" target_schemes="" namespace_claim_keys=""`,
		`startup_limits max_concurrent_sends=4 send_timeout="1m0s"`,
	}, "\n")
	if got := strings.TrimSpace(logged); got != want {
		t.Errorf("disabled scratchpad startup log mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	for _, event := range []string{"startup_config", "startup_auth", "startup_scratchpad", "startup_limits"} {
		if count := strings.Count(logged, event+" "); count != 1 {
			t.Errorf("%s count = %d, want 1:\n%s", event, count, logged)
		}
	}
}

func TestStartupCredentialDiagnosticsLogging(t *testing.T) {
	const apiKey = "SG.startup-diagnostic-test-key"
	apiKeyRef := encryptedCommandAPIKeyRef(t, " \t"+apiKey+"\r\n")
	digest := sha256.Sum256([]byte(apiKey))
	diagnostic := fmt.Sprintf(
		"credential_diagnostics loaded=true prefix_valid=true length=%d fingerprint=sha256:%s",
		len(apiKey),
		hex.EncodeToString(digest[:])[:16],
	)

	for _, test := range []struct {
		name     string
		disabled bool
	}{
		{name: "enabled by default"},
		{name: "explicitly disabled", disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := stubStartupDependencies()
			deps.newSendGridService = func(ctx context.Context, cfg sendgridsvc.Config) (*sendgridsvc.Service, error) {
				return sendgridsvc.NewService(ctx, cfg)
			}
			var output bytes.Buffer
			failure := runWithDependencies(context.Background(), Options{
				APIKeyRef:                    string(apiKeyRef),
				DisableCredentialDiagnostics: test.disabled,
			}, log.New(&output, "", 0), deps)
			if failure != nil {
				t.Fatalf("runWithDependencies failed: %v", failure)
			}

			logged := output.String()
			if strings.Contains(logged, apiKey) {
				t.Fatalf("startup log exposed the raw key:\n%s", logged)
			}
			if !test.disabled {
				if count := strings.Count(logged, diagnostic+"\n"); count != 1 {
					t.Fatalf("credential diagnostic count = %d, want 1:\n%s", count, logged)
				}
				return
			}
			for _, metadata := range []string{"credential_diagnostics", "loaded=", "prefix_valid=", "length=", "fingerprint="} {
				if strings.Contains(logged, metadata) {
					t.Fatalf("disabled startup diagnostics exposed %q:\n%s", metadata, logged)
				}
			}
		})
	}
}

func TestStartupConfigLoggingEmitsAllowAllScratchpadTargets(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{
			name: "omitted",
			args: []string{
				"--api-key-ref", "configured-api-key-ref",
				"--scratchpad-root-uri", "file:///scratchpad/${userID}",
				"--attachment-source-schemes", "scratchpad",
			},
		},
		{
			name: "explicit empty",
			args: []string{
				"--api-key-ref", "configured-api-key-ref",
				"--scratchpad-root-uri", "file:///scratchpad/${userID}",
				"--attachment-source-schemes", "scratchpad",
				"--scratchpad-target-schemes", "",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, parseFailure := parseCommandLine(test.args, io.Discard)
			if parseFailure != nil {
				t.Fatalf("parse failed: %v", parseFailure)
			}
			var output bytes.Buffer
			failure := runWithDependencies(context.Background(), *opts, log.New(&output, "", 0), stubStartupDependencies())
			if failure != nil {
				t.Fatalf("runWithDependencies failed: %v", failure)
			}

			want := `startup_scratchpad enabled=true scheme="file" source_schemes="scratchpad" target_schemes="*" namespace_claim_keys="email,sub"`
			if !strings.Contains(output.String(), want) {
				t.Fatalf("allow-all scratchpad startup log missing:\n%s", output.String())
			}
		})
	}
}

func TestInvalidRegionStartupFailureIsRedacted(t *testing.T) {
	const (
		regionMarker   = "invalid-region-marker"
		apiRefMarker   = "api-ref-marker"
		kmsRefMarker   = "kms-ref-marker"
		providerMarker = "provider-detail-marker"
	)
	deps := stubStartupDependencies()
	deps.newSendGridService = func(_ context.Context, cfg sendgridsvc.Config) (*sendgridsvc.Service, error) {
		if cfg.Region != regionMarker {
			t.Fatalf("service region = %q, want %q", cfg.Region, regionMarker)
		}
		return nil, fmt.Errorf(
			"invalid SendGrid region %q for %q via %s",
			cfg.Region,
			cfg.APIKeyRef,
			providerMarker,
		)
	}

	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	failure := runWithDependencies(context.Background(), Options{
		APIKeyRef: fmt.Sprintf(
			"file:///%s|kms://%s",
			apiRefMarker,
			kmsRefMarker,
		),
		Region: regionMarker,
	}, logger, deps)
	if failure == nil || failure.stage != startupStageSendGrid {
		t.Fatalf("failure = %#v, want sendgrid stage", failure)
	}
	if failure.Error() != "failed to initialize SendGrid service" {
		t.Fatalf("failure error = %q, want generic diagnostic", failure.Error())
	}
	logStartupFailure(logger, failure)

	logged := output.String()
	if strings.Contains(logged, "startup_config") {
		t.Fatalf("invalid SendGrid configuration emitted startup_config:\n%s", logged)
	}
	if !strings.Contains(logged, `stage=sendgrid error="failed to initialize SendGrid service"`) {
		t.Fatalf("missing safe SendGrid startup failure:\n%s", logged)
	}
	for _, marker := range []string{regionMarker, apiRefMarker, kmsRefMarker, providerMarker} {
		if strings.Contains(failure.Error()+"\n"+logged, marker) {
			t.Fatalf("SendGrid startup failure exposed %q:\nerror=%s\nlog=%s", marker, failure, logged)
		}
	}
}

func TestServeHTTPServerListenerConflictDoesNotLogReady(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener: %v", err)
	}
	defer occupied.Close()

	var output bytes.Buffer
	deps := defaultStartupDependencies()
	deps.serve = func(*http.Server, net.Listener) error {
		t.Fatal("Serve was called after listener bind failed")
		return nil
	}
	failure := serveHTTPServer(
		log.New(&output, "", 0),
		&http.Server{Addr: occupied.Addr().String(), Handler: http.NotFoundHandler()},
		deps,
	)
	if failure == nil || failure.stage != startupStageListener {
		t.Fatalf("failure = %#v, want listener stage", failure)
	}
	if strings.Contains(output.String(), "startup_ready") {
		t.Fatalf("listener conflict emitted ready log:\n%s", output.String())
	}
}

func TestServeHTTPServerLogsActualAddressAndHandlesErrServerClosed(t *testing.T) {
	var output bytes.Buffer
	var actualAddress string
	deps := defaultStartupDependencies()
	deps.serve = func(_ *http.Server, listener net.Listener) error {
		actualAddress = listener.Addr().String()
		return fmt.Errorf("wrapped shutdown: %w", http.ErrServerClosed)
	}

	failure := serveHTTPServer(
		log.New(&output, "", 0),
		&http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler()},
		deps,
	)
	if failure != nil {
		t.Fatalf("serveHTTPServer returned failure for ErrServerClosed: %v", failure)
	}
	if actualAddress == "" || strings.HasSuffix(actualAddress, ":0") {
		t.Fatalf("actual listener address = %q", actualAddress)
	}
	logged := output.String()
	if !strings.Contains(logged, fmt.Sprintf(`startup_ready service=%q version=%q listen_addr=%q endpoint=%q`,
		sendGridServiceName, sendGridVersion, actualAddress, sendGridEndpoint)) {
		t.Fatalf("ready log does not contain actual listener address:\n%s", logged)
	}
	if strings.Contains(logged, `listen_addr="127.0.0.1:0"`) {
		t.Fatalf("ready log contains requested ephemeral address instead of actual address:\n%s", logged)
	}
}

func TestStartupFailureStageClassification(t *testing.T) {
	validOptions := Options{APIKeyRef: "configured-api-key-ref", SendTimeout: "60s"}
	oauthOptions := validOptions
	oauthOptions.Oauth2Config = "configured-oauth-ref"
	oauthOptions.UseIdToken = true

	tests := []struct {
		name          string
		wantStage     startupStage
		forbiddenText string
		start         func(*log.Logger) *startupFailure
	}{
		{
			name:          "config",
			wantStage:     startupStageConfig,
			forbiddenText: "config-secret-marker",
			start: func(logger *log.Logger) *startupFailure {
				opts := validOptions
				opts.SendTimeout = "config-secret-marker"
				return runWithDependencies(context.Background(), opts, logger, stubStartupDependencies())
			},
		},
		{
			name:      "sendgrid",
			wantStage: startupStageSendGrid,
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.newSendGridService = func(context.Context, sendgridsvc.Config) (*sendgridsvc.Service, error) {
					return nil, errors.New("SendGrid configuration rejected")
				}
				return runWithDependencies(context.Background(), validOptions, logger, deps)
			},
		},
		{
			name:          "oauth secret load or type",
			wantStage:     startupStageOAuth,
			forbiddenText: "oauth-secret-ref-marker",
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.loadOAuthConfig = func(context.Context, string) (*cred.Oauth2Config, error) {
					return nil, errors.New("oauth-secret-ref-marker")
				}
				return runWithDependencies(context.Background(), oauthOptions, logger, deps)
			},
		},
		{
			name:          "oauth auth service",
			wantStage:     startupStageOAuth,
			forbiddenText: "oauth-client-secret-marker",
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.newAuthService = func(*serverauth.Config) (*serverauth.Service, error) {
					return nil, errors.New("oauth-client-secret-marker")
				}
				return runWithDependencies(context.Background(), oauthOptions, logger, deps)
			},
		},
		{
			name:          "oidc",
			wantStage:     startupStageOIDC,
			forbiddenText: "https://unsafe-oidc-marker.example",
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.newOIDCVerifier = func(context.Context, sendgridauth.OIDCConfig) (sendgridauth.TokenVerifier, error) {
					return nil, errors.New("https://unsafe-oidc-marker.example")
				}
				return runWithDependencies(context.Background(), oauthOptions, logger, deps)
			},
		},
		{
			name:      "server",
			wantStage: startupStageServer,
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.newMCPServer = func(...mcpsrv.Option) (*mcpsrv.Server, error) {
					return nil, errors.New("server construction failed")
				}
				return runWithDependencies(context.Background(), validOptions, logger, deps)
			},
		},
		{
			name:      "listener",
			wantStage: startupStageListener,
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.listen = func(string, string) (net.Listener, error) {
					return nil, errors.New("listener bind failed")
				}
				return serveHTTPServer(logger, &http.Server{Addr: "127.0.0.1:0"}, deps)
			},
		},
		{
			name:      "serve",
			wantStage: startupStageServe,
			start: func(logger *log.Logger) *startupFailure {
				deps := stubStartupDependencies()
				deps.serve = func(*http.Server, net.Listener) error {
					return errors.New("accept failed")
				}
				return serveHTTPServer(logger, &http.Server{Addr: "127.0.0.1:0"}, deps)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			failure := test.start(log.New(&output, "", 0))
			if failure == nil {
				t.Fatal("startup unexpectedly succeeded")
			}
			if failure.stage != test.wantStage {
				t.Fatalf("stage = %q, want %q (error: %v)", failure.stage, test.wantStage, failure)
			}
			if test.forbiddenText != "" && strings.Contains(failure.Error()+"\n"+output.String(), test.forbiddenText) {
				t.Fatalf("startup failure exposed %q:\nerror=%s\nlog=%s", test.forbiddenText, failure, output.String())
			}
		})
	}
}

func stubStartupDependencies() startupDependencies {
	deps := defaultStartupDependencies()
	deps.newSendGridService = func(context.Context, sendgridsvc.Config) (*sendgridsvc.Service, error) {
		return nil, nil
	}
	deps.loadOAuthConfig = func(context.Context, string) (*cred.Oauth2Config, error) {
		return &cred.Oauth2Config{}, nil
	}
	deps.newOIDCVerifier = func(context.Context, sendgridauth.OIDCConfig) (sendgridauth.TokenVerifier, error) {
		return &commandTokenVerifier{claims: map[string]any{"sub": "startup-test"}}, nil
	}
	deps.serve = func(*http.Server, net.Listener) error {
		return http.ErrServerClosed
	}
	return deps
}

func captureStderr(t *testing.T, action func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	previous := os.Stderr
	os.Stderr = writer
	defer func() {
		os.Stderr = previous
		_ = writer.Close()
		_ = reader.Close()
	}()

	action()
	os.Stderr = previous
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	captured, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(captured)
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
		APIKeyRef:                    "file:///tmp/sendgrid-api-key.enc|blowfish://default",
		Region:                       "global",
		ScratchpadRootURI:            "file://$HOME/scratchpad/${userID}",
		AttachmentSourceSchemes:      "scratchpad,gs,scratchpad",
		ScratchpadTargetSchemes:      "file,gs",
		MaxConcurrentSends:           3,
		SendTimeout:                  "45s",
		DisableCredentialDiagnostics: false,
	}
	cfg, err := serviceConfigFromOptions(opts)
	if err != nil {
		t.Fatalf("serviceConfigFromOptions failed: %v", err)
	}
	if string(cfg.APIKeyRef) != opts.APIKeyRef || !cfg.CredentialDiagnostics || cfg.Region != "global" || cfg.MaxConcurrentSends != 3 || cfg.SendTimeout != 45*time.Second {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if len(cfg.AttachmentSourceSchemes) != 2 || cfg.AttachmentSourceSchemes[0] != "scratchpad" || cfg.AttachmentSourceSchemes[1] != "gs" {
		t.Fatalf("unexpected source schemes: %#v", cfg.AttachmentSourceSchemes)
	}
	if cfg.ScratchpadRootURI != "file:///tmp/sendgrid-home/scratchpad/${userID}" {
		t.Fatalf("scratchpad root = %q", cfg.ScratchpadRootURI)
	}
	disabledOpts := opts
	disabledOpts.DisableCredentialDiagnostics = true
	disabledCfg, err := serviceConfigFromOptions(disabledOpts)
	if err != nil {
		t.Fatalf("serviceConfigFromOptions with diagnostics disabled failed: %v", err)
	}
	if disabledCfg.CredentialDiagnostics {
		t.Fatal("disabled CLI diagnostics mapped to enabled service diagnostics")
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
		"--disable-credential-diagnostics",
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
		opts.Oauth2Config != "oauth.enc" || !opts.UseIdToken || !opts.DisableCredentialDiagnostics || opts.Region != "eu" ||
		opts.JWTIssuer != "https://issuer.example" || opts.JWTJWKSURL != "https://issuer.example/jwks" ||
		opts.JWTAudience != "sendgrid-client" || opts.JWTAlgorithms != "RS256,RS512" ||
		opts.NamespaceClaimKeys != "sub,email" || opts.MaxConcurrentSends != 7 || opts.SendTimeout != "30s" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

func TestCredentialDiagnosticsCLICompatibilityAndPrecedence(t *testing.T) {
	for _, test := range []struct {
		name         string
		args         []string
		wantPositive bool
		wantDisabled bool
		wantEnabled  bool
	}{
		{name: "omitted defaults enabled", wantEnabled: true},
		{
			name:         "legacy positive accepted and enabled",
			args:         []string{"--credential-diagnostics"},
			wantPositive: true,
			wantEnabled:  true,
		},
		{
			name:         "disable flag disables",
			args:         []string{"--disable-credential-diagnostics"},
			wantDisabled: true,
		},
		{
			name:         "disable takes precedence over positive",
			args:         []string{"--credential-diagnostics", "--disable-credential-diagnostics"},
			wantPositive: true,
			wantDisabled: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, failure := parseCommandLine(test.args, io.Discard)
			if failure != nil || opts == nil {
				t.Fatalf("parse options failed: %v", failure)
			}
			if opts.CredentialDiagnostics != test.wantPositive {
				t.Fatalf("credential-diagnostics = %t, want %t", opts.CredentialDiagnostics, test.wantPositive)
			}
			if opts.DisableCredentialDiagnostics != test.wantDisabled {
				t.Fatalf("disable-credential-diagnostics = %t, want %t", opts.DisableCredentialDiagnostics, test.wantDisabled)
			}
			cfg, err := serviceConfigFromOptions(*opts)
			if err != nil {
				t.Fatalf("serviceConfigFromOptions failed: %v", err)
			}
			if cfg.CredentialDiagnostics != test.wantEnabled {
				t.Fatalf("effective credential diagnostics = %t, want %t", cfg.CredentialDiagnostics, test.wantEnabled)
			}
		})
	}
}

func encryptedCommandAPIKeyRef(t *testing.T, value string) scy.EncodedResource {
	t.Helper()
	target := "file://" + filepath.ToSlash(filepath.Join(t.TempDir(), "sendgrid-api-key.enc"))
	resource := scy.NewResource(nil, target, "blowfish://default")
	if err := scy.New().Store(context.Background(), scy.NewSecret(value, resource)); err != nil {
		t.Fatalf("encrypt test API key: %v", err)
	}
	return scy.EncodedResource(target + "|blowfish://default")
}
