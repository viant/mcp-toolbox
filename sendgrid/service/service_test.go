package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sendgrid/sendgrid-go/helpers/mail"
	afsscratchpad "github.com/viant/afs/scratchpad"
	"github.com/viant/scy"
)

const testAPIKey = "SG.test-secret"

type fakeSender struct {
	mu       sync.Mutex
	calls    int
	messages []*mail.SGMailV3
	response *providerResponse
	err      error
	send     func(context.Context, *mail.SGMailV3) (*providerResponse, error)
}

func (f *fakeSender) Send(ctx context.Context, message *mail.SGMailV3) (*providerResponse, error) {
	f.mu.Lock()
	f.calls++
	f.messages = append(f.messages, message)
	send := f.send
	response := f.response
	err := f.err
	f.mu.Unlock()
	if send != nil {
		return send(ctx, message)
	}
	if response == nil && err == nil {
		response = acceptedResponse("test-message-id")
	}
	return response, err
}

func (f *fakeSender) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSender) lastMessage() *mail.SGMailV3 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) == 0 {
		return nil
	}
	return f.messages[len(f.messages)-1]
}

func acceptedResponse(messageID string) *providerResponse {
	headers := http.Header{}
	if messageID != "" {
		headers.Set("X-Message-Id", messageID)
	}
	return &providerResponse{StatusCode: http.StatusAccepted, Headers: headers}
}

func encryptedAPIKeyRef(t *testing.T, value string) scy.EncodedResource {
	t.Helper()
	target := "file://" + filepath.ToSlash(filepath.Join(t.TempDir(), "sendgrid-api-key.enc"))
	resource := scy.NewResource(nil, target, "blowfish://default")
	if err := scy.New().Store(context.Background(), scy.NewSecret(value, resource)); err != nil {
		t.Fatalf("encrypt test API key: %v", err)
	}
	return scy.EncodedResource(target + "|blowfish://default")
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		APIKeyRef:          encryptedAPIKeyRef(t, testAPIKey),
		Region:             "global",
		MaxConcurrentSends: 4,
		SendTimeout:        time.Second,
	}
}

func validInput() *SendEmailInput {
	return &SendEmailInput{
		From:     "sender@example.com",
		To:       []string{"alice@example.com"},
		Subject:  "Status",
		BodyText: "All green.",
	}
}

func newTestService(t *testing.T, cfg Config, fake *fakeSender, options ...Option) *Service {
	t.Helper()
	options = append([]Option{withSender(fake)}, options...)
	result, err := NewService(context.Background(), cfg, options...)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	return result
}

func TestNewServiceValidatesConfiguration(t *testing.T) {
	invalidRegion := testConfig(t)
	invalidRegion.Region = "mars"
	invalidConcurrency := testConfig(t)
	invalidConcurrency.MaxConcurrentSends = -1
	invalidTimeout := testConfig(t)
	invalidTimeout.SendTimeout = -time.Second

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "missing key ref", cfg: Config{}, want: "api-key-ref is required"},
		{name: "missing resource URL", cfg: Config{APIKeyRef: "|blowfish://default"}, want: "resource URL is required"},
		{name: "missing KMS key", cfg: Config{APIKeyRef: "file:///unused"}, want: "KMS key is required"},
		{name: "invalid region", cfg: invalidRegion, want: "expected global or eu"},
		{name: "invalid concurrency", cfg: invalidConcurrency, want: "greater than zero"},
		{name: "invalid timeout", cfg: invalidTimeout, want: "greater than zero"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewService(context.Background(), test.cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewService error = %v, want containing %q", err, test.want)
			}
		})
	}

	cfg := Config{
		APIKeyRef: encryptedAPIKeyRef(t, testAPIKey),
		Region:    " EU ",
	}
	service, err := NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected normalized EU region: %v", err)
	}
	if service.cfg.Region != "eu" {
		t.Fatalf("region = %q, want eu", service.cfg.Region)
	}
	if service.cfg.MaxConcurrentSends != DefaultMaxConcurrentSends || service.cfg.SendTimeout != DefaultSendTimeout {
		t.Fatalf("defaults were not applied: %#v", service.cfg)
	}
}

func TestNewServiceAllowsUnrestrictedScratchpadTargets(t *testing.T) {
	tests := []struct {
		name          string
		targetSchemes []string
	}{
		{name: "omitted"},
		{name: "explicit empty", targetSchemes: []string{""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.AttachmentSourceSchemes = []string{"scratchpad"}
			cfg.ScratchpadTargetSchemes = test.targetSchemes

			service, err := NewService(context.Background(), cfg)
			if err != nil {
				t.Fatalf("NewService rejected unrestricted scratchpad targets: %v", err)
			}
			if len(service.cfg.ScratchpadTargetSchemes) != 0 {
				t.Fatalf("normalized target schemes = %#v, want empty", service.cfg.ScratchpadTargetSchemes)
			}
		})
	}
}

func TestNewServiceLoadsEncryptedAPIKey(t *testing.T) {
	cfg := testConfig(t)
	service, err := NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if service.apiKey != testAPIKey {
		t.Fatalf("decrypted API key was not retained by the service")
	}
}

func TestCredentialDiagnosticFormatAndPrefix(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "valid prefix", key: "SG.valid-prefix-test-key"},
		{name: "invalid prefix", key: "not-a-sendgrid-key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := newCredentialDiagnostic(test.key).String()
			want := expectedCredentialDiagnostic(test.key)
			if got != want {
				t.Fatalf("credential diagnostic = %q, want %q", got, want)
			}
			if strings.Contains(got, test.key) {
				t.Fatalf("credential diagnostic exposed the raw key: %q", got)
			}
		})
	}
}

func TestCredentialDiagnosticUsesNormalizedSDKAPIKey(t *testing.T) {
	const rawAPIKey = " \t\nSG.normalized-test-key\r\n "
	normalizedAPIKey := strings.TrimSpace(rawAPIKey)
	cfg := testConfig(t)
	cfg.APIKeyRef = encryptedAPIKeyRef(t, rawAPIKey)
	cfg.CredentialDiagnostics = true

	service, err := NewService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	sdk, ok := service.sender.(*sdkSender)
	if !ok {
		t.Fatalf("sender type = %T, want *sdkSender", service.sender)
	}
	if service.apiKey != normalizedAPIKey || sdk.apiKey != normalizedAPIKey {
		t.Fatal("service, diagnostic, and SDK did not share the normalized API key")
	}
	got := service.CredentialDiagnostics()
	want := expectedCredentialDiagnostic(normalizedAPIKey)
	if got != want {
		t.Fatalf("credential diagnostic = %q, want %q", got, want)
	}
	if strings.Contains(got, normalizedAPIKey) {
		t.Fatalf("credential diagnostic exposed the raw key: %q", got)
	}
}

func TestNewServiceRejectsInvalidEncryptedAPIKeyResources(t *testing.T) {
	encrypted := testConfig(t)
	sourceURL := strings.SplitN(string(encrypted.APIKeyRef), "|", 2)[0]

	invalidCiphertextPath := filepath.Join(t.TempDir(), "invalid.enc")
	if err := os.WriteFile(invalidCiphertextPath, []byte("bad"), 0o600); err != nil {
		t.Fatalf("write invalid ciphertext: %v", err)
	}

	tests := []struct {
		name string
		ref  scy.EncodedResource
		want string
	}{
		{
			name: "unsupported KMS",
			ref:  scy.EncodedResource(sourceURL + "|unsupported-kms://key"),
			want: "failed to load encrypted SendGrid API key",
		},
		{
			name: "unsupported source",
			ref:  "unsupported-source://secret|blowfish://default",
			want: "failed to load encrypted SendGrid API key",
		},
		{
			name: "invalid ciphertext",
			ref:  scy.EncodedResource("file://" + filepath.ToSlash(invalidCiphertextPath) + "|blowfish://default"),
			want: "failed to load encrypted SendGrid API key",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewService(context.Background(), Config{APIKeyRef: test.ref})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewService error = %v, want containing %q", err, test.want)
			}
			if strings.Contains(err.Error(), string(test.ref)) {
				t.Fatalf("startup error leaked api-key-ref: %v", err)
			}
		})
	}

	_, err := NewService(context.Background(), Config{
		APIKeyRef: encryptedAPIKeyRef(t, " \t\n "),
	})
	if err == nil || !strings.Contains(err.Error(), "decrypted SendGrid API key is empty") {
		t.Fatalf("empty decrypted key error = %v", err)
	}
}

func TestNewServiceLoadsEncryptedAPIKeyFromHTTP(t *testing.T) {
	localRef := encryptedAPIKeyRef(t, testAPIKey)
	localURL := strings.SplitN(string(localRef), "|", 2)[0]
	ciphertext, err := os.ReadFile(strings.TrimPrefix(localURL, "file://"))
	if err != nil {
		t.Fatalf("read encrypted API key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(ciphertext)
	}))
	defer server.Close()

	service, err := NewService(context.Background(), Config{
		APIKeyRef: scy.EncodedResource(server.URL + "|blowfish://default"),
	})
	if err != nil {
		t.Fatalf("NewService failed for HTTP source: %v", err)
	}
	if service.apiKey != testAPIKey {
		t.Fatal("HTTP-loaded API key did not decrypt correctly")
	}
}

func TestSendBuildsMessageAndReturnsAccepted(t *testing.T) {
	fake := &fakeSender{response: acceptedResponse("provider-123")}
	service := newTestService(t, testConfig(t), fake)
	input := &SendEmailInput{
		From:       "sender@example.com",
		FromName:   "Example Service",
		To:         []string{"alice@example.com", "bob@example.com"},
		Subject:    "Report",
		BodyText:   "Plain",
		BodyHTML:   "<strong>HTML</strong>",
		Importance: "High",
		Attachments: []EmailAttachment{{
			Name:        "report.pdf",
			ContentType: "application/pdf",
			DataBase64:  " cGRm\nLWRhdGE= ",
		}},
	}

	output, err := service.Send(context.Background(), input)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if output.Status != "accepted" || output.Provider != "sendgrid" || output.StatusCode != http.StatusAccepted || output.MessageID != "provider-123" {
		t.Fatalf("unexpected output: %#v", output)
	}
	message := fake.lastMessage()
	if message == nil {
		t.Fatal("provider did not receive a message")
	}
	if message.From.Address != input.From || message.From.Name != input.FromName || message.Subject != input.Subject {
		t.Fatalf("unexpected sender/subject: %#v", message)
	}
	if len(message.Personalizations) != 1 || len(message.Personalizations[0].To) != 2 {
		t.Fatalf("unexpected recipients: %#v", message.Personalizations)
	}
	if len(message.Content) != 2 || message.Content[0].Type != "text/plain" || message.Content[1].Type != "text/html" {
		t.Fatalf("unexpected body content: %#v", message.Content)
	}
	if message.Headers["Importance"] != "high" || message.Headers["X-Priority"] != "1" {
		t.Fatalf("unexpected importance headers: %#v", message.Headers)
	}
	if len(message.Attachments) != 1 {
		t.Fatalf("unexpected attachments: %#v", message.Attachments)
	}
	attachment := message.Attachments[0]
	if attachment.Filename != "report.pdf" || attachment.Name != "" || attachment.Type != "application/pdf" || attachment.Disposition != "attachment" {
		t.Fatalf("unexpected SendGrid attachment mapping: %#v", attachment)
	}
	if attachment.Content != base64.StdEncoding.EncodeToString([]byte("pdf-data")) {
		t.Fatalf("unexpected attachment content: %q", attachment.Content)
	}
}

func TestSendValidatesInputsBeforeProvider(t *testing.T) {
	tooMany := make([]EmailAttachment, MaxAttachments+1)
	for i := range tooMany {
		tooMany[i] = EmailAttachment{Name: "a.txt", DataBase64: "YQ=="}
	}
	tests := []struct {
		name   string
		mutate func(*SendEmailInput)
		want   string
	}{
		{name: "missing from", mutate: func(in *SendEmailInput) { in.From = "" }, want: "from is required"},
		{name: "invalid from", mutate: func(in *SendEmailInput) { in.From = "Sender <sender@example.com>" }, want: "bare email"},
		{name: "missing to", mutate: func(in *SendEmailInput) { in.To = nil }, want: "at least one"},
		{name: "invalid recipient", mutate: func(in *SendEmailInput) { in.To = []string{"bad"} }, want: "valid bare email"},
		{name: "missing subject", mutate: func(in *SendEmailInput) { in.Subject = "" }, want: "subject is required"},
		{name: "missing body", mutate: func(in *SendEmailInput) { in.BodyText = ""; in.BodyHTML = "" }, want: "bodyText or bodyHtml"},
		{name: "invalid importance", mutate: func(in *SendEmailInput) { in.Importance = "urgent" }, want: "Low, Normal, or High"},
		{name: "too many attachments", mutate: func(in *SendEmailInput) { in.Attachments = tooMany }, want: "at most 10"},
		{name: "missing attachment source", mutate: func(in *SendEmailInput) {
			in.Attachments = []EmailAttachment{{Name: "a.txt"}}
		}, want: "exactly one"},
		{name: "both attachment sources", mutate: func(in *SendEmailInput) {
			in.Attachments = []EmailAttachment{{Name: "a.txt", DataBase64: "YQ==", SourceURL: "file:///tmp/a"}}
		}, want: "exactly one"},
		{name: "invalid attachment base64", mutate: func(in *SendEmailInput) {
			in.Attachments = []EmailAttachment{{Name: "a.txt", DataBase64: "%%%"}}
		}, want: "invalid dataBase64"},
		{name: "attachment filename newline", mutate: func(in *SendEmailInput) {
			in.Attachments = []EmailAttachment{{Name: "a\r\n.txt", DataBase64: "YQ=="}}
		}, want: "invalid newline"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeSender{}
			service := newTestService(t, testConfig(t), fake)
			input := validInput()
			test.mutate(input)
			_, err := service.Send(context.Background(), input)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) || !strings.Contains(validationErr.Error(), test.want) {
				t.Fatalf("Send error = %v, want validation error containing %q", err, test.want)
			}
			if fake.callCount() != 0 {
				t.Fatalf("provider was called %d times", fake.callCount())
			}
		})
	}
}

func TestSendEnforcesAttachmentAndPayloadLimits(t *testing.T) {
	t.Run("decoded attachments", func(t *testing.T) {
		fake := &fakeSender{}
		service := newTestService(t, testConfig(t), fake, WithLimits(4, 100_000))
		input := validInput()
		input.Attachments = []EmailAttachment{{
			Name:       "five.bin",
			DataBase64: base64.StdEncoding.EncodeToString([]byte("12345")),
		}}
		_, err := service.Send(context.Background(), input)
		if err == nil || !strings.Contains(err.Error(), "4 byte limit") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("decoded attachment at exact limit", func(t *testing.T) {
		fake := &fakeSender{}
		service := newTestService(t, testConfig(t), fake, WithLimits(4, 100_000))
		input := validInput()
		input.Attachments = []EmailAttachment{{
			Name:       "four.bin",
			DataBase64: base64.StdEncoding.EncodeToString([]byte("1234")),
		}}
		if _, err := service.Send(context.Background(), input); err != nil {
			t.Fatalf("Send rejected an attachment at the exact limit: %v", err)
		}
	})

	t.Run("whitespace does not bypass inline bound", func(t *testing.T) {
		fake := &fakeSender{}
		service := newTestService(t, testConfig(t), fake, WithLimits(4, 100_000))
		input := validInput()
		input.Attachments = []EmailAttachment{{
			Name:       "five.bin",
			DataBase64: strings.Repeat(" \t\r\n", 10_000) + base64.StdEncoding.EncodeToString([]byte("12345")),
		}}
		_, err := service.Send(context.Background(), input)
		if err == nil || !strings.Contains(err.Error(), "4 byte limit") {
			t.Fatalf("unexpected error: %v", err)
		}
		if fake.callCount() != 0 {
			t.Fatal("provider was called for an oversized whitespace-padded attachment")
		}
	})

	t.Run("serialized payload", func(t *testing.T) {
		fake := &fakeSender{}
		service := newTestService(t, testConfig(t), fake, WithLimits(1000, 100))
		_, err := service.Send(context.Background(), validInput())
		if err == nil || !strings.Contains(err.Error(), "serialized message size") {
			t.Fatalf("unexpected error: %v", err)
		}
		if fake.callCount() != 0 {
			t.Fatal("provider was called for oversized payload")
		}
	})
}

func TestSendRejectsDisallowedSourceScheme(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		schemes []string
	}{
		{name: "default deny"},
		{name: "explicit scratchpad only", schemes: []string{"scratchpad"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.AttachmentSourceSchemes = testCase.schemes
			if len(testCase.schemes) > 0 {
				cfg.ScratchpadTargetSchemes = []string{"file"}
			}
			fake := &fakeSender{}
			service := newTestService(t, cfg, fake)
			input := validInput()
			input.Attachments = []EmailAttachment{{Name: "report.txt", SourceURL: "file:///tmp/report.txt"}}

			_, err := service.Send(context.Background(), input)
			if err == nil || !strings.Contains(err.Error(), `scheme "file" is not allowed`) {
				t.Fatalf("unexpected error: %v", err)
			}
			if fake.callCount() != 0 {
				t.Fatal("provider was called for a disallowed source")
			}
		})
	}
}

func TestScratchpadTargetAllowlistDoesNotEnableOuterSourceScheme(t *testing.T) {
	cfg := testConfig(t)
	cfg.ScratchpadTargetSchemes = []string{"file"}
	fake := &fakeSender{}
	service := newTestService(t, cfg, fake)
	input := validInput()
	input.Attachments = []EmailAttachment{{
		Name:      "report.txt",
		SourceURL: "scratchpad://artifact/report-1",
	}}

	_, err := service.Send(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), `scheme "scratchpad" is not allowed`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatal("provider was called when the outer scratchpad source scheme was disabled")
	}
}

func TestSendResolvesScratchpadWithRequestUserIsolation(t *testing.T) {
	rootDir := t.TempDir()
	rootURI := "file://" + filepath.ToSlash(filepath.Join(rootDir, "scratchpad", "${userID}"))
	cfg := testConfig(t)
	cfg.ScratchpadRootURI = rootURI
	cfg.AttachmentSourceSchemes = []string{"scratchpad"}

	aliceContext := afsscratchpad.ContextWithUserID(context.Background(), "alice@example.com")
	aliceScratchpad := afsscratchpad.New(
		afsscratchpad.WithRootURI(rootURI),
		afsscratchpad.WithAllowedTargetSchemes("file"),
	)
	reportPath := filepath.Join(rootDir, "alice-report.txt")
	if err := os.WriteFile(reportPath, []byte("alice report"), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	artifact, err := json.Marshal(afsscratchpad.Artifact{
		Kind:        "artifact",
		ArtifactID:  "report-1",
		Name:        "report.txt",
		ContentType: "text/plain",
		SourceURL:   "file://" + filepath.ToSlash(reportPath),
	})
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	if _, err = aliceScratchpad.Memorize(aliceContext, &afsscratchpad.MemorizeInput{
		Key:         afsscratchpad.ArtifactKey("report-1"),
		Description: "Alice report",
		Body:        string(artifact),
	}); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	fake := &fakeSender{}
	service := newTestService(t, cfg, fake)
	input := validInput()
	input.Attachments = []EmailAttachment{{
		Name:      "report.txt",
		SourceURL: "scratchpad://artifact/report-1",
	}}
	if _, err := service.Send(aliceContext, input); err != nil {
		t.Fatalf("alice send failed: %v", err)
	}
	message := fake.lastMessage()
	if got, want := message.Attachments[0].Content, base64.StdEncoding.EncodeToString([]byte("alice report")); got != want {
		t.Fatalf("attachment content = %q, want %q", got, want)
	}

	explicitEmptyConfig := cfg
	explicitEmptyConfig.ScratchpadTargetSchemes = []string{""}
	explicitEmptySender := &fakeSender{}
	explicitEmptyService := newTestService(t, explicitEmptyConfig, explicitEmptySender)
	if _, err := explicitEmptyService.Send(aliceContext, input); err != nil {
		t.Fatalf("send with explicit empty target allowlist failed: %v", err)
	}
	if explicitEmptySender.callCount() != 1 {
		t.Fatalf("provider calls with explicit empty target allowlist = %d, want 1", explicitEmptySender.callCount())
	}

	bobContext := afsscratchpad.ContextWithUserID(context.Background(), "bob@example.com")
	if _, err := service.Send(bobContext, input); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("bob error = %v, want isolated scratchpad failure", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1", fake.callCount())
	}

	blockedConfig := cfg
	blockedConfig.ScratchpadTargetSchemes = []string{"gs"}
	blockedSender := &fakeSender{}
	blockedService := newTestService(t, blockedConfig, blockedSender)
	if _, err := blockedService.Send(aliceContext, input); err == nil || !strings.Contains(err.Error(), `scheme "file" is not allowed`) {
		t.Fatalf("target scheme error = %v, want file rejection", err)
	}
	if blockedSender.callCount() != 0 {
		t.Fatal("provider was called for a disallowed scratchpad target")
	}
}

func TestSendProviderFailuresAreSanitized(t *testing.T) {
	cfg := testConfig(t)
	fake := &fakeSender{response: &providerResponse{
		StatusCode: http.StatusUnauthorized,
		Body:       "bad key " + testAPIKey + "\ntry again",
		Headers:    http.Header{},
	}}
	service := newTestService(t, cfg, fake)

	_, err := service.Send(context.Background(), validInput())
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected ProviderError, got %v", err)
	}
	if providerErr.StatusCode != http.StatusUnauthorized || strings.Contains(providerErr.Error(), testAPIKey) || !strings.Contains(providerErr.Error(), "[REDACTED]") {
		t.Fatalf("unexpected provider error: %v", providerErr)
	}
	if strings.Contains(providerErr.Error(), "\n") {
		t.Fatalf("provider error contains newline: %q", providerErr.Error())
	}
	for _, metadata := range []string{"credential_diagnostics", "loaded=", "prefix_valid=", "length=", "fingerprint="} {
		if strings.Contains(providerErr.Error(), metadata) {
			t.Fatalf("disabled credential diagnostics exposed %q: %v", metadata, providerErr)
		}
	}
}

func TestSendUnauthorizedIncludesOptInCredentialDiagnostic(t *testing.T) {
	cfg := testConfig(t)
	cfg.CredentialDiagnostics = true
	fake := &fakeSender{response: &providerResponse{
		StatusCode: http.StatusUnauthorized,
		Body:       "bad key " + testAPIKey,
		Headers:    http.Header{},
	}}
	service := newTestService(t, cfg, fake)

	_, err := service.Send(context.Background(), validInput())
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected ProviderError, got %v", err)
	}
	diagnostic := expectedCredentialDiagnostic(testAPIKey)
	if providerErr.StatusCode != http.StatusUnauthorized || !strings.HasSuffix(providerErr.Error(), "; "+diagnostic) {
		t.Fatalf("unauthorized error does not contain the exact diagnostic: %v", providerErr)
	}
	if strings.Contains(providerErr.Error(), testAPIKey) {
		t.Fatalf("unauthorized error exposed the raw key: %v", providerErr)
	}
}

func expectedCredentialDiagnostic(apiKey string) string {
	digest := sha256.Sum256([]byte(apiKey))
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])[:16]
	return fmt.Sprintf(
		"credential_diagnostics loaded=true prefix_valid=%t length=%d fingerprint=%s",
		strings.HasPrefix(apiKey, "SG."),
		len(apiKey),
		fingerprint,
	)
}

func TestSendSemaphoreHonorsContextAndReleasesCapacity(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fake := &fakeSender{send: func(ctx context.Context, _ *mail.SGMailV3) (*providerResponse, error) {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return acceptedResponse("first"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	cfg := testConfig(t)
	cfg.MaxConcurrentSends = 1
	service := newTestService(t, cfg, fake)

	firstDone := make(chan error, 1)
	go func() {
		_, err := service.Send(context.Background(), validInput())
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first send did not reach provider")
	}

	secondContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := service.Send(secondContext, validInput())
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || !strings.Contains(providerErr.Error(), "waiting for capacity") {
		t.Fatalf("second send error = %v", err)
	}
	if fake.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1 while semaphore is held", fake.callCount())
	}

	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first send failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first send did not finish")
	}

	if _, err := service.Send(context.Background(), validInput()); err != nil {
		t.Fatalf("send after release failed: %v", err)
	}
}
