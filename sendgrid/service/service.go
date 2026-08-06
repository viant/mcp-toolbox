package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	netmail "net/mail"
	"strings"

	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/viant/afs"
	afsscratchpad "github.com/viant/afs/scratchpad"
	"github.com/viant/scy"
)

// Option customizes the service, primarily for deterministic tests.
type Option func(*Service)

func withSender(value sender) Option {
	return func(service *Service) {
		if value != nil {
			service.sender = value
		}
	}
}

// WithLimits overrides memory and serialized payload limits.
func WithLimits(maxDecoded, maxPayload int64) Option {
	return func(service *Service) {
		if maxDecoded > 0 {
			service.maxDecodedAttachmentBytes = maxDecoded
		}
		if maxPayload > 0 {
			service.maxPayloadBytes = maxPayload
		}
	}
}

// Service validates, builds, and submits outbound SendGrid messages.
type Service struct {
	cfg                       Config
	apiKey                    string
	credentialDiagnostic      *credentialDiagnostic
	sender                    sender
	resolver                  *attachmentResolver
	sem                       chan struct{}
	maxDecodedAttachmentBytes int64
	maxPayloadBytes           int64
}

// NewService creates an independent SendGrid service.
func NewService(ctx context.Context, cfg Config, opts ...Option) (*Service, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg.normalize()
	switch {
	case cfg.APIKeyRef == "":
		return nil, fmt.Errorf("SendGrid api-key-ref is required")
	case cfg.Region != "global" && cfg.Region != "eu":
		return nil, fmt.Errorf("invalid SendGrid region %q: expected global or eu", cfg.Region)
	case cfg.MaxConcurrentSends <= 0:
		return nil, fmt.Errorf("max concurrent sends must be greater than zero")
	case cfg.SendTimeout <= 0:
		return nil, fmt.Errorf("send timeout must be greater than zero")
	}
	apiKey, err := loadAPIKey(ctx, cfg.APIKeyRef)
	if err != nil {
		return nil, err
	}

	fs := afs.New()
	scratchpadOpts := []afsscratchpad.Option{
		afsscratchpad.WithAFS(fs),
		afsscratchpad.WithAllowedTargetSchemes(cfg.ScratchpadTargetSchemes...),
	}
	if cfg.ScratchpadRootURI != "" {
		scratchpadOpts = append(scratchpadOpts, afsscratchpad.WithRootURI(cfg.ScratchpadRootURI))
	}
	scratchpad := afsscratchpad.New(scratchpadOpts...)

	result := &Service{
		cfg:                       cfg,
		apiKey:                    apiKey,
		sender:                    &sdkSender{apiKey: apiKey, region: cfg.Region},
		sem:                       make(chan struct{}, cfg.MaxConcurrentSends),
		maxDecodedAttachmentBytes: DefaultMaxDecodedAttachmentBytes,
		maxPayloadBytes:           DefaultMaxPayloadBytes,
	}
	if cfg.CredentialDiagnostics {
		result.credentialDiagnostic = newCredentialDiagnostic(apiKey)
	}
	for _, opt := range opts {
		if opt != nil {
			opt(result)
		}
	}
	result.resolver = newAttachmentResolver(cfg, fs, scratchpad, result.maxDecodedAttachmentBytes)
	return result, nil
}

// CredentialDiagnostics returns stable, secret-safe API-key metadata when the
// corresponding opt-in configuration is enabled. It never returns plaintext.
func (s *Service) CredentialDiagnostics() string {
	if s == nil {
		return ""
	}
	return s.credentialDiagnostic.String()
}

func loadAPIKey(ctx context.Context, encoded scy.EncodedResource) (apiKey string, resultErr error) {
	defer func() {
		if recover() != nil {
			apiKey = ""
			resultErr = fmt.Errorf("failed to load encrypted SendGrid API key")
		}
	}()

	rawRef := string(encoded)
	separator := strings.Index(rawRef, "|")
	switch {
	case separator == -1:
		return "", fmt.Errorf("SendGrid api-key-ref KMS key is required")
	case strings.TrimSpace(rawRef[:separator]) == "":
		return "", fmt.Errorf("SendGrid api-key-ref resource URL is required")
	case strings.TrimSpace(rawRef[separator+1:]) == "":
		return "", fmt.Errorf("SendGrid api-key-ref KMS key is required")
	}

	resource := encoded.Decode(ctx, nil)
	resource.URL = strings.TrimSpace(resource.URL)
	resource.Key = strings.TrimSpace(resource.Key)
	switch {
	case resource.URL == "":
		return "", fmt.Errorf("SendGrid api-key-ref resource URL is required")
	case resource.Key == "":
		return "", fmt.Errorf("SendGrid api-key-ref KMS key is required")
	}

	secret, err := scy.New().Load(ctx, resource)
	if err != nil {
		// Provider errors can include resource locations or KMS references. Keep
		// startup diagnostics secret-safe and expose neither part of the ref.
		return "", fmt.Errorf("failed to load encrypted SendGrid API key")
	}
	if secret == nil {
		return "", fmt.Errorf("failed to load encrypted SendGrid API key")
	}
	apiKey = strings.TrimSpace(secret.String())
	if apiKey == "" {
		return "", fmt.Errorf("decrypted SendGrid API key is empty")
	}
	return apiKey, nil
}

// Send validates and submits a message. Its timeout covers queueing, attachment
// resolution, payload construction, and the provider request.
func (s *Service) Send(ctx context.Context, input *SendEmailInput) (*SendEmailOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SendTimeout)
	defer cancel()

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, &ProviderError{Message: "SendGrid request canceled while waiting for capacity"}
	}

	if err := validateInput(input); err != nil {
		return nil, err
	}
	attachments, err := s.resolver.resolve(ctx, input.Attachments)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &ProviderError{Message: "SendGrid request canceled while resolving attachments"}
		}
		return nil, err
	}
	message := buildMessage(input, attachments)
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, &ProviderError{Message: "failed to encode SendGrid message"}
	}
	if int64(len(payload)) >= s.maxPayloadBytes {
		return nil, validationErrorf("serialized message size %d exceeds the %d byte limit", len(payload), s.maxPayloadBytes)
	}
	if err := ctx.Err(); err != nil {
		return nil, &ProviderError{Message: "SendGrid request canceled before submission"}
	}

	response, err := s.sender.Send(ctx, message)
	if err != nil {
		return nil, &ProviderError{Message: "SendGrid request failed: " + sanitizeProviderText(err.Error(), s.apiKey)}
	}
	if response == nil {
		return nil, &ProviderError{Message: "SendGrid returned an empty response"}
	}
	if response.StatusCode != http.StatusAccepted {
		message := fmt.Sprintf("SendGrid request failed with status %d", response.StatusCode)
		if body := sanitizeProviderText(response.Body, s.apiKey); body != "" {
			message += ": " + body
		}
		if diagnostic := s.CredentialDiagnostics(); diagnostic != "" {
			message += "; " + diagnostic
		}
		return nil, &ProviderError{StatusCode: response.StatusCode, Message: message}
	}
	return &SendEmailOutput{
		Status:       "accepted",
		Provider:     "sendgrid",
		StatusCode:   response.StatusCode,
		MessageID:    response.Headers.Get("X-Message-Id"),
		ResolvedFrom: strings.TrimSpace(input.From),
	}, nil
}

func validateInput(input *SendEmailInput) error {
	if input == nil {
		return validationErrorf("input is required")
	}
	if err := validateEmail("from", input.From); err != nil {
		return err
	}
	if len(input.To) == 0 {
		return validationErrorf("to must contain at least one recipient")
	}
	if len(input.To) > MaxRecipients {
		return validationErrorf("to must contain at most %d recipients", MaxRecipients)
	}
	for i, recipient := range input.To {
		if err := validateEmail(fmt.Sprintf("to[%d]", i), recipient); err != nil {
			return err
		}
	}
	if strings.TrimSpace(input.Subject) == "" {
		return validationErrorf("subject is required")
	}
	if strings.TrimSpace(input.BodyText) == "" && strings.TrimSpace(input.BodyHTML) == "" {
		return validationErrorf("bodyText or bodyHtml is required")
	}
	if _, _, err := normalizeImportance(input.Importance); err != nil {
		return err
	}
	return nil
}

func validateEmail(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return validationErrorf("%s is required", field)
	}
	address, err := netmail.ParseAddress(value)
	if err != nil || !strings.EqualFold(address.Address, value) {
		return validationErrorf("%s must be a valid bare email address", field)
	}
	return nil
}

func buildMessage(input *SendEmailInput, attachments []resolvedAttachment) *mail.SGMailV3 {
	message := mail.NewV3Mail()
	message.SetFrom(mail.NewEmail(strings.TrimSpace(input.FromName), strings.TrimSpace(input.From)))
	message.Subject = input.Subject

	personalization := mail.NewPersonalization()
	for _, recipient := range input.To {
		personalization.AddTos(mail.NewEmail("", strings.TrimSpace(recipient)))
	}
	message.AddPersonalizations(personalization)
	if input.BodyText != "" {
		message.AddContent(mail.NewContent("text/plain", input.BodyText))
	}
	if input.BodyHTML != "" {
		message.AddContent(mail.NewContent("text/html", input.BodyHTML))
	}
	importance, priority, _ := normalizeImportance(input.Importance)
	message.SetHeader("Importance", importance)
	message.SetHeader("X-Priority", priority)
	message.AddAttachment(sendGridAttachments(attachments)...)
	return message
}

func normalizeImportance(value string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "normal":
		return "normal", "3", nil
	case "low":
		return "low", "5", nil
	case "high":
		return "high", "1", nil
	default:
		return "", "", validationErrorf("importance must be Low, Normal, or High")
	}
}

func sanitizeProviderText(value, apiKey string) string {
	value = strings.TrimSpace(value)
	if apiKey != "" {
		value = strings.ReplaceAll(value, apiKey, "[REDACTED]")
	}
	value = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
	value = strings.Join(strings.Fields(value), " ")
	const maxBytes = 2048
	if len(value) > maxBytes {
		value = value[:maxBytes] + "..."
	}
	return value
}
