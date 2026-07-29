package service

import "fmt"

// SendEmailInput is the public MCP input for an outbound SendGrid message.
type SendEmailInput struct {
	From        string            `json:"from" description:"sender email address; it must be verified by SendGrid"`
	FromName    string            `json:"fromName,omitempty" description:"optional sender display name"`
	To          []string          `json:"to" description:"recipient email addresses"`
	Subject     string            `json:"subject"`
	BodyText    string            `json:"bodyText,omitempty"`
	BodyHTML    string            `json:"bodyHtml,omitempty"`
	Importance  string            `json:"importance,omitempty" description:"Low, Normal, or High"`
	Attachments []EmailAttachment `json:"attachments,omitempty"`
}

// EmailAttachment accepts either inline base64 data or an AFS/scratchpad URL.
type EmailAttachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType,omitempty"`
	DataBase64  string `json:"dataBase64,omitempty"`
	SourceURL   string `json:"sourceURL,omitempty"`
}

// SendEmailOutput reports provider acceptance, not final delivery.
type SendEmailOutput struct {
	Status     string `json:"status"`
	Provider   string `json:"provider"`
	StatusCode int    `json:"statusCode"`
	MessageID  string `json:"messageId,omitempty"`
}

// ValidationError identifies a caller-correctable tool input error.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func validationErrorf(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

// ProviderError identifies a SendGrid or transport failure after validation.
type ProviderError struct {
	StatusCode int
	Message    string
}

func (e *ProviderError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}
