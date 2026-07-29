package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sendgrid/rest"
	sgapi "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type providerResponse struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

type sender interface {
	Send(ctx context.Context, message *mail.SGMailV3) (*providerResponse, error)
}

type sdkSender struct {
	apiKey     string
	region     string
	httpClient *http.Client
}

func (s *sdkSender) Send(ctx context.Context, message *mail.SGMailV3) (*providerResponse, error) {
	client := sgapi.NewSendClient(s.apiKey)
	request, err := sgapi.SetDataResidency(client.Request, s.region)
	if err != nil {
		return nil, fmt.Errorf("configure SendGrid region: %w", err)
	}
	request.Body = mail.GetRequestBody(message)
	restClient := &rest.Client{HTTPClient: noRedirectHTTPClient(s.httpClient)}
	response, err := restClient.SendWithContext(ctx, request)
	if err != nil {
		return nil, err
	}
	return &providerResponse{
		StatusCode: response.StatusCode,
		Body:       response.Body,
		Headers:    http.Header(response.Headers),
	}, nil
}

func noRedirectHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	result := *base
	result.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &result
}
