package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSDKSenderDoesNotFollowProviderRedirect(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		response.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()

	var sourceRequests atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		sourceRequests.Add(1)
		if request.URL.Path != "/v3/mail/send" {
			t.Errorf("provider path = %q, want /v3/mail/send", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer SG.test-secret" {
			t.Errorf("provider Authorization header = %q", request.Header.Get("Authorization"))
		}
		response.Header().Set("Location", target.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	sourceTransport := source.Client().Transport
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() != "api.sendgrid.com" {
			return sourceTransport.RoundTrip(request)
		}
		clone := request.Clone(request.Context())
		clonedURL := *request.URL
		clonedURL.Scheme = "http"
		clonedURL.Host = source.Listener.Addr().String()
		clone.URL = &clonedURL
		return sourceTransport.RoundTrip(clone)
	})

	cfg := testConfig(t)
	service, err := NewService(context.Background(), cfg, withSender(&sdkSender{
		apiKey:     testAPIKey,
		region:     cfg.Region,
		httpClient: &http.Client{Transport: transport},
	}))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	_, err = service.Send(context.Background(), validInput())
	var providerError *ProviderError
	if !errors.As(err, &providerError) || providerError.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("Send error = %v, want provider status 307", err)
	}
	if got := sourceRequests.Load(); got != 1 {
		t.Fatalf("provider source received %d requests, want 1", got)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
