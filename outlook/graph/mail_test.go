package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	afsscratchpad "github.com/viant/afs/scratchpad"
)

func TestBuildSendMailPayloadWithoutAttachments(t *testing.T) {
	payload := mustPayload(t, &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Status",
		BodyText: "All green.",
	})

	msg := payload["message"].(map[string]any)
	if _, ok := msg["attachments"]; ok {
		t.Fatalf("did not expect attachments in payload")
	}
	if msg["subject"] != "Status" {
		t.Fatalf("unexpected subject: %v", msg["subject"])
	}
}

func TestBuildSendMailPayloadWithDataBase64Attachment(t *testing.T) {
	payload := mustPayload(t, &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Report",
		BodyText: "Attached.",
		Attachments: []EmailAttachment{
			{
				Name:        "report.pdf",
				ContentType: "application/pdf",
				DataBase64:  base64.StdEncoding.EncodeToString([]byte("pdf-data")),
			},
		},
	})

	attachment := firstAttachment(t, payload)
	if attachment["@odata.type"] != "#microsoft.graph.fileAttachment" {
		t.Fatalf("unexpected odata type: %v", attachment["@odata.type"])
	}
	if attachment["name"] != "report.pdf" {
		t.Fatalf("unexpected name: %v", attachment["name"])
	}
	if attachment["contentType"] != "application/pdf" {
		t.Fatalf("unexpected content type: %v", attachment["contentType"])
	}
	if got, want := attachment["contentBytes"], base64.StdEncoding.EncodeToString([]byte("pdf-data")); got != want {
		t.Fatalf("unexpected content bytes: got %v want %v", got, want)
	}
}

func TestBuildSendMailPayloadWithSourceURLAttachment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	payload := mustPayload(t, &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Note",
		BodyText: "Attached.",
		Attachments: []EmailAttachment{
			{
				Name:      "note.txt",
				SourceURL: "file://" + filepath.ToSlash(path),
			},
		},
	})

	attachment := firstAttachment(t, payload)
	if got, want := attachment["contentType"], "text/plain; charset=utf-8"; got != want {
		t.Fatalf("unexpected content type: got %v want %v", got, want)
	}
	if got, want := attachment["contentBytes"], base64.StdEncoding.EncodeToString([]byte("from-file")); got != want {
		t.Fatalf("unexpected content bytes: got %v want %v", got, want)
	}
}

func TestReadAttachmentSourceGCS(t *testing.T) {
	sourceURL := strings.TrimSpace(os.Getenv("OUTLOOK_GCS_ATTACHMENT_TEST_URL"))
	if sourceURL == "" {
		t.Skip("set OUTLOOK_GCS_ATTACHMENT_TEST_URL to enable GCS attachment read verification")
	}
	data, err := readAttachmentSource(context.Background(), sourceURL)
	if err != nil {
		t.Fatalf("failed to read %s: %v", sourceURL, err)
	}
	if len(data) == 0 {
		t.Fatalf("expected non-empty data from %s", sourceURL)
	}
}

func TestReadAttachmentSourceRejectsDisallowedScheme(t *testing.T) {
	ConfigureAttachmentSources(AttachmentSourceConfig{AllowedSourceSchemes: []string{"scratchpad"}})
	t.Cleanup(func() {
		ConfigureAttachmentSources(AttachmentSourceConfig{})
	})

	_, err := readAttachmentSource(context.Background(), "file:///tmp/report.txt")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), `sourceURL scheme "file" is not allowed`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadAttachmentSourceScratchpadArtifact(t *testing.T) {
	ConfigureAttachmentSources(AttachmentSourceConfig{AllowedSourceSchemes: []string{"scratchpad"}})
	t.Cleanup(func() {
		ConfigureAttachmentSources(AttachmentSourceConfig{})
	})

	ctx := context.Background()
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(reportPath, []byte("report from scratchpad"), 0o600); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	root := "file://" + filepath.ToSlash(filepath.Join(dir, "scratchpad", "${userID}"))
	sourceURL := "file://" + filepath.ToSlash(reportPath)
	service := afsscratchpad.New(
		afsscratchpad.WithRootURI(root),
		afsscratchpad.WithUserID("devuser"),
		afsscratchpad.WithAllowedTargetSchemes("file"),
	)
	metadata, err := json.Marshal(afsscratchpad.Artifact{
		Kind:        "artifact",
		ArtifactID:  "report-1",
		Name:        "report.txt",
		ContentType: "text/plain",
		SourceURL:   sourceURL,
	})
	if err != nil {
		t.Fatalf("failed to marshal artifact metadata: %v", err)
	}
	if _, err = service.Memorize(ctx, &afsscratchpad.MemorizeInput{
		Key:         afsscratchpad.ArtifactKey("report-1"),
		Description: "Artifact report-1",
		Body:        string(metadata),
	}); err != nil {
		t.Fatalf("failed to write artifact metadata: %v", err)
	}
	afsscratchpad.Register(
		afsscratchpad.WithRootURI(root),
		afsscratchpad.WithUserID("devuser"),
		afsscratchpad.WithAllowedTargetSchemes("file"),
	)

	data, err := readAttachmentSource(ctx, "scratchpad://artifact/report-1")
	if err != nil {
		t.Fatalf("failed to read scratchpad artifact: %v", err)
	}
	if got, want := string(data), "report from scratchpad"; got != want {
		t.Fatalf("unexpected data: got %q want %q", got, want)
	}
}

func TestBuildSendMailPayloadAttachmentContentTypeFallback(t *testing.T) {
	payload := mustPayload(t, &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Data",
		BodyText: "Attached.",
		Attachments: []EmailAttachment{
			{Name: "payload.unknownext", DataBase64: base64.StdEncoding.EncodeToString([]byte("data"))},
		},
	})

	attachment := firstAttachment(t, payload)
	if got, want := attachment["contentType"], "application/octet-stream"; got != want {
		t.Fatalf("unexpected content type: got %v want %v", got, want)
	}
}

func TestBuildSendMailPayloadAttachmentValidation(t *testing.T) {
	tooLarge := base64.StdEncoding.EncodeToString(make([]byte, maxSimpleAttachmentBytes))
	tests := []struct {
		name       string
		attachment EmailAttachment
		want       string
	}{
		{
			name:       "missing name",
			attachment: EmailAttachment{DataBase64: base64.StdEncoding.EncodeToString([]byte("data"))},
			want:       "name is required",
		},
		{
			name:       "both sources",
			attachment: EmailAttachment{Name: "a.txt", DataBase64: base64.StdEncoding.EncodeToString([]byte("data")), SourceURL: "file:///tmp/a.txt"},
			want:       "exactly one of dataBase64 or sourceURL",
		},
		{
			name:       "no source",
			attachment: EmailAttachment{Name: "a.txt"},
			want:       "must provide dataBase64 or sourceURL",
		},
		{
			name:       "invalid base64",
			attachment: EmailAttachment{Name: "a.txt", DataBase64: "not-base64"},
			want:       "invalid dataBase64",
		},
		{
			name:       "too large",
			attachment: EmailAttachment{Name: "a.bin", DataBase64: tooLarge},
			want:       "require Outlook large attachment upload sessions",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildSendMailPayload(context.Background(), &SendEmailInput{
				To:          []string{"alice@example.com"},
				Subject:     "Test",
				BodyText:    "Body",
				Attachments: []EmailAttachment{test.attachment},
			})
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %q", test.want, err.Error())
			}
		})
	}
}

func TestResolveEmailAttachmentsRejectsOverLargeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "too-large.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := file.Truncate(maxLargeAttachmentBytes + 1); err != nil {
		t.Fatalf("failed to truncate file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("failed to close file: %v", err)
	}
	_, _, err = resolveEmailAttachments(context.Background(), []EmailAttachment{
		{Name: "too-large.bin", SourceURL: "file://" + filepath.ToSlash(path)},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "150 MB") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendLargeMessageUploadsAttachmentAndSendsDraft(t *testing.T) {
	var requests []seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, seenRequest{Method: r.Method, Path: r.URL.Path, ContentRange: r.Header.Get("Content-Range"), Body: body})
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"draft-1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/attachments/createUploadSession":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uploadUrl":"` + serverUploadURL(r, "/upload/1") + `"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/upload/1":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/send":
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	withGraphTestServer(t, server.URL)

	attachment := resolvedEmailAttachment{
		Name:        "large.bin",
		ContentType: "application/octet-stream",
		Data:        bytes.Repeat([]byte("x"), maxSimpleAttachmentBytes),
		Size:        maxSimpleAttachmentBytes,
		Large:       true,
	}
	err := (&MailService{}).sendLargeMessage(context.Background(), "token", &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Large",
		BodyText: "Attached.",
	}, []resolvedEmailAttachment{attachment})
	if err != nil {
		t.Fatalf("sendLargeMessage failed: %v", err)
	}
	assertRequest(t, requests, 0, http.MethodPost, "/me/messages")
	assertRequest(t, requests, 1, http.MethodPost, "/me/messages/draft-1/attachments/createUploadSession")
	assertRequest(t, requests, 2, http.MethodPut, "/upload/1")
	if got, want := requests[2].ContentRange, "bytes 0-2999999/3000000"; got != want {
		t.Fatalf("unexpected content range: got %q want %q", got, want)
	}
	assertRequest(t, requests, 3, http.MethodPost, "/me/messages/draft-1/send")
}

func TestSendLargeMessageAddsMixedAttachments(t *testing.T) {
	var requests []seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, seenRequest{Method: r.Method, Path: r.URL.Path, ContentRange: r.Header.Get("Content-Range"), Body: body})
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"draft-1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/attachments":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/attachments/createUploadSession":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uploadUrl":"` + serverUploadURL(r, "/upload/1") + `"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/upload/1":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/send":
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	withGraphTestServer(t, server.URL)

	attachments := []resolvedEmailAttachment{
		{Name: "small.txt", ContentType: "text/plain", Data: []byte("small"), Size: 5},
		{Name: "large.bin", ContentType: "application/octet-stream", Data: bytes.Repeat([]byte("x"), maxSimpleAttachmentBytes), Size: maxSimpleAttachmentBytes, Large: true},
	}
	err := (&MailService{}).sendLargeMessage(context.Background(), "token", &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Mixed",
		BodyText: "Attached.",
	}, attachments)
	if err != nil {
		t.Fatalf("sendLargeMessage failed: %v", err)
	}
	assertRequest(t, requests, 0, http.MethodPost, "/me/messages")
	assertRequest(t, requests, 1, http.MethodPost, "/me/messages/draft-1/attachments")
	assertRequest(t, requests, 2, http.MethodPost, "/me/messages/draft-1/attachments/createUploadSession")
	assertRequest(t, requests, 3, http.MethodPut, "/upload/1")
	assertRequest(t, requests, 4, http.MethodPost, "/me/messages/draft-1/send")
}

func TestSendLargeMessageDeletesDraftOnUploadFailure(t *testing.T) {
	var requests []seenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, seenRequest{Method: r.Method, Path: r.URL.Path, ContentRange: r.Header.Get("Content-Range"), Body: body})
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"draft-1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/me/messages/draft-1/attachments/createUploadSession":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"uploadUrl":"` + serverUploadURL(r, "/upload/1") + `"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/upload/1":
			http.Error(w, "upload failed", http.StatusInternalServerError)
		case r.Method == http.MethodDelete && r.URL.Path == "/me/messages/draft-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	withGraphTestServer(t, server.URL)

	attachment := resolvedEmailAttachment{
		Name:        "large.bin",
		ContentType: "application/octet-stream",
		Data:        bytes.Repeat([]byte("x"), maxSimpleAttachmentBytes),
		Size:        maxSimpleAttachmentBytes,
		Large:       true,
	}
	err := (&MailService{}).sendLargeMessage(context.Background(), "token", &SendEmailInput{
		To:       []string{"alice@example.com"},
		Subject:  "Large",
		BodyText: "Attached.",
	}, []resolvedEmailAttachment{attachment})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "upload failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertRequest(t, requests, 3, http.MethodDelete, "/me/messages/draft-1")
}

func mustPayload(t *testing.T, in *SendEmailInput) map[string]any {
	t.Helper()
	data, err := buildSendMailPayload(context.Background(), in)
	if err != nil {
		t.Fatalf("buildSendMailPayload failed: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	return payload
}

func firstAttachment(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	msg, ok := payload["message"].(map[string]any)
	if !ok {
		t.Fatalf("message missing from payload")
	}
	attachments, ok := msg["attachments"].([]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("expected one attachment, got %#v", msg["attachments"])
	}
	attachment, ok := attachments[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected attachment type: %#v", attachments[0])
	}
	return attachment
}

type seenRequest struct {
	Method       string
	Path         string
	ContentRange string
	Body         []byte
}

func withGraphTestServer(t *testing.T, baseURL string) {
	t.Helper()
	oldBaseURL := graphBaseURL
	oldClient := graphHTTPClient
	graphBaseURL = baseURL
	graphHTTPClient = http.DefaultClient
	t.Cleanup(func() {
		graphBaseURL = oldBaseURL
		graphHTTPClient = oldClient
	})
}

func serverUploadURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

func assertRequest(t *testing.T, requests []seenRequest, index int, method, path string) {
	t.Helper()
	if len(requests) <= index {
		t.Fatalf("missing request %d, got %d requests", index, len(requests))
	}
	if got := requests[index].Method; got != method {
		t.Fatalf("request %d method: got %q want %q", index, got, method)
	}
	if got := requests[index].Path; got != path {
		t.Fatalf("request %d path: got %q want %q", index, got, path)
	}
}
