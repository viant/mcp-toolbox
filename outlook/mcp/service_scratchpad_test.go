package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/afs"
	afsscratchpad "github.com/viant/afs/scratchpad"
	"github.com/viant/mcp-protocol/authorization"
	"github.com/viant/mcp-toolbox/outlook/graph"
)

func TestServiceIdentityNamespaceUsesConfiguredClaimOrder(t *testing.T) {
	svc := NewService(&Config{})
	ctx := contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	}))
	identity, err := svc.identityNamespace(ctx)
	if err != nil {
		t.Fatalf("identityNamespace failed: %v", err)
	}
	if got, want := identity, "alice@example.com"; got != want {
		t.Fatalf("unexpected identity: got %q want %q", got, want)
	}

	svc = NewService(&Config{NamespaceClaimKeys: []string{"sub", "email"}})
	ctx = contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	}))
	identity, err = svc.identityNamespace(ctx)
	if err != nil {
		t.Fatalf("identityNamespace failed: %v", err)
	}
	if got, want := identity, "alice-subject"; got != want {
		t.Fatalf("unexpected identity: got %q want %q", got, want)
	}
}

func TestServiceIdentityNamespaceUsesNextConfiguredClaim(t *testing.T) {
	svc := NewService(&Config{NamespaceClaimKeys: []string{"sub", "email"}})
	ctx := contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "alice@example.com",
	}))
	identity, err := svc.identityNamespace(ctx)
	if err != nil {
		t.Fatalf("identityNamespace failed: %v", err)
	}
	if got, want := identity, "alice@example.com"; got != want {
		t.Fatalf("unexpected identity: got %q want %q", got, want)
	}
}

func TestServiceIdentityNamespaceRejectsNonIdentityDescriptors(t *testing.T) {
	svc := NewService(&Config{})
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "default", ctx: context.Background()},
		{name: "token hash", ctx: contextWithBearer(context.Background(), "opaque-token")},
		{name: "malformed", ctx: contextWithBearer(context.Background(), "not.a.jwt")},
		{name: "missing claims", ctx: contextWithBearer(context.Background(), testJWT(t, map[string]any{"aud": "outlook"}))},
		{name: "empty claim", ctx: contextWithBearer(context.Background(), testJWT(t, map[string]any{"email": "", "sub": ""}))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := svc.identityNamespace(test.ctx)
			if !errors.Is(err, graph.ErrIdentityNamespaceRequired) {
				t.Fatalf("expected identity error, got %v", err)
			}
			if err.Error() != graph.IdentityNamespaceRequiredMessage {
				t.Fatalf("unexpected identity error message: %q", err.Error())
			}
		})
	}
}

func TestServiceWiresNamespaceClaimKeysToScratchpadAndGraphManager(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewService(&Config{
		SecretsBase:        storageDir,
		NamespaceClaimKeys: []string{"sub", "email"},
	})
	ctx := contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	}))

	identity, err := svc.identityNamespace(ctx)
	if err != nil || identity != "alice-subject" {
		t.Fatalf("unexpected identity: got %q err=%v", identity, err)
	}
	if got := afsscratchpad.UserIDFromContext(afsscratchpad.ContextWithUserID(ctx, identity)); got != identity {
		t.Fatalf("scratchpad identity %q differs from Outlook identity %q", got, identity)
	}

	subjectRecord := filepath.Join(storageDir, "alice-subject_personal_auth_record.json")
	if err := os.WriteFile(subjectRecord, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write subject auth record: %v", err)
	}
	if !svc.graphMgr.HasAuthRecord(ctx, "personal") {
		t.Fatal("expected graph manager to use subject namespace from service config")
	}

	if err := os.Remove(subjectRecord); err != nil {
		t.Fatalf("failed to remove subject auth record: %v", err)
	}
	emailRecord := filepath.Join(storageDir, "alice_example.com_personal_auth_record.json")
	if err := os.WriteFile(emailRecord, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write email auth record: %v", err)
	}
	if svc.graphMgr.HasAuthRecord(ctx, "personal") {
		t.Fatal("expected graph manager not to fall back to email while subject claim is present")
	}
}

func TestServiceScratchpadRegistrationUsesRequestUser(t *testing.T) {
	dir := t.TempDir()
	root := "file://" + filepath.ToSlash(filepath.Join(dir, "scratchpad", "${userID}"))
	svc := NewService(&Config{
		ScratchpadRootURI:       root,
		ScratchpadTargetSchemes: []string{"file"},
	})
	scratchpad := afsscratchpad.New(
		afsscratchpad.WithRootURI(root),
		afsscratchpad.WithAllowedTargetSchemes("file"),
	)

	aliceRequestContext := contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "alice@example.com",
	}))
	bobRequestContext := contextWithBearer(context.Background(), testJWT(t, map[string]any{
		"email": "bob@example.com",
	}))
	aliceIdentity, err := svc.identityNamespace(aliceRequestContext)
	if err != nil {
		t.Fatalf("failed to resolve alice identity: %v", err)
	}
	bobIdentity, err := svc.identityNamespace(bobRequestContext)
	if err != nil {
		t.Fatalf("failed to resolve bob identity: %v", err)
	}
	aliceCtx := afsscratchpad.ContextWithUserID(aliceRequestContext, aliceIdentity)
	bobCtx := afsscratchpad.ContextWithUserID(bobRequestContext, bobIdentity)
	writeMCPTestArtifact(t, scratchpad, aliceCtx, "report-1", "file://"+filepath.ToSlash(writeMCPTestFile(t, dir, "alice.txt", "alice report")))

	data, err := afs.New().DownloadWithURL(aliceCtx, "scratchpad://artifact/report-1")
	if err != nil {
		t.Fatalf("failed to read alice artifact: %v", err)
	}
	if got, want := string(data), "alice report"; got != want {
		t.Fatalf("unexpected alice artifact data: got %q want %q", got, want)
	}

	_, err = afs.New().DownloadWithURL(bobCtx, "scratchpad://artifact/report-1")
	if err == nil {
		t.Fatalf("expected bob artifact read to fail")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "different user") {
		t.Fatalf("unexpected bob artifact read error: %v", err)
	}
}

func contextWithBearer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authorization.TokenKey, &authorization.Token{Token: "Bearer " + token})
}

func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to marshal jwt part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]any{"alg": "none", "typ": "JWT"}) + "." + encode(claims) + "."
}

func writeMCPTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write test file %s: %v", name, err)
	}
	return path
}

func writeMCPTestArtifact(t *testing.T, scratchpad *afsscratchpad.Service, ctx context.Context, artifactID, sourceURL string) {
	t.Helper()
	metadata, err := json.Marshal(afsscratchpad.Artifact{
		Kind:        "artifact",
		ArtifactID:  artifactID,
		Name:        artifactID + ".txt",
		ContentType: "text/plain",
		SourceURL:   sourceURL,
	})
	if err != nil {
		t.Fatalf("failed to marshal artifact metadata: %v", err)
	}
	if _, err = scratchpad.Memorize(ctx, &afsscratchpad.MemorizeInput{
		Key:         afsscratchpad.ArtifactKey(artifactID),
		Description: "Artifact " + artifactID,
		Body:        string(metadata),
	}); err != nil {
		t.Fatalf("failed to write artifact metadata: %v", err)
	}
}
