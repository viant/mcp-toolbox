package service

import (
	"context"
	"os"
	"testing"
)

// This test is intentionally skipped by default; it requires a working browser environment.
func TestIntegration_ChromedriverStartOpenStop(t *testing.T) {
	if os.Getenv("MCP_BROWSER_INTEGRATION") == "" {
		t.Skip("set MCP_BROWSER_INTEGRATION=1 to run")
	}
	svc := NewService(&Config{UseData: true})
	_, err := svc.Start(context.Background(), &StartInput{Driver: ChromeDriver, Port: 4444})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _, _ = svc.Stop(context.Background(), &StopInput{Port: 4444}) }()

	_, err = svc.OpenSession(context.Background(), &OpenSessionInput{SessionID: "localhost:4444", Browser: ChromeBrowser})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	_, _ = svc.CloseSession(context.Background(), &CloseSessionInput{SessionID: "localhost:4444"})
}
