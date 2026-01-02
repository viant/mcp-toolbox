//go:build !windows
// +build !windows

package service

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestService_StartProcess_Wait(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	out, err := svc.StartProcess(context.Background(), &StartProcessInput{
		Command: "sh",
		Args:    []string{"-c", "echo hi"},
		Wait:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("expected exitCode 0, got %d output=%q", out.ExitCode, out.Output)
	}
	if out.Output == "" {
		t.Fatalf("expected non-empty output")
	}
}

func TestService_StartProcess_NoWait(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	out, err := svc.StartProcess(context.Background(), &StartProcessInput{
		Command:   "sh",
		Args:      []string{"-c", "sleep 2"},
		Wait:      false,
		TimeoutMs: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Pid <= 0 {
		t.Fatalf("expected pid > 0, got %d", out.Pid)
	}
	p, err := os.FindProcess(out.Pid)
	if err == nil && p != nil {
		_ = p.Kill()
	}
	time.Sleep(20 * time.Millisecond)
}
