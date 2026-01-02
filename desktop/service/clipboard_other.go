//go:build !darwin
// +build !darwin

package service

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/go-vgo/robotgo"
)

func (s *Service) ReadClipboard(_ context.Context, in *ReadClipboardInput) (*ReadClipboardOutput, error) {
	if in == nil {
		in = &ReadClipboardInput{}
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "auto"
	}
	if format != "auto" && format != "text" {
		return nil, fmt.Errorf("clipboard %s not supported on %s (only text)", format, runtime.GOOS)
	}
	var text string
	if err := s.withTimings(in.Timing, func() error {
		t, err := robotgo.ReadAll()
		if err != nil {
			return err
		}
		text = t
		return nil
	}); err != nil {
		return nil, err
	}
	return &ReadClipboardOutput{MimeType: "text/plain", Text: text}, nil
}

func (s *Service) WriteClipboard(_ context.Context, in *WriteClipboardInput) (*WriteClipboardOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	mime := strings.ToLower(strings.TrimSpace(in.MimeType))
	if mime == "" {
		mime = "text/plain"
	}
	switch mime {
	case "text/plain":
		return &WriteClipboardOutput{}, s.withTimings(in.Timing, func() error { return robotgo.WriteAll(in.Text) })
	case "text/html":
		// Fallback: write HTML as plain text.
		return &WriteClipboardOutput{}, s.withTimings(in.Timing, func() error { return robotgo.WriteAll(in.Text) })
	case "image/png":
		return nil, fmt.Errorf("image/png clipboard not supported on %s", runtime.GOOS)
	default:
		return nil, fmt.Errorf("unsupported mimeType: %q", in.MimeType)
	}
}
