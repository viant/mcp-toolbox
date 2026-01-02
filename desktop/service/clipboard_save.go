package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Service) SaveClipboard(ctx context.Context, in *SaveClipboardInput) (*SaveClipboardOutput, error) {
	if in == nil {
		in = &SaveClipboardInput{}
	}
	read, err := s.ReadClipboard(ctx, &ReadClipboardInput{Format: in.Format, Timing: in.Timing})
	if err != nil {
		return nil, err
	}
	if read == nil || read.MimeType == "" {
		return nil, fmt.Errorf("clipboard read returned no content")
	}

	dest := strings.TrimSpace(in.DestURL)
	if dest == "" {
		u, err := DefaultClipboardDestURL(read.MimeType)
		if err != nil {
			return nil, err
		}
		dest = u
	}

	var payload []byte
	encoding := ""
	switch read.MimeType {
	case "text/plain", "text/html":
		payload = []byte(read.Text)
	default:
		if read.Encoding != "base64" || read.Data == "" {
			return nil, fmt.Errorf("clipboard %s requires base64 data", read.MimeType)
		}
		b, err := decodeBase64(read.Data)
		if err != nil {
			return nil, err
		}
		payload = b
		encoding = "base64"
	}

	if err := s.fs.Upload(ctx, dest, 0o644, bytes.NewReader(payload)); err != nil {
		return nil, err
	}
	return &SaveClipboardOutput{
		DestURL:   dest,
		MimeType:  read.MimeType,
		Bytes:     len(payload),
		Encoding:  encoding,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func DefaultClipboardDestURL(mimeType string) (string, error) {
	base := filepath.Join(os.TempDir(), "mcp-toolbox", "desktop", "clipboard")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	ext := ".bin"
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/png":
		ext = ".png"
	case "text/html":
		ext = ".html"
	case "text/plain":
		ext = ".txt"
	}
	name := fmt.Sprintf("clipboard_%s%s", time.Now().UTC().Format("20060102T150405.000Z"), ext)
	return "file://" + filepath.ToSlash(filepath.Join(base, name)), nil
}
