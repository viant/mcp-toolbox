package service

import (
	"bytes"
	"context"
	"fmt"
)

func (s *Service) GetSource(ctx context.Context, in *GetSourceInput) (*GetSourceOutput, error) {
	if in == nil {
		in = &GetSourceInput{}
	}
	sessionID := in.SessionID
	if sessionID == "" {
		sessionID = "localhost:4444"
	}
	sess, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", sessionID)
	}

	html, err := sess.driver.PageSource()
	if err != nil {
		return nil, err
	}
	html, truncated := truncateUTF8ByBytes(html, in.MaxBytes)

	out := &GetSourceOutput{
		SessionID: sessionID,
		DestURL:   in.DestURL,
		Bytes:     len([]byte(html)),
		Truncated: truncated,
	}
	if in.DestURL != "" {
		if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader([]byte(html))); err != nil {
			return nil, err
		}
		return out, nil
	}
	out.Encoding = "utf-8"
	out.Data = html
	return out, nil
}
