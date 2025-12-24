package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (s *Service) GetDOM(ctx context.Context, in *GetDOMInput) (*GetDOMOutput, error) {
	if in == nil {
		in = &GetDOMInput{}
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

	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "outerhtml"
	}

	switch format {
	case "outerhtml", "outer-html", "html":
		raw, err := sess.driver.ExecuteScript("return document.documentElement ? document.documentElement.outerHTML : ''", nil)
		if err != nil {
			return nil, err
		}
		html := fmt.Sprintf("%v", raw)
		html, truncated := truncateUTF8ByBytes(html, in.MaxBytes)

		out := &GetDOMOutput{
			SessionID: sessionID,
			Format:    "outerHTML",
			DestURL:   in.DestURL,
			Bytes:     len([]byte(html)),
			Truncated: truncated,
			Encoding:  "utf-8",
			OuterHTML: html,
		}
		if in.DestURL != "" {
			out.Encoding = ""
			out.OuterHTML = ""
			if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader([]byte(html))); err != nil {
				return nil, err
			}
		}
		return out, nil

	case "snapshot":
		if sess.Remote == "" {
			host, port := splitHostPort(sess.ID)
			sess.Remote = fmt.Sprintf("http://%s:%s/wd/hub", host, port)
		}
		if !strings.EqualFold(sess.Browser, ChromeBrowser) && !strings.EqualFold(sess.Browser, "edge") {
			return nil, fmt.Errorf("dom snapshot is supported only for Chrome/Edge")
		}
		wdSession := sess.driver.SessionID()
		if wdSession == "" {
			return nil, fmt.Errorf("missing webdriver session id")
		}

		raw, err := cdpExecute(sess.Remote, wdSession, "DOMSnapshot.captureSnapshot", map[string]any{
			"computedStyles": []string{},
		})
		if err != nil {
			return nil, err
		}
		var snapshot map[string]any
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return nil, err
		}
		out := &GetDOMOutput{SessionID: sessionID, Format: "snapshot", DestURL: in.DestURL, Snapshot: snapshot}
		if in.DestURL != "" {
			b, err := json.Marshal(snapshot)
			if err != nil {
				return nil, err
			}
			out.Bytes = len(b)
			out.Snapshot = nil
			if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader(b)); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", in.Format)
	}
}
