package service

import (
	"context"
	"fmt"
	"strings"
)

func (s *Service) CaptureStart(ctx context.Context, in *CaptureStartInput) (*CaptureStartOutput, error) {
	if in == nil {
		in = &CaptureStartInput{}
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
		return nil, fmt.Errorf("webdriver session not open: %s", sessionID)
	}
	sess.capture = newCaptureState(in)
	if in.SinkURL != "" {
		if err := sess.capture.StartSink(s.fs, in.SinkURL, in.FlushIntervalMs); err != nil {
			return nil, err
		}
	}

	warning := ""
	if sess.Remote == "" {
		host, port := splitHostPort(sess.ID)
		sess.Remote = fmt.Sprintf("http://%s:%s/wd/hub", host, port)
	}

	// Best-effort CDP enable for Chrome/Edge.
	if strings.EqualFold(sess.Browser, ChromeBrowser) || strings.EqualFold(sess.Browser, "edge") {
		wdSession := sess.driver.SessionID()
		if wdSession != "" {
			_, _ = cdpExecute(sess.Remote, wdSession, "Network.enable", map[string]any{})
			_, _ = cdpExecute(sess.Remote, wdSession, "Runtime.enable", map[string]any{})
		}
	} else {
		warning = fmt.Sprintf("capture enabled, but browser %q is not supported (Chrome/Edge only)", sess.Browser)
	}

	_ = ctx
	return &CaptureStartOutput{SessionID: sess.ID, Enabled: true, Warning: warning}, nil
}

func (s *Service) CaptureStop(_ context.Context, in *CaptureStopInput) (*CaptureStopOutput, error) {
	if in == nil {
		in = &CaptureStopInput{}
	}
	sessionID := in.SessionID
	if sessionID == "" {
		sessionID = "localhost:4444"
	}
	sess, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	if sess.capture != nil {
		sess.capture.Drain(sess)
		_ = sess.capture.FlushSink()
		_ = sess.capture.CloseSink()
	}
	return &CaptureStopOutput{SessionID: sess.ID, Summary: captureSummary(sess)}, nil
}

func (s *Service) CaptureStatus(_ context.Context, in *CaptureStatusInput) (*CaptureStatusOutput, error) {
	if in == nil {
		in = &CaptureStatusInput{}
	}
	sessionID := in.SessionID
	if sessionID == "" {
		sessionID = "localhost:4444"
	}
	sess, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	return &CaptureStatusOutput{SessionID: sess.ID, Summary: captureSummary(sess)}, nil
}

func (s *Service) CaptureClear(_ context.Context, in *CaptureClearInput) (*CaptureClearOutput, error) {
	if in == nil {
		in = &CaptureClearInput{}
	}
	sessionID := in.SessionID
	if sessionID == "" {
		sessionID = "localhost:4444"
	}
	sess, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	if sess.capture != nil {
		sess.capture.Clear()
	}
	return &CaptureClearOutput{SessionID: sess.ID}, nil
}

func (s *Service) CaptureExport(_ context.Context, in *CaptureExportInput) (*CaptureExportOutput, error) {
	if in == nil {
		in = &CaptureExportInput{}
	}
	sessionID := in.SessionID
	if sessionID == "" {
		sessionID = "localhost:4444"
	}
	sess, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	if sess.capture == nil {
		return nil, fmt.Errorf("capture not started for session: %s", sess.ID)
	}
	sess.capture.Drain(sess)

	includeConsole := true
	includeNetwork := true
	if in.IncludeConsole != nil {
		includeConsole = *in.IncludeConsole
	}
	if in.IncludeNetwork != nil {
		includeNetwork = *in.IncludeNetwork
	}
	console, network := sess.capture.Snapshot(in.MaxEntries, includeConsole, includeNetwork)
	return &CaptureExportOutput{SessionID: sess.ID, Summary: sess.capture.Summary(), Console: console, Network: network}, nil
}

func captureSummary(sess *Session) *CaptureSummary {
	if sess == nil || sess.capture == nil {
		return &CaptureSummary{}
	}
	return sess.capture.Summary()
}
