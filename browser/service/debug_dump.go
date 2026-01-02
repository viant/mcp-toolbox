package service

import (
	"context"
	"fmt"
)

func (s *Service) DebugDump(ctx context.Context, in *DebugDumpInput) (*DebugDumpOutput, error) {
	if in == nil {
		in = &DebugDumpInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}

	out := &DebugDumpOutput{SessionID: in.SessionID}
	maxBytes := in.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 2_000_000
	}
	maxEntries := in.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 500
	}

	if in.IncludeSource {
		src, err := s.GetSource(ctx, &GetSourceInput{SessionID: in.SessionID, MaxBytes: maxBytes})
		if err != nil {
			out.Warning += "getSource: " + err.Error() + "; "
		} else if src != nil {
			out.Source = src.Data
		}
	}
	if in.IncludeDOM {
		dom, err := s.GetDOM(ctx, &GetDOMInput{SessionID: in.SessionID, Format: "outerHTML", MaxBytes: maxBytes})
		if err != nil {
			out.Warning += "getDOM: " + err.Error() + "; "
		} else if dom != nil {
			out.DOM = dom.OuterHTML
		}
	}
	if in.IncludeConsole || in.IncludeNetwork {
		if sess.capture == nil || !sess.capture.enabled {
			out.Warning += "capture not enabled; "
		} else {
			cap, err := s.CaptureExport(ctx, &CaptureExportInput{
				SessionID:      in.SessionID,
				MaxEntries:     maxEntries,
				IncludeConsole: &in.IncludeConsole,
				IncludeNetwork: &in.IncludeNetwork,
			})
			if err != nil {
				out.Warning += "captureExport: " + err.Error() + "; "
			} else {
				out.Capture = cap
			}
		}
	}
	return out, nil
}
