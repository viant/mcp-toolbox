package service

import "context"

func (s *Service) Sessions(_ context.Context, in *SessionsInput) (*SessionsOutput, error) {
	if in == nil {
		in = &SessionsInput{}
	}
	s.mux.Lock()
	defer s.mux.Unlock()

	out := &SessionsOutput{Sessions: make([]*SessionInfo, 0, len(s.sessions))}
	for _, sess := range s.sessions {
		if sess == nil {
			continue
		}
		open := sess.driver != nil
		if !in.IncludeAll && !open {
			continue
		}
		captureEnabled := sess.capture != nil && sess.capture.enabled
		out.Sessions = append(out.Sessions, &SessionInfo{
			SessionID:      sess.ID,
			Browser:        sess.Browser,
			Remote:         sess.Remote,
			DriverPath:     sess.DriverPath,
			Capabilities:   append([]string(nil), sess.Capabilities...),
			Open:           open,
			CaptureEnabled: captureEnabled,
		})
	}
	return out, nil
}
