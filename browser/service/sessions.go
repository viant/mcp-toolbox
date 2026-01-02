package service

import (
	"context"
	"strconv"
)

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
			DriverVersion:  sess.DriverVersion,
			Capabilities:   append([]string(nil), sess.Capabilities...),
			Open:           open,
			CaptureEnabled: captureEnabled,
		})
	}
	return out, nil
}

func (s *Service) Health(_ context.Context, in *HealthInput) (*HealthOutput, error) {
	if in == nil {
		in = &HealthInput{}
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	out := &HealthOutput{Sessions: []*HealthItem{}}
	for _, sess := range s.sessions {
		if sess == nil {
			continue
		}
		open := sess.driver != nil
		if !in.IncludeAll && !open {
			continue
		}
		status := "unknown"
		host, port := splitHostPort(sess.ID)
		if p, err := strconv.Atoi(port); err == nil {
			if driverStatusOK(host, p) {
				status = "healthy"
			} else {
				status = "unreachable"
			}
		}
		item := &HealthItem{
			SessionID:     sess.ID,
			Open:          open,
			DriverStatus:  status,
			Remote:        sess.Remote,
			DriverPath:    sess.DriverPath,
			DriverVersion: sess.DriverVersion,
		}
		out.Sessions = append(out.Sessions, item)
	}
	return out, nil
}
