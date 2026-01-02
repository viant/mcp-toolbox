package service

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Service) Wait(ctx context.Context, in *WaitInput) (*WaitOutput, error) {
	if in == nil {
		in = &WaitInput{}
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
	if in.Locator == nil {
		return nil, fmt.Errorf("locator is required")
	}

	state := strings.ToLower(strings.TrimSpace(in.State))
	if state == "" {
		state = WaitStateVisible
	}
	timeoutMs := in.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultFindWaitMs
	}
	pollMs := in.PollMs
	if pollMs <= 0 {
		pollMs = defaultFindPollMs
	}

	start := time.Now()
	for time.Since(start) < time.Duration(timeoutMs)*time.Millisecond {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ok, match, err := s.checkWaitState(ctx, sess, in.Locator, state, in.VisibleOnly, timeoutMs)
		if err != nil {
			return nil, err
		}
		if ok {
			return &WaitOutput{SessionID: in.SessionID, State: state, Match: match}, nil
		}
		time.Sleep(time.Duration(pollMs) * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for state %q", state)
}

func (s *Service) checkWaitState(_ context.Context, sess *Session, loc *Locator, state string, visibleOnly bool, _ int) (bool, *FindMatch, error) {
	if loc == nil {
		return false, nil, fmt.Errorf("locator is required")
	}
	handle := strings.TrimSpace(loc.Handle)
	if handle != "" {
		el, ok := sess.getHandle(handle)
		if !ok || el == nil {
			return state == WaitStateDetached, nil, nil
		}
		sess.lock.Lock()
		defer sess.lock.Unlock()
		disp, err := el.IsDisplayed()
		if err != nil {
			if isStaleElementError(err) {
				sess.deleteHandle(handle)
				return state == WaitStateDetached, nil, nil
			}
			return false, nil, err
		}
		switch state {
		case WaitStateVisible:
			return disp, &FindMatch{Handle: handle, Visible: disp}, nil
		case WaitStateHidden:
			return !disp, &FindMatch{Handle: handle, Visible: disp}, nil
		case WaitStateAttached:
			return true, &FindMatch{Handle: handle, Visible: disp}, nil
		case WaitStateDetached:
			return false, nil, nil
		default:
			return false, nil, fmt.Errorf("unsupported wait state: %s", state)
		}
	}

	switch state {
	case WaitStateVisible:
		if !visibleOnly {
			visibleOnly = true
		}
		matches, err := s.findOnce(sess, loc, 1, visibleOnly, true)
		if err != nil {
			return false, nil, err
		}
		if len(matches) == 0 {
			return false, nil, nil
		}
		return true, matches[0], nil
	case WaitStateAttached:
		matches, err := s.findOnce(sess, loc, 1, false, true)
		if err != nil {
			return false, nil, err
		}
		if len(matches) == 0 {
			return false, nil, nil
		}
		return true, matches[0], nil
	case WaitStateDetached:
		matches, err := s.findOnce(sess, loc, 1, false, true)
		if err != nil {
			return false, nil, err
		}
		return len(matches) == 0, nil, nil
	case WaitStateHidden:
		matches, err := s.findOnce(sess, loc, 1, false, true)
		if err != nil {
			return false, nil, err
		}
		if len(matches) == 0 {
			return false, nil, nil
		}
		// findOnce returns Visible value regardless of visibleOnly.
		return !matches[0].Visible, matches[0], nil
	default:
		return false, nil, fmt.Errorf("unsupported wait state: %s", state)
	}
}
