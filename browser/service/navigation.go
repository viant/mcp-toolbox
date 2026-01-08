package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tebeka/selenium"
	"github.com/viant/toolbox"
)

func isGetMethod(method string) bool { return strings.EqualFold(method, "Get") }

func navigationWithDefaults(nav *NavigationOptions) NavigationOptions {
	if nav == nil {
		nav = &NavigationOptions{}
	}
	out := *nav
	if out.TimeoutMs <= 0 {
		out.TimeoutMs = 45000
	}
	if out.AutoScrollMs < 0 {
		out.AutoScrollMs = 0
	}
	if out.ScrollDelayMs <= 0 {
		out.ScrollDelayMs = 300
	}
	if out.StableWindowMs <= 0 {
		out.StableWindowMs = 1500
	}
	if out.MaxScrollSteps <= 0 {
		out.MaxScrollSteps = 30
	}
	if out.IdleThreshold < 0 {
		out.IdleThreshold = 0
	}
	if out.IdleWindowMs <= 0 {
		out.IdleWindowMs = 1500
	}
	if out.IdleMaxWaitMs < 0 {
		out.IdleMaxWaitMs = 0
	}
	return out
}

func (s *Service) getWithGuard(sess *Session, URL string, nav NavigationOptions) error {
	if sess == nil || sess.driver == nil {
		return fmt.Errorf("webdriver session not open")
	}
	_ = sess.driver.SetPageLoadTimeout(time.Duration(nav.TimeoutMs) * time.Millisecond)
	err := sess.driver.Get(URL)
	if err == nil {
		return nil
	}
	if !isPageLoadTimeout(err) {
		return err
	}
	// warn/continue
	sess.state.Put("_webdriver_last_nav_timeout", err.Error())
	if nav.AutoScrollMs > 0 {
		if sess.capture == nil && sess.net == nil {
			sess.net = &netTracker{}
		}
		s.autoScrollStabilize(sess, nav)
	}
	return nil
}

func (s *Service) afterNavigate(ctx context.Context, sess *Session, nav NavigationOptions) error {
	if sess == nil || sess.driver == nil {
		return fmt.Errorf("webdriver session not open")
	}
	// Ensure a network tracker exists when idle detection is requested.
	if (nav.IdleMaxWaitMs > 0 || nav.IdleThreshold > 0) && sess.capture == nil && sess.net == nil {
		sess.net = &netTracker{}
	}

	if err := s.waitDocumentReady(sess, time.Duration(nav.TimeoutMs)*time.Millisecond); err != nil {
		// Treat readiness as best-effort; return errors since callers often rely on it for determinism.
		return err
	}

	// Optional post-nav wait for selector/locator.
	waitLoc := nav.WaitFor
	if waitLoc == nil && strings.TrimSpace(nav.WaitForSelector) != "" {
		waitLoc = &Locator{CSS: strings.TrimSpace(nav.WaitForSelector)}
	}
	if waitLoc != nil {
		state := strings.ToLower(strings.TrimSpace(nav.WaitForState))
		if state == "" {
			state = WaitStateVisible
		}
		// Back-compat: some callers set WaitForState to common navigation states. Treat them
		// as presets instead of erroring inside Wait().
		switch state {
		case "load", "domcontentloaded", "dom-content-loaded", "dom_content_loaded":
			state = WaitStateAttached
		case "networkidle", "network-idle", "network_idle":
			state = WaitStateAttached
			// If idle wait wasn't explicitly requested, enable it with sensible defaults.
			if nav.IdleMaxWaitMs <= 0 && nav.IdleThreshold <= 0 {
				nav.IdleThreshold = 2
				nav.IdleWindowMs = 1000
				nav.IdleMaxWaitMs = nav.TimeoutMs
			}
		}
		_, err := s.Wait(ctx, &WaitInput{
			SessionID:   sess.ID,
			Locator:     waitLoc,
			State:       state,
			TimeoutMs:   nav.TimeoutMs,
			PollMs:      defaultFindPollMs,
			VisibleOnly: state == WaitStateVisible,
		})
		if err != nil {
			return err
		}
	}

	// Optional idle wait (with or without auto-scroll).
	if nav.IdleMaxWaitMs > 0 || nav.IdleThreshold > 0 {
		s.waitNetworkIdle(sess, nav)
	}
	return nil
}

func (s *Service) waitDocumentReady(sess *Session, timeout time.Duration) error {
	if sess == nil || sess.driver == nil {
		return fmt.Errorf("webdriver session not open")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sess.lock.Lock()
		v, err := sess.driver.ExecuteScript("return document.readyState;", nil)
		sess.lock.Unlock()
		if err == nil {
			if st, ok := v.(string); ok {
				if st == "complete" || st == "interactive" {
					return nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("document did not reach ready state within %s", timeout)
}

func (s *Service) waitNetworkIdle(sess *Session, nav NavigationOptions) {
	maxWaitMs := nav.IdleMaxWaitMs
	if maxWaitMs <= 0 {
		maxWaitMs = nav.TimeoutMs
	}
	deadline := time.Now().Add(time.Duration(maxWaitMs) * time.Millisecond)
	idleWindow := time.Duration(nav.IdleWindowMs) * time.Millisecond
	idleSince := time.Time{}

	for time.Now().Before(deadline) {
		if s.isNetworkIdle(sess, nav.IdleThreshold, idleWindow, &idleSince) {
			return
		}
		time.Sleep(200 * time.Millisecond)
		sess.drainTrackers()
	}
}

func isPageLoadTimeout(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return true
	}
	var sErr *selenium.Error
	if errors.As(err, &sErr) {
		if sErr.LegacyCode == 21 {
			return true
		}
		if strings.Contains(strings.ToLower(sErr.Message), "timeout") {
			return true
		}
	}
	return false
}

func (s *Service) autoScrollStabilize(sess *Session, nav NavigationOptions) {
	maxWaitMs := nav.IdleMaxWaitMs
	if maxWaitMs == 0 {
		if nav.AutoScrollMs > 0 {
			maxWaitMs = nav.AutoScrollMs
		} else {
			maxWaitMs = nav.TimeoutMs
		}
	}
	deadline := time.Now().Add(time.Duration(maxWaitMs) * time.Millisecond)
	delay := time.Duration(nav.ScrollDelayMs) * time.Millisecond
	stableWindow := time.Duration(nav.StableWindowMs) * time.Millisecond
	idleWindow := time.Duration(nav.IdleWindowMs) * time.Millisecond

	lastHeight := float64(-1)
	stableSince := time.Now()
	idleSince := time.Time{}

	for step := 0; step < nav.MaxScrollSteps && time.Now().Before(deadline); step++ {
		height := s.scrollHeight(sess)
		if height >= 0 && height == lastHeight {
			if time.Since(stableSince) >= stableWindow {
				if s.isNetworkIdle(sess, nav.IdleThreshold, idleWindow, &idleSince) {
					return
				}
			}
		} else {
			stableSince = time.Now()
			lastHeight = height
		}

		_, _ = sess.driver.ExecuteScript("window.scrollBy(0, window.innerHeight || 800);", nil)
		time.Sleep(delay)
		sess.drainTrackers()
		if time.Since(stableSince) >= stableWindow && s.isNetworkIdle(sess, nav.IdleThreshold, idleWindow, &idleSince) {
			return
		}
	}
}

func (s *Service) isNetworkIdle(sess *Session, threshold int, window time.Duration, idleSince *time.Time) bool {
	inflight := -1
	if sess.capture != nil {
		inflight = sess.capture.Summary().RequestsInFlight
	} else if sess.net != nil {
		inflight = sess.net.Inflight()
	}
	if inflight < 0 {
		return true
	}
	if inflight <= threshold {
		if idleSince != nil && idleSince.IsZero() {
			*idleSince = time.Now()
		}
		if idleSince == nil {
			return true
		}
		return time.Since(*idleSince) >= window
	}
	if idleSince != nil {
		*idleSince = time.Time{}
	}
	return false
}

func (s *Service) scrollHeight(sess *Session) float64 {
	if sess == nil || sess.driver == nil {
		return -1
	}
	v, err := sess.driver.ExecuteScript("return (document.body && document.body.scrollHeight) ? document.body.scrollHeight : 0;", nil)
	if err != nil {
		return -1
	}
	switch actual := v.(type) {
	case float64:
		return actual
	case int:
		return float64(actual)
	case int64:
		return float64(actual)
	case uint64:
		return float64(actual)
	case string:
		return toolbox.AsFloat(actual)
	default:
		return toolbox.AsFloat(actual)
	}
}
