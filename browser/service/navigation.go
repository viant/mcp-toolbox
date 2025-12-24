package service

import (
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
