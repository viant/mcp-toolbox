package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tebeka/selenium"
)

func isElementClickIntercepted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "element click intercepted") ||
		strings.Contains(msg, "other element would receive the click")
}

func (s *Service) scrollIntoView(driver selenium.WebDriver, el selenium.WebElement) {
	if driver == nil || el == nil {
		return
	}
	// Best-effort: ignore errors (some drivers/pages can reject script execution during transitions).
	_, _ = driver.ExecuteScript("arguments[0].scrollIntoView({block:'center', inline:'center', behavior:'instant'});", []any{el})
}

func (s *Service) jsClick(driver selenium.WebDriver, el selenium.WebElement) error {
	if driver == nil || el == nil {
		return fmt.Errorf("missing driver/element")
	}
	_, err := driver.ExecuteScript("arguments[0].click();", []any{el})
	return err
}

func (s *Service) hoverElement(driver selenium.WebDriver, el selenium.WebElement) error {
	if driver == nil || el == nil {
		return fmt.Errorf("missing driver/element")
	}
	s.scrollIntoView(driver, el)
	_, err := driver.ExecuteScript(`
		(function(el){
			if(!el) return;
			var opts = {bubbles:true, cancelable:true, view:window};
			['mouseover','mouseenter','mousemove'].forEach(function(t){
				el.dispatchEvent(new MouseEvent(t, opts));
			});
		})(arguments[0]);
	`, []any{el})
	return err
}

func (s *Service) resolveSingleElement(ctx context.Context, sess *Session, locator *Locator, timeoutMs int, strict bool, visibleOnly bool) (selenium.WebElement, *FindMatch, error) {
	if sess == nil || sess.driver == nil {
		return nil, nil, fmt.Errorf("session not open")
	}
	if locator == nil {
		return nil, nil, fmt.Errorf("locator is required")
	}
	if handle := strings.TrimSpace(locator.Handle); handle != "" {
		el, ok := sess.getHandle(handle)
		if !ok || el == nil {
			return nil, nil, fmt.Errorf("unknown handle: %s", handle)
		}
		// Best-effort match metadata for handle-based calls.
		return el, &FindMatch{Handle: handle}, nil
	}
	elements, matches, err := s.ResolveLocator(ctx, sess, locator, &ResolveLocatorOptions{
		MaxWaitMs:  timeoutMs,
		MinMatches: 1,
		// Allow multiple matches so we can skip non-actionable elements (e.g. <html>/<body>)
		// and still resolve a real element by selector.
		MaxMatches:         defaultFindMax,
		Strict:             strict,
		VisibleOnly:        visibleOnly,
		ResolveElements:    true,
		ResolveAllElements: false,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(elements) == 0 {
		return nil, nil, fmt.Errorf("no element matched locator")
	}
	var match *FindMatch
	if len(matches) > 0 {
		m := matches[0]
		match = &m
	}
	return elements[0], match, nil
}

func (s *Service) Click(ctx context.Context, in *ClickInput) (*ClickOutput, error) {
	if in == nil {
		in = &ClickInput{}
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
	visibleOnly := in.VisibleOnly
	if !visibleOnly {
		visibleOnly = true
	}
	el, match, err := s.resolveSingleElement(ctx, sess, in.Locator, in.TimeoutMs, in.Strict, visibleOnly)
	if err != nil {
		return nil, err
	}
	sess.lock.Lock()
	defer sess.lock.Unlock()
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := ensureEnabled(el); err != nil {
		return nil, err
	}
	// Many modern UIs (modals/flyouts/sticky headers) can intercept clicks. Be resilient:
	// - scroll into view
	// - retry native click
	// - fallback to JS click for intercepted-click errors
	s.scrollIntoView(sess.driver, el)
	if err := el.Click(); err != nil {
		if isElementClickIntercepted(err) {
			time.Sleep(75 * time.Millisecond)
			s.scrollIntoView(sess.driver, el)
			if err2 := el.Click(); err2 == nil {
				err = nil
			} else if jsErr := s.jsClick(sess.driver, el); jsErr == nil {
				err = nil
			} else {
				err = err2
			}
		}
		if err != nil {
			if isStaleElementError(err) {
				sess.deleteHandle(in.Locator.Handle)
			}
			return nil, err
		}
	}
	out := &ClickOutput{SessionID: in.SessionID}
	out.Match = match
	if in.Locator != nil && strings.TrimSpace(in.Locator.Handle) != "" {
		sess.deleteHandle(in.Locator.Handle)
	}
	return out, nil
}

func (s *Service) Hover(ctx context.Context, in *HoverInput) (*HoverOutput, error) {
	if in == nil {
		in = &HoverInput{}
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
	visibleOnly := in.VisibleOnly
	if !visibleOnly {
		visibleOnly = true
	}
	el, match, err := s.resolveSingleElement(ctx, sess, in.Locator, in.TimeoutMs, in.Strict, visibleOnly)
	if err != nil {
		return nil, err
	}
	sess.lock.Lock()
	defer sess.lock.Unlock()
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := s.hoverElement(sess.driver, el); err != nil {
		if isStaleElementError(err) {
			sess.deleteHandle(in.Locator.Handle)
		}
		return nil, err
	}
	out := &HoverOutput{SessionID: in.SessionID}
	out.Match = match
	return out, nil
}

func (s *Service) Fill(ctx context.Context, in *FillInput) (*FillOutput, error) {
	if in == nil {
		in = &FillInput{}
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
	visibleOnly := in.VisibleOnly
	if !visibleOnly {
		visibleOnly = true
	}
	el, match, err := s.resolveSingleElement(ctx, sess, in.Locator, in.TimeoutMs, in.Strict, visibleOnly)
	if err != nil {
		return nil, err
	}
	sess.lock.Lock()
	defer sess.lock.Unlock()
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := ensureEnabled(el); err != nil {
		return nil, err
	}
	if in.ClearFirst {
		_ = el.Clear()
	}
	if err := el.SendKeys(in.Text); err != nil {
		if isStaleElementError(err) {
			sess.deleteHandle(in.Locator.Handle)
		}
		return nil, err
	}
	out := &FillOutput{SessionID: in.SessionID}
	out.Match = match
	if in.Locator != nil && strings.TrimSpace(in.Locator.Handle) != "" {
		sess.deleteHandle(in.Locator.Handle)
	}
	return out, nil
}

func (s *Service) Press(ctx context.Context, in *PressInput) (*PressOutput, error) {
	if in == nil {
		in = &PressInput{}
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
	key := strings.TrimSpace(in.Key)
	if key == "" {
		return nil, fmt.Errorf("key is required")
	}
	visibleOnly := in.VisibleOnly
	if !visibleOnly {
		visibleOnly = true
	}
	el, match, err := s.resolveSingleElement(ctx, sess, in.Locator, in.TimeoutMs, in.Strict, visibleOnly)
	if err != nil {
		return nil, err
	}
	sess.lock.Lock()
	defer sess.lock.Unlock()
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := ensureEnabled(el); err != nil {
		return nil, err
	}
	sk := normalizeKey(key)
	if err := el.SendKeys(sk); err != nil {
		if isStaleElementError(err) {
			sess.deleteHandle(in.Locator.Handle)
		}
		return nil, err
	}
	out := &PressOutput{SessionID: in.SessionID}
	out.Match = match
	if in.Locator != nil && strings.TrimSpace(in.Locator.Handle) != "" {
		sess.deleteHandle(in.Locator.Handle)
	}
	return out, nil
}

func ensureEnabled(el selenium.WebElement) error {
	var err error
	for i := 0; i < 10; i++ {
		ok, e := el.IsEnabled()
		if e == nil && ok {
			return nil
		}
		err = e
		time.Sleep(150 * time.Millisecond)
	}
	return err
}

func normalizeKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "enter", "return":
		return selenium.EnterKey
	case "tab":
		return selenium.TabKey
	case "escape", "esc":
		return selenium.EscapeKey
	case "backspace":
		return selenium.BackspaceKey
	case "delete", "del":
		return selenium.DeleteKey
	case "space":
		return selenium.SpaceKey
	case "home":
		return selenium.HomeKey
	case "end":
		return selenium.EndKey
	case "pageup":
		return selenium.PageUpKey
	case "pagedown":
		return selenium.PageDownKey
	case "left":
		return selenium.LeftArrowKey
	case "right":
		return selenium.RightArrowKey
	case "up":
		return selenium.UpArrowKey
	case "down":
		return selenium.DownArrowKey
	default:
		return key
	}
}
