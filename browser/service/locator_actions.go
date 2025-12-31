package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tebeka/selenium"
)

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
	elements, matches, err := s.ResolveLocator(ctx, sess, in.Locator, &ResolveLocatorOptions{
		MaxWaitMs:          in.TimeoutMs,
		MinMatches:         1,
		MaxMatches:         1,
		Strict:             in.Strict,
		VisibleOnly:        visibleOnly,
		ResolveElements:    true,
		ResolveAllElements: false,
	})
	if err != nil {
		return nil, err
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("no element matched locator")
	}
	el := elements[0]
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := ensureEnabled(el); err != nil {
		return nil, err
	}
	if err := el.Click(); err != nil {
		return nil, err
	}
	out := &ClickOutput{SessionID: in.SessionID}
	if len(matches) > 0 {
		m := matches[0]
		out.Match = &m
	}
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
	elements, matches, err := s.ResolveLocator(ctx, sess, in.Locator, &ResolveLocatorOptions{
		MaxWaitMs:          in.TimeoutMs,
		MinMatches:         1,
		MaxMatches:         1,
		Strict:             in.Strict,
		VisibleOnly:        visibleOnly,
		ResolveElements:    true,
		ResolveAllElements: false,
	})
	if err != nil {
		return nil, err
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("no element matched locator")
	}
	el := elements[0]
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
		return nil, err
	}
	out := &FillOutput{SessionID: in.SessionID}
	if len(matches) > 0 {
		m := matches[0]
		out.Match = &m
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
	elements, matches, err := s.ResolveLocator(ctx, sess, in.Locator, &ResolveLocatorOptions{
		MaxWaitMs:          in.TimeoutMs,
		MinMatches:         1,
		MaxMatches:         1,
		Strict:             in.Strict,
		VisibleOnly:        visibleOnly,
		ResolveElements:    true,
		ResolveAllElements: false,
	})
	if err != nil {
		return nil, err
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("no element matched locator")
	}
	el := elements[0]
	if err := s.ensureVisible(el); err != nil {
		return nil, err
	}
	if err := ensureEnabled(el); err != nil {
		return nil, err
	}
	sk := normalizeKey(key)
	if err := el.SendKeys(sk); err != nil {
		return nil, err
	}
	out := &PressOutput{SessionID: in.SessionID}
	if len(matches) > 0 {
		m := matches[0]
		out.Match = &m
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

