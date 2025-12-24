package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tebeka/selenium"
)

func (s *Service) Screenshot(ctx context.Context, in *ScreenshotInput) (*ScreenshotOutput, error) {
	if in == nil {
		in = &ScreenshotInput{}
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

	var png []byte
	switch {
	case in.FullPage:
		png, err = s.fullPagePNG(sess)
		if err != nil {
			// best-effort fallback
			png, err = sess.driver.Screenshot()
		}
	case in.Selector != nil:
		png, err = s.elementPNG(sess, in.Selector, in.MaxWaitMs, in.ScrollIntoView)
	default:
		png, err = sess.driver.Screenshot()
	}
	if err != nil {
		return nil, err
	}

	out := &ScreenshotOutput{SessionID: sessionID, DestURL: in.DestURL, Bytes: len(png)}
	if in.DestURL != "" {
		if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader(png)); err != nil {
			return nil, err
		}
		return out, nil
	}
	out.Encoding = "base64"
	out.Data = base64.StdEncoding.EncodeToString(png)
	return out, nil
}

func (s *Service) elementPNG(sess *Session, selector *WebElementSelector, maxWaitMs int, scrollIntoView *bool) ([]byte, error) {
	if selector == nil {
		return nil, fmt.Errorf("selector was nil")
	}
	if err := selector.Validate(); err != nil {
		return nil, err
	}
	wait := defaultFindElementTimeout
	if maxWaitMs > 0 {
		wait = time.Duration(maxWaitMs) * time.Millisecond
	}
	var (
		elem selenium.WebElement
		err  error
	)
	err = sess.driver.WaitWithTimeout(func(wd selenium.WebDriver) (bool, error) {
		elem, err = sess.driver.FindElement(selector.By, selector.Value)
		if elem != nil {
			return true, nil
		}
		return false, nil
	}, wait)
	if err != nil || elem == nil {
		return nil, fmt.Errorf("failed to lookup element: %s %s, %v", selector.By, selector.Value, err)
	}
	scroll := true
	if scrollIntoView != nil {
		scroll = *scrollIntoView
	}
	return elem.Screenshot(scroll)
}

func (s *Service) fullPagePNG(sess *Session) ([]byte, error) {
	if sess == nil || sess.driver == nil || sess.Remote == "" {
		return nil, fmt.Errorf("missing session remote")
	}
	wdSession := sess.driver.SessionID()
	if wdSession == "" {
		return nil, fmt.Errorf("missing webdriver session id")
	}
	// CDP: Page.captureScreenshot returns {data:"base64..."}.
	raw, err := cdpExecute(sess.Remote, wdSession, "Page.captureScreenshot", map[string]any{
		"format":                "png",
		"fromSurface":           true,
		"captureBeyondViewport": true,
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.Data == "" {
		return nil, fmt.Errorf("empty screenshot data")
	}
	return base64.StdEncoding.DecodeString(resp.Data)
}
