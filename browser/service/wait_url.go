package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func (s *Service) WaitURL(ctx context.Context, in *WaitURLInput) (*WaitURLOutput, error) {
	if in == nil {
		in = &WaitURLInput{}
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

	exact := strings.TrimSpace(in.Exact)
	contains := strings.TrimSpace(in.Contains)
	regexStr := strings.TrimSpace(in.Regex)
	if exact == "" && contains == "" && regexStr == "" {
		return nil, fmt.Errorf("one of exact|contains|regex is required")
	}

	var re *regexp.Regexp
	if regexStr != "" {
		r, err := regexp.Compile(regexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		re = r
	}

	timeoutMs := in.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 10000
	}
	pollMs := in.PollMs
	if pollMs <= 0 {
		pollMs = 200
	}

	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		sess.lock.Lock()
		hrefAny, _ := sess.driver.ExecuteScript("return window.location.href;", nil)
		sess.lock.Unlock()
		href := fmt.Sprintf("%v", hrefAny)

		ok := false
		switch {
		case exact != "":
			ok = href == exact
		case contains != "":
			ok = strings.Contains(href, contains)
		case re != nil:
			ok = re.MatchString(href)
		}
		if ok {
			return &WaitURLOutput{SessionID: in.SessionID, URL: href}, nil
		}
		time.Sleep(time.Duration(pollMs) * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for url")
}

