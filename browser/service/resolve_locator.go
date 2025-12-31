package service

import (
	"context"
	"fmt"
	"time"

	"github.com/tebeka/selenium"
)

// ResolveLocatorOptions control locator resolution and auto-wait behavior.
type ResolveLocatorOptions struct {
	MaxWaitMs   int
	PollMs      int
	MinMatches  int
	MaxMatches  int
	Strict      bool
	VisibleOnly bool

	// ResolveElements attempts to convert returned match selectors into WebElements.
	// This is best-effort: matches without a usable CSS selector are skipped.
	ResolveElements bool
	// ResolveAllElements resolves all returned matches (up to MaxMatches). When false, resolves only the first.
	ResolveAllElements bool
}

// ResolveLocator resolves a Playwright-like Locator to match metadata and (optionally) WebElements.
//
// - It uses the same DOM-side matching logic as browserFind (via ExecuteScript).
// - It auto-waits at the locator resolution layer until MinMatches/Strict are satisfied.
// - When ResolveElements is enabled, it converts generated CSS selectors into WebElements via FindElement(css).
func (s *Service) ResolveLocator(ctx context.Context, sess *Session, locator *Locator, opts *ResolveLocatorOptions) ([]selenium.WebElement, []FindMatch, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("service was nil")
	}
	if sess == nil || sess.driver == nil {
		return nil, nil, fmt.Errorf("session not open")
	}
	if locator == nil {
		return nil, nil, fmt.Errorf("locator is required")
	}

	o := opts
	if o == nil {
		o = &ResolveLocatorOptions{}
	}
	maxWait := o.MaxWaitMs
	if maxWait <= 0 {
		maxWait = defaultFindWaitMs
	}
	poll := o.PollMs
	if poll <= 0 {
		poll = defaultFindPollMs
	}
	min := o.MinMatches
	if min <= 0 {
		min = 1
	}
	max := o.MaxMatches
	if max <= 0 {
		max = defaultFindMax
	}
	if max < 1 {
		max = 1
	}
	if max > 200 {
		max = 200
	}

	start := time.Now()
	var last []*FindMatch
	var lastErr error
	for time.Since(start) < time.Duration(maxWait)*time.Millisecond {
		matches, err := s.findOnce(sess, locator, max, o.VisibleOnly)
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			last = matches
			if o.Strict {
				if len(matches) == 1 {
					break
				}
			} else if len(matches) >= min {
				break
			}
		}
		select {
		case <-ctx.Done():
			break
		case <-time.After(time.Duration(poll) * time.Millisecond):
		}
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}

	// Convert pointer matches to value slice.
	outMatches := make([]FindMatch, 0, len(last))
	for _, m := range last {
		if m == nil {
			continue
		}
		outMatches = append(outMatches, *m)
	}

	if !o.ResolveElements || len(outMatches) == 0 {
		return nil, outMatches, nil
	}

	var elements []selenium.WebElement
	for i := range outMatches {
		if !o.ResolveAllElements && len(elements) > 0 {
			break
		}
		sel := outMatches[i].Selector
		if sel == "" {
			continue
		}
		el, err := sess.driver.FindElement(selenium.ByCSSSelector, sel)
		if err != nil || el == nil {
			continue
		}
		elements = append(elements, el)
	}
	return elements, outMatches, nil
}

