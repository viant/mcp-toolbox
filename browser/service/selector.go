package service

import (
	"fmt"
	"strings"

	"github.com/tebeka/selenium"
	"github.com/viant/toolbox"
)

type WebSelector string

var supportedSelectors = map[string]bool{
	selenium.ByCSSSelector:     true,
	selenium.ByClassName:       true,
	selenium.ByTagName:         true,
	selenium.ByXPATH:           true,
	selenium.ByID:              true,
	selenium.ByLinkText:        true,
	selenium.ByPartialLinkText: true,
}

// ByAndValue returns Selenium selector type and value.
func (s WebSelector) ByAndValue() (string, string) {
	selector := string(s)
	if selector == "" {
		return selenium.ByXPATH, selector
	}
	if strings.HasPrefix(selector, "css:") {
		return selenium.ByCSSSelector, selector[4:]
	}
	if strings.HasPrefix(selector, "xpath:") {
		return selenium.ByXPATH, selector[6:]
	}
	if strings.HasPrefix(selector, "#") {
		return selenium.ByCSSSelector, selector
	}
	if strings.HasPrefix(selector, ".") {
		// class selector
		return selenium.ByCSSSelector, selector
	}
	if strings.HasPrefix(selector, "//") || strings.HasPrefix(selector, "(/") {
		return selenium.ByXPATH, selector
	}
	return selenium.ByXPATH, selector
}

func (s *WebElementSelector) Init() error {
	if s.By == "" && s.Value != "" {
		ws := WebSelector(s.Value)
		s.By, s.Value = ws.ByAndValue()
	}
	return nil
}

func (s *WebElementSelector) Validate() error {
	if s == nil {
		return fmt.Errorf("selector was nil")
	}
	if err := s.Init(); err != nil {
		return err
	}
	if s.By == "" || s.Value == "" {
		return fmt.Errorf("selector By and Value are required")
	}
	if !supportedSelectors[s.By] {
		return fmt.Errorf("unsupported selector By: %s", s.By)
	}
	return nil
}

func toolboxAsFloat(v any) float64 { return toolbox.AsFloat(v) }
