package service

import (
	"strings"

	"github.com/tebeka/selenium"
)

func isStaleElementError(err error) bool {
	if err == nil {
		return false
	}
	if sErr, ok := err.(*selenium.Error); ok {
		// W3C "stale element reference" is legacy code 10 in older selenium libs.
		if sErr.LegacyCode == 10 {
			return true
		}
		msg := strings.ToLower(sErr.Message)
		return strings.Contains(msg, "stale element")
	}
	return strings.Contains(strings.ToLower(err.Error()), "stale element")
}
