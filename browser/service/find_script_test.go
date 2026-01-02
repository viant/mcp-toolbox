package service

import (
	"strings"
	"testing"
)

func TestFindScript_CssEscapeIdent_NoRegexLiteral(t *testing.T) {
	// Chrome 143 rejects some regex-literal patterns used for CSS escaping,
	// causing browserFind/browserClick to fail with "Invalid regular expression".
	//
	// This is a lightweight guard to prevent re-introducing that failure mode.
	if strings.Contains(findScript, "replace(/([ #;?%&") {
		t.Fatalf("findScript should not use regex literal based css escaping")
	}
	if !strings.Contains(findScript, "CSS.escape") {
		t.Fatalf("findScript should prefer native CSS.escape when available")
	}
	if !strings.Contains(findScript, "returnSelectors === undefined") {
		t.Fatalf("findScript should default returnSelectors=true for backward compatibility")
	}
}
