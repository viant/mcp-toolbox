package service

import (
	"testing"

	"github.com/tebeka/selenium"
	"github.com/viant/toolbox/data"
)

func TestBuiltinKeysExpand(t *testing.T) {
	state := data.Map{}
	initBuiltinKeys(state)
	got := state.Expand("${KEY_ENTER}")
	if got != selenium.EnterKey {
		t.Fatalf("expected EnterKey, got %q", got)
	}
}
