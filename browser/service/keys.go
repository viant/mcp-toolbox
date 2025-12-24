package service

import (
	"strings"

	"github.com/tebeka/selenium"
	"github.com/viant/toolbox/data"
)

func ensureSessionState(sess *Session) {
	if sess == nil {
		return
	}
	if sess.state == nil {
		sess.state = data.Map{}
	}
	initBuiltinKeys(sess.state)
}

func initBuiltinKeys(state data.Map) {
	if state == nil {
		return
	}
	// Common Endly-style key constants used in commands like sendKeys(${KEY_ENTER}).
	// Keep names stable and uppercase.
	add := func(name string, value string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, exists := state[name]; exists {
			return
		}
		state[name] = value
	}
	add("KEY_ENTER", selenium.EnterKey)
	add("KEY_RETURN", selenium.EnterKey)
	add("KEY_TAB", selenium.TabKey)
	add("KEY_ESCAPE", selenium.EscapeKey)
	add("KEY_BACKSPACE", selenium.BackspaceKey)
	add("KEY_DELETE", selenium.DeleteKey)
	add("KEY_SPACE", selenium.SpaceKey)
	add("KEY_HOME", selenium.HomeKey)
	add("KEY_END", selenium.EndKey)
	add("KEY_PAGEUP", selenium.PageUpKey)
	add("KEY_PAGEDOWN", selenium.PageDownKey)
	add("KEY_LEFT", selenium.LeftArrowKey)
	add("KEY_RIGHT", selenium.RightArrowKey)
	add("KEY_UP", selenium.UpArrowKey)
	add("KEY_DOWN", selenium.DownArrowKey)
}
