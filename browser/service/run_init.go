package service

import (
	"fmt"
	"strings"

	"github.com/viant/toolbox"
)

const defaultExitWaitTimeMs = 1000

func (r *RunInput) initFromCommands() error {
	if len(r.Commands) == 0 {
		return nil
	}
	expectMap := r.expectMap()
	r.Actions = make([]*Action, 0)
	var previousAction *Action
	p := &parser{}
	for _, candidate := range r.Commands {
		command, ok := candidate.(string)
		if !ok {
			action, err := r.asWaitAction(p, candidate)
			if err != nil {
				return err
			}
			r.setWaitExitIfNeeded(action.Calls[0], expectMap, action)
			r.Actions = append(r.Actions, action)
			previousAction = action
			continue
		}
		action, err := p.Parse(command)
		if err != nil {
			return fmt.Errorf("invalid command: %v, %v", command, err)
		}
		if previousAction != nil && previousAction.Selector != nil && action.Selector != nil && previousAction.Selector.Value == action.Selector.Value {
			if action.Key == "" && isReadMethod(action.Calls[0].Method) && isReadMethod(previousAction.Calls[0].Method) {
				previousAction.Calls = append(previousAction.Calls, action.Calls[0])
				previousAction.PathKind = PathKindComposite
				continue
			}
		}
		r.Actions = append(r.Actions, action)
		previousAction = action
		call := action.Calls[0]
		r.setWaitExitIfNeeded(call, expectMap, action)
	}
	return nil
}

func (r *RunInput) asWaitAction(p *parser, candidate any) (*Action, error) {
	aMap, ok := candidate.(map[string]any)
	if !ok {
		if m, ok := candidate.(map[any]any); ok {
			aMap = map[string]any{}
			for k, v := range m {
				aMap[toolbox.AsString(k)] = v
			}
		} else {
			return nil, fmt.Errorf("unsupported command: %T", candidate)
		}
	}
	command, ok := aMap["command"]
	if !ok {
		return nil, fmt.Errorf("command was missing: %v", candidate)
	}
	action, err := p.Parse(toolbox.AsString(command))
	if err != nil {
		return nil, err
	}
	if action.PathKind == PathKindUndefined {
		action.PathKind = PathKindSimple
	}
	call := action.Calls[0]
	// Assign wait fields from map keys (matching Endly naming).
	if v, ok := aMap["waitTimeMs"]; ok {
		call.WaitTimeMs = toolbox.AsInt(v)
	}
	if v, ok := aMap["thinkTimeMs"]; ok {
		call.ThinkTimeMs = toolbox.AsInt(v)
	}
	if v, ok := aMap["ignoreTimeout"]; ok {
		call.IgnoreTimeout = toolbox.AsBoolean(v)
	}
	if v, ok := aMap["exit"]; ok {
		call.Exit = toolbox.AsString(v)
	}
	return action, nil
}

func (r *RunInput) setWaitExitIfNeeded(call *MethodCall, expectMap map[string]any, action *Action) {
	if call.Exit != "" {
		return
	}
	if expectValue, ok := expectMap[action.Key]; ok && expectValue != nil {
		switch actual := expectValue.(type) {
		case string:
			call.Exit = "$" + action.Key + " contains " + actual
		case int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8:
			call.Exit = "$" + action.Key + " = " + toolbox.AsString(expectValue)
		case float64:
			call.Exit = "$" + action.Key + " = " + toolbox.AsString(expectValue)
		default:
			_ = actual
		}
		if call.Exit != "" {
			if call.WaitTimeMs == 0 {
				call.WaitTimeMs = defaultExitWaitTimeMs
			}
			call.IgnoreTimeout = true
		}
	}
}

func isReadMethod(method string) bool {
	return strings.HasPrefix(method, "Get") || strings.HasPrefix(method, "Text")
}

func (r *RunInput) expectMap() map[string]any {
	expectMap := map[string]any{}
	if r.Expect == nil {
		return expectMap
	}
	if v, ok := r.Expect.(map[string]any); ok {
		return v
	}
	if v, ok := r.Expect.(map[any]any); ok {
		for k, val := range v {
			expectMap[toolbox.AsString(k)] = val
		}
	}
	return expectMap
}

func (r *RunInput) NavigationCaps() []string { return nil }
