package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type asyncScriptTimeoutSetter interface {
	SetAsyncScriptTimeout(time.Duration) error
}

type asyncExecutor interface {
	ExecuteScriptAsync(script string, args []interface{}) (interface{}, error)
}

func (s *Service) EvalJS(ctx context.Context, in *EvalJSInput) (*EvalJSOutput, error) {
	if in == nil {
		in = &EvalJSInput{}
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
	if in.Script == "" {
		return nil, fmt.Errorf("script is required")
	}

	args := make([]interface{}, 0, len(in.Args))
	for _, a := range in.Args {
		args = append(args, a)
	}

	var result any
	if in.Async {
		if in.TimeoutMs > 0 {
			if setter, ok := sess.driver.(asyncScriptTimeoutSetter); ok {
				_ = setter.SetAsyncScriptTimeout(time.Duration(in.TimeoutMs) * time.Millisecond)
			}
		}
		exec, ok := sess.driver.(asyncExecutor)
		if !ok {
			return nil, fmt.Errorf("async eval not supported by driver")
		}
		r, err := exec.ExecuteScriptAsync(in.Script, args)
		if err != nil {
			return nil, err
		}
		result = r
	} else {
		r, err := sess.driver.ExecuteScript(in.Script, args)
		if err != nil {
			return nil, err
		}
		result = r
	}

	out := &EvalJSOutput{SessionID: sessionID, DestURL: in.DestURL, Result: result}
	if in.DestURL != "" {
		b, err := json.Marshal(map[string]any{"result": result})
		if err != nil {
			return nil, err
		}
		out.Bytes = len(b)
		out.Result = nil
		if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader(b)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
