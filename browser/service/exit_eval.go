package service

import (
	"github.com/viant/mcp-toolbox/browser/service/criteria/compiler"
	"github.com/viant/toolbox/data"
)

// evaluateExit evaluates Endly-compatible criteria expressions used by webdriver waits.
// This is a local port of Endly criteria parser/compiler/evaluator to avoid bringing the full Endly runtime.
func evaluateExit(state data.Map, actual map[string]any, expr string) (bool, error) {
	if expr == "" {
		return true, nil
	}
	// Merge session state + response data into a single evaluation state.
	evalState := data.Map{}
	for k, v := range state {
		evalState[k] = v
	}
	for k, v := range actual {
		evalState[k] = v
	}
	newCompute, err := compiler.Compile(expr)
	if err != nil {
		return false, err
	}
	compute, err := newCompute()
	if err != nil {
		return false, err
	}
	value, has, err := compute(evalState)
	if err != nil {
		return false, err
	}
	if !has {
		return false, nil
	}
	if b, ok := value.(bool); ok {
		return b, nil
	}
	// non-bool results are treated as false.
	return false, nil
}
