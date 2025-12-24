package compiler

import (
	"fmt"
	"strings"

	"github.com/viant/mcp-toolbox/browser/service/criteria/ast"
	"github.com/viant/mcp-toolbox/browser/service/criteria/eval"
	"github.com/viant/toolbox/data"
)

type Operand struct {
	literal  *ast.Literal
	selector *ast.Selector
	compute  New
	nil      bool
}

type operand struct {
	literal  *ast.Literal
	selector *ast.Selector
	nil      bool
	compute  eval.Compute
}

func (o *Operand) operand() *operand {
	var compute eval.Compute
	if o.compute != nil {
		compute, _ = o.compute()
	}
	return &operand{literal: o.literal, selector: o.selector, nil: o.nil, compute: compute}
}

func (o *operand) Value(state data.Map) (interface{}, bool, error) {
	if o.literal != nil {
		return o.literal.Value, true, nil
	}
	if o.selector != nil {
		ret, ok := state.GetValue(o.selector.X[1:])
		if !ok {
			if index := strings.LastIndex(o.selector.X, "("); index != -1 {
				key := o.selector.X[1:index]
				if state.Has(key) {
					return state.Expand(o.selector.X), true, nil
				}
				if udfs := state.GetMap(data.UDFKey); len(udfs) > 0 {
					return state.Expand(o.selector.X), true, nil
				}
			}
		}
		return ret, ok, nil
	}
	if o.nil {
		return nil, false, nil
	}
	if o.compute != nil {
		return o.compute(state)
	}
	return nil, false, fmt.Errorf("unsupported operand")
}
