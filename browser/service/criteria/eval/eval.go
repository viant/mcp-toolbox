package eval

import "github.com/viant/toolbox/data"

// Compute evaluates expression against a state map.
// It returns (value, has, error) where has indicates whether required operands were present.
type Compute func(state data.Map) (interface{}, bool, error)
