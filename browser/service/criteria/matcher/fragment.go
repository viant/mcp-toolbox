package matcher

import (
	"github.com/viant/parsly"
	"github.com/viant/parsly/matcher"
)

// Fragment matches a token until whitespace or an operator boundary.
// This is a minimal port of Endly criteria matcher.
type Fragment struct{}

func NewFragment() *Fragment { return &Fragment{} }

func (m *Fragment) Match(cursor *parsly.Cursor) (matched int) {
	input := cursor.Input
	pos := cursor.Pos
	size := len(input)
	for i := pos; i < size; i++ {
		c := input[i]
		if matcher.IsWhiteSpace(c) {
			break
		}
		switch c {
		case '(', ')':
			if matched == 0 {
				return 0
			}
			return matched
		}
		// stop at logical operators
		if c == '&' || c == '|' {
			if matched == 0 {
				return 0
			}
			return matched
		}
		matched++
	}
	return matched
}
