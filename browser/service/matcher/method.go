package matcher

import (
	"github.com/viant/parsly"
)

// Literal matches a method call literal like Foo(...) up to the closing ')'.
// It is used to capture "Method(params)" in a single token.
type Literal struct{}

func NewLiteral() *Literal { return &Literal{} }

func (m *Literal) Match(cursor *parsly.Cursor) int {
	pos := cursor.Pos
	input := cursor.Input
	if pos >= len(input) {
		return 0
	}
	i := pos
	// Must start with a letter.
	c := input[i]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return 0
	}
	// Consume until we see a '('; if none, return 0 so identifier matcher can take over.
	for i < len(input) && input[i] != '(' && input[i] != '\n' && input[i] != '\r' {
		i++
	}
	if i >= len(input) || input[i] != '(' {
		return 0
	}
	// Find matching ')', no nested parens support (matches Endly behavior).
	depth := 0
	for i < len(input) {
		if input[i] == '(' {
			depth++
		} else if input[i] == ')' {
			depth--
			if depth == 0 {
				i++
				return i - pos
			}
		}
		i++
	}
	return 0
}
