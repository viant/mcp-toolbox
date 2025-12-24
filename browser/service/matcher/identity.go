package matcher

import (
	"github.com/viant/parsly"
)

// Identity matches an identifier with optional dashes/underscores and digits.
type Identity struct{}

func NewIdentity() *Identity { return &Identity{} }

func (m *Identity) Match(cursor *parsly.Cursor) int {
	pos := cursor.Pos
	input := cursor.Input
	if pos >= len(input) {
		return 0
	}
	i := pos
	for i < len(input) {
		c := input[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			i++
			continue
		}
		break
	}
	return i - pos
}
