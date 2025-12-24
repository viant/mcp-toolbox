package parser

import (
	"github.com/viant/mcp-toolbox/browser/service/criteria/ast"
	"github.com/viant/parsly"
)

func ParseCriteria(input string) (*ast.Qualify, error) {
	cursor := parsly.NewCursor("", []byte(input), 0)
	qualify := &ast.Qualify{}
	err := parseCriteria(cursor, qualify)
	if err != nil {
		return nil, err
	}
	return qualify, nil
}
