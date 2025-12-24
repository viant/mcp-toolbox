package service

import (
	"fmt"
	"strings"

	"github.com/viant/toolbox"
)

func addResultIfPresent(callResult []any, result map[string]any, key string, call *MethodCall, kind PathKind) bool {
	if len(callResult) == 0 {
		return false
	}
	var responseData any
	has := false
	for _, element := range callResult {
		if element == nil {
			continue
		}
		switch actual := element.(type) {
		case string:
			responseData = actual
		case []byte:
			responseData = string(actual)
		case []any:
			responseData = actual
		case []map[string]any:
			responseData = actual
		case map[string]any:
			responseData = actual
		default:
			// Ignore unsupported types; typically the last return is error which is handled elsewhere.
			continue
		}
		has = true
		break
	}
	if !has {
		return false
	}
	path := resultPath(key, call, kind)
	result[strings.Join(path, ".")] = responseData
	return true
}

func resultPath(key string, call *MethodCall, kind PathKind) []string {
	if kind == PathKindSimple || call == nil {
		return []string{key}
	}
	method := call.Method
	if len(call.Parameters) == 1 && toolbox.IsString(call.Parameters[0]) {
		method = strings.Replace(method, "Get", "", 1) + "." + toolbox.AsString(call.Parameters[0])
	}
	return []string{key, method}
}

func (s *Service) TableData(owner any, format string) (any, error) {
	// owner is expected to be selenium.WebElement
	elem, ok := owner.(interface {
		TagName() (string, error)
		GetAttribute(name string) (string, error)
	})
	if !ok {
		return nil, fmt.Errorf("TableData owner unsupported: %T", owner)
	}
	header := ""
	if idx := strings.Index(format, ":"); idx != -1 {
		header = format[idx+1:]
		format = format[:idx]
	}
	if format == "" {
		format = "objects"
	}
	var headers []string
	if header != "" {
		headers = strings.Split(header, ",")
	}
	tagName, err := elem.TagName()
	if err != nil {
		return nil, err
	}
	if tagName != "table" {
		return nil, fmt.Errorf("element is not a table")
	}
	tableHTML, err := elem.GetAttribute("outerHTML")
	if err != nil {
		return nil, fmt.Errorf("failed to get table html: %v", err)
	}
	exp, err := newTableExporter(tableHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to create table exporter: %v", err)
	}
	ret, err := exp.Export(headers, format)
	if err != nil {
		return nil, fmt.Errorf("failed to export table: %v", err)
	}
	return ret, nil
}
