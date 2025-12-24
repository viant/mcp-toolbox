package service

import (
	"testing"

	"github.com/viant/toolbox/data"
)

func TestEvaluateExit_CriteriaParitySubset(t *testing.T) {
	state := data.Map{
		"key1":    123,
		"key2":    13,
		"k3":      "123",
		"counter": 11,
	}

	cases := []struct {
		expr   string
		expect bool
	}{
		{"$counter > 10", true},
		{"$key1 = 123", true},
		{"$key1 = 123 && $key2 > 12", true},
		{"$key1 = 123 && $key2 > 99", false},
		{"($key1 = 123 && $key2 > 12) || $k3 contains 123 || $z", true},
		{"($key1 = 123 && $key2 > 99) || $k3 contains 999 || $z", false},
		// terminator contains form (Endly uses :/ with /pattern/)
		{"$k3:/23/", true},
		{"$k3:!/23/", false},
		{"defined $missing", false},
		{"!defined $missing", true},
		{":!$value", false},
	}
	for _, tc := range cases {
		ok, err := evaluateExit(state, map[string]any{}, tc.expr)
		if err != nil {
			t.Fatalf("expr %q err: %v", tc.expr, err)
		}
		if ok != tc.expect {
			t.Fatalf("expr %q expected %v got %v", tc.expr, tc.expect, ok)
		}
	}
}
