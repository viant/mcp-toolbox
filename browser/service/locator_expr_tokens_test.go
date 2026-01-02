package service

import (
	"testing"
)

func TestLooksLikeKeyValueToken(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "empty", input: "", expected: false},
		{name: "whitespace", input: "   \t", expected: false},
		{name: "no_equals", input: "text", expected: false},
		{name: "leading_equals", input: "=x", expected: false},
		{name: "has_space_before_equals", input: "text =x", expected: false},
		{name: "simple", input: "text=Sign", expected: true},
		{name: "with_quotes", input: "name='Sign in'", expected: true},
		{name: "with_prefix_whitespace", input: "  role=button", expected: true},
		{name: "not_kv_token", input: "in", expected: false},
		{name: "function_call", input: "within(role=dialog)", expected: true}, // contains '=' after token start
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := looksLikeKeyValueToken(testCase.input)
			if actual != testCase.expected {
				t.Fatalf("got %v, want %v", actual, testCase.expected)
			}
		})
	}
}
