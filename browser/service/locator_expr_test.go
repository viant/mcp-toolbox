package service

import (
	"reflect"
	"testing"
)

func TestParseLocatorExpr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want *Locator
		ok   bool
	}{
		{
			name: "text",
			in:   "text=Sign in",
			ok:   true,
			want: &Locator{Text: "Sign in"},
		},
		{
			name: "role_name_exact",
			in:   "role=button name='Sign in' exact=true",
			ok:   true,
			want: &Locator{Role: "button", Name: "Sign in", Exact: true},
		},
		{
			name: "within_prefix",
			in:   "within(text='Dialog') role=button name='Sign in'",
			ok:   true,
			want: &Locator{
				Within: &Locator{Text: "Dialog"},
				Role:   "button",
				Name:   "Sign in",
			},
		},
		{
			name: "within_or",
			in:   "within(role=dialog) or(text='Sign in', text='Log in')",
			ok:   true,
			want: &Locator{
				Within: &Locator{Role: "dialog"},
				Any:    []*Locator{{Text: "Sign in"}, {Text: "Log in"}},
			},
		},
		{
			name: "or_comma",
			in:   "or(text='Sign in', text='Log in')",
			ok:   true,
			want: &Locator{
				Any: []*Locator{{Text: "Sign in"}, {Text: "Log in"}},
			},
		},
		{
			name: "or_pipe_legacy",
			in:   "or(text='Sign in' | text='Log in')",
			ok:   true,
			want: &Locator{
				Any: []*Locator{{Text: "Sign in"}, {Text: "Log in"}},
			},
		},
		{
			name: "and_comma",
			in:   "and(role=button, name='Submit')",
			ok:   true,
			want: &Locator{
				All: []*Locator{{Role: "button"}, {Name: "Submit"}},
			},
		},
		{
			name: "not",
			in:   "not(text='Cancel')",
			ok:   true,
			want: &Locator{
				Not: &Locator{Text: "Cancel"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLocatorExpr(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok=%v, want %v (got=%#v)", ok, tt.ok, got)
			}
			if !tt.ok {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
