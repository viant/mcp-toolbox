package service

import "testing"

func TestParser_ParseGet(t *testing.T) {
	p := &parser{}
	a, err := p.Parse("get(http://example.com)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Calls[0].Method != "Get" {
		t.Fatalf("expected Get, got %s", a.Calls[0].Method)
	}
}

func TestWebSelector_ByAndValue(t *testing.T) {
	by, v := WebSelector("#id").ByAndValue()
	if by == "" || v != "#id" {
		t.Fatalf("unexpected selector: %s %s", by, v)
	}
	by, v = WebSelector(".red").ByAndValue()
	if v != ".red" {
		t.Fatalf("expected .red, got %s", v)
	}
	by, v = WebSelector("xpath://div").ByAndValue()
	if by == "" || v != "//div" {
		t.Fatalf("unexpected xpath: %s %s", by, v)
	}
}
