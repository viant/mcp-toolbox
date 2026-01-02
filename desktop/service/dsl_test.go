package service

import "testing"

func TestParseDSL(t *testing.T) {
	cmd, err := parseDSL("x = screenshot(destURL='file:///tmp/a.png', x=1, y=2, w=3, h=4)")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Assign != "x" {
		t.Fatalf("expected assign x, got %q", cmd.Assign)
	}
	if cmd.Name != "screenshot" {
		t.Fatalf("expected screenshot, got %q", cmd.Name)
	}
	if cmd.Kw["destURL"] != "file:///tmp/a.png" {
		t.Fatalf("destURL mismatch: %#v", cmd.Kw["destURL"])
	}
}
