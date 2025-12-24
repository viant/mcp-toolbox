package service

import "testing"

func TestEnforceHeadfulCaps(t *testing.T) {
	in := []string{
		"  --headless  ",
		"--headless=new",
		"-headless",
		"headless",
		"--window-size=1280,720",
		"--disable-gpu",
	}
	got := enforceHeadfulCaps(in)
	for _, arg := range got {
		if arg == "--headless" || arg == "--headless=new" || arg == "-headless" || arg == "headless" {
			t.Fatalf("expected headless args removed, got: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 args remaining, got: %v", got)
	}
	if got[0] != "--window-size=1280,720" || got[1] != "--disable-gpu" {
		t.Fatalf("unexpected remaining args: %v", got)
	}
}
