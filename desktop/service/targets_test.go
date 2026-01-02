package service

import "testing"

func TestNormalizeTarget(t *testing.T) {
	_, _, err := normalizeTarget(nil)
	if err == nil {
		t.Fatalf("expected error for nil input")
	}

	_, _, err = normalizeTarget(&ActivateWindowInput{Target: WindowTarget{Kind: "pid", ID: 0}})
	if err == nil {
		t.Fatalf("expected error for pid=0")
	}

	id, isHandle, err := normalizeTarget(&ActivateWindowInput{Target: WindowTarget{Kind: "pid", ID: 123}})
	if err != nil || isHandle || id != 123 {
		t.Fatalf("unexpected: id=%v isHandle=%v err=%v", id, isHandle, err)
	}

	id, isHandle, err = normalizeTarget(&ActivateWindowInput{Target: WindowTarget{Kind: "handle", ID: 55}})
	if err != nil || !isHandle || id != 55 {
		t.Fatalf("unexpected: id=%v isHandle=%v err=%v", id, isHandle, err)
	}

	_, _, err = normalizeTarget(&ActivateWindowInput{Target: WindowTarget{Kind: "nope", ID: 1}})
	if err == nil {
		t.Fatalf("expected error for unknown kind")
	}
}
