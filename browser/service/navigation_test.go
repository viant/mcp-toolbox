package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tebeka/selenium"
)

func TestNavigation_WithDefaults(t *testing.T) {
	nav := navigationWithDefaults(nil)
	if nav.TimeoutMs <= 0 || nav.ScrollDelayMs <= 0 || nav.StableWindowMs <= 0 || nav.MaxScrollSteps <= 0 {
		t.Fatalf("expected defaults: %#v", nav)
	}
	if nav.IdleWindowMs <= 0 {
		t.Fatalf("expected IdleWindowMs default: %#v", nav)
	}
}

func TestNavigation_IsPageLoadTimeout(t *testing.T) {
	if !isPageLoadTimeout(errors.New("timeout")) {
		t.Fatalf("expected timeout match")
	}
	if !isPageLoadTimeout(&selenium.Error{LegacyCode: 21, Message: "timeout"}) {
		t.Fatalf("expected legacy timeout match")
	}
	if isPageLoadTimeout(errors.New("other")) {
		t.Fatalf("did not expect match")
	}
}

func TestNetTracker_Inflight(t *testing.T) {
	tracker := &netTracker{}
	_ = tracker.consume("Network.requestWillBeSent", nil)
	_ = tracker.consume("Network.requestWillBeSent", nil)
	if tracker.Inflight() != 2 {
		t.Fatalf("expected inflight 2, got %d", tracker.Inflight())
	}
	_ = tracker.consume("Network.loadingFinished", nil)
	if tracker.Inflight() != 1 {
		t.Fatalf("expected inflight 1, got %d", tracker.Inflight())
	}
	_ = tracker.consume("Network.loadingFailed", nil)
	if tracker.Inflight() != 0 {
		t.Fatalf("expected inflight 0, got %d", tracker.Inflight())
	}
}

type nilableDriver struct{ selenium.WebDriver }

func (d *nilableDriver) ExecuteScript(_ string, _ []any) (any, error) { return "complete", nil }

type panicExecuteScriptDriver struct{ selenium.WebDriver }

func (d panicExecuteScriptDriver) ExecuteScript(_ string, _ []any) (any, error) { panic("boom") }

func TestWaitDocumentReady_TypedNilDriver(t *testing.T) {
	var d *nilableDriver
	var wd selenium.WebDriver = d // typed nil interface
	sess := &Session{ID: "x", driver: wd}

	svc := &Service{}
	err := svc.waitDocumentReady(sess, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "webdriver session not open") {
		t.Fatalf("expected session not open error, got: %v", err)
	}
}

func TestWaitDocumentReady_ExecuteScriptPanic(t *testing.T) {
	sess := &Session{ID: "x", driver: panicExecuteScriptDriver{}}

	svc := &Service{}
	err := svc.waitDocumentReady(sess, 10*time.Millisecond)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "panic") {
		t.Fatalf("expected panic error, got: %v", err)
	}

	done := make(chan struct{})
	go func() {
		sess.lock.Lock()
		sess.lock.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("session lock appears to be left locked")
	}
}
