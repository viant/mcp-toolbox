package service

import (
	"encoding/json"
	"sync"
	"time"

	selog "github.com/tebeka/selenium/log"
)

type netTracker struct {
	mux        sync.Mutex
	inflight   int
	lastChange time.Time
}

func (t *netTracker) Inflight() int {
	t.mux.Lock()
	defer t.mux.Unlock()
	return t.inflight
}

func (t *netTracker) Drain(driver any) {
	wd, ok := driver.(interface {
		Log(typ selog.Type) ([]selog.Message, error)
	})
	if !ok {
		return
	}
	messages, err := wd.Log(selog.Performance)
	if err != nil {
		return
	}
	for _, msg := range messages {
		method, params, perr := parsePerformanceLogMessage(msg.Message)
		if perr != nil {
			continue
		}
		_ = t.consume(method, params)
	}
}

func (t *netTracker) consume(method string, _ json.RawMessage) error {
	switch method {
	case "Network.requestWillBeSent":
		t.bump(+1)
	case "Network.loadingFinished", "Network.loadingFailed":
		t.bump(-1)
	}
	return nil
}

func (t *netTracker) bump(delta int) {
	t.mux.Lock()
	defer t.mux.Unlock()
	t.inflight += delta
	if t.inflight < 0 {
		t.inflight = 0
	}
	t.lastChange = time.Now()
}
