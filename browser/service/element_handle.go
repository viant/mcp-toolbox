package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/tebeka/selenium"
)

const (
	defaultHandleTTL  = 10 * time.Minute
	defaultMaxHandles = 500
	handlePrefix      = "h"
)

func (s *Session) storeHandle(el selenium.WebElement) string {
	if s == nil || el == nil {
		return ""
	}
	s.handlesMux.Lock()
	defer s.handlesMux.Unlock()
	if s.handles == nil {
		s.handles = map[string]*elementHandle{}
	}
	s.handleSeq++
	id := fmt.Sprintf("%s%d", handlePrefix, s.handleSeq)
	now := time.Now()
	s.handles[id] = &elementHandle{element: el, created: now, lastUsed: now}
	s.purgeHandlesLocked(now)
	return id
}

func (s *Session) getHandle(id string) (selenium.WebElement, bool) {
	if s == nil {
		return nil, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false
	}
	s.handlesMux.Lock()
	defer s.handlesMux.Unlock()
	if s.handles == nil {
		return nil, false
	}
	h := s.handles[id]
	if h == nil || h.element == nil {
		delete(s.handles, id)
		return nil, false
	}
	h.lastUsed = time.Now()
	return h.element, true
}

func (s *Session) deleteHandle(id string) {
	if s == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	s.handlesMux.Lock()
	defer s.handlesMux.Unlock()
	if s.handles == nil {
		return
	}
	delete(s.handles, id)
}

func (s *Session) purgeHandlesLocked(now time.Time) {
	if s == nil || s.handles == nil {
		return
	}
	ttl := defaultHandleTTL
	for k, v := range s.handles {
		if v == nil || v.element == nil {
			delete(s.handles, k)
			continue
		}
		if now.Sub(v.lastUsed) > ttl {
			delete(s.handles, k)
		}
	}
	// Hard cap to prevent unbounded growth.
	if len(s.handles) <= defaultMaxHandles {
		return
	}
	// Best-effort: drop oldest by lastUsed (single pass selection).
	type kv struct {
		key      string
		lastUsed time.Time
	}
	oldest := make([]kv, 0, len(s.handles))
	for k, v := range s.handles {
		oldest = append(oldest, kv{key: k, lastUsed: v.lastUsed})
	}
	// Partial selection: repeatedly remove the currently oldest until within cap.
	for len(s.handles) > defaultMaxHandles {
		var min kv
		found := false
		for _, item := range oldest {
			if _, ok := s.handles[item.key]; !ok {
				continue
			}
			if !found || item.lastUsed.Before(min.lastUsed) {
				min = item
				found = true
			}
		}
		if !found {
			break
		}
		delete(s.handles, min.key)
	}
}
