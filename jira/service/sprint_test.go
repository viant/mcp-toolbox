package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestListSprints(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/agile/1.0/board/281/sprint" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		if got := q.Get("state"); got != "active" {
			t.Errorf("unexpected state query: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := q.Get("startAt"); got != "0" && got != "" {
			t.Errorf("unexpected startAt query: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := q.Get("maxResults"); got != "50" {
			t.Errorf("unexpected maxResults query: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "startAt": 0,
  "maxResults": 50,
  "total": 1,
  "isLast": true,
  "values": [
    {
      "id": 4699,
      "name": "Sprint329(16/Feb/26-02/Mar/26)",
      "state": "active",
      "startDate": "2026-02-16T22:30:23.782Z",
      "endDate": "2026-03-02T22:30:00.000Z",
      "completeDate": ""
    }
  ]
}`))
	}))
	defer server.Close()

	baseURL := server.URL
	_, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}

	svc := NewService(&Config{
		Accounts: map[string]Account{
			"default": {
				Alias:   "default",
				BaseURL: baseURL,
				Email:   "test@example.com",
				Token:   "test-token",
			},
		},
	})

	out, err := svc.ListSprints(context.Background(), &ListSprintsInput{
		Account:    AccountRef{Alias: "default"},
		BoardID:    281,
		State:      "active",
		StartAt:    0,
		MaxResults: 50,
	})
	if err != nil {
		t.Fatalf("ListSprints error: %v", err)
	}
	if out.Total != 1 || len(out.Sprints) != 1 {
		t.Fatalf("expected 1 sprint, got total=%d len=%d", out.Total, len(out.Sprints))
	}
	if out.Sprints[0].ID != 4699 || out.Sprints[0].State != "active" {
		t.Fatalf("unexpected sprint: %#v", out.Sprints[0])
	}
}

func TestGetActiveSprint(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/agile/1.0/board/281/sprint" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		if got := q.Get("state"); got != "active" {
			t.Errorf("unexpected state query: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := q.Get("maxResults"); got != "1" {
			t.Errorf("unexpected maxResults query: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "startAt": 0,
  "maxResults": 1,
  "total": 1,
  "isLast": true,
  "values": [
    {
      "id": 4699,
      "name": "Sprint329(16/Feb/26-02/Mar/26)",
      "state": "active",
      "startDate": "2026-02-16T22:30:23.782Z",
      "endDate": "2026-03-02T22:30:00.000Z",
      "completeDate": ""
    }
  ]
}`))
	}))
	defer server.Close()

	svc := NewService(&Config{
		Accounts: map[string]Account{
			"default": {
				Alias:   "default",
				BaseURL: server.URL,
				Email:   "test@example.com",
				Token:   "test-token",
			},
		},
	})

	out, err := svc.GetActiveSprint(context.Background(), &GetActiveSprintInput{
		Account: AccountRef{Alias: "default"},
		BoardID: 281,
	})
	if err != nil {
		t.Fatalf("GetActiveSprint error: %v", err)
	}
	if out.Sprint.ID != 4699 || out.Sprint.State != "active" {
		t.Fatalf("unexpected sprint: %#v", out.Sprint)
	}
}
