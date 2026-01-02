package service

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Service) TypeIntoWindow(ctx context.Context, in *TypeIntoWindowInput) (*TypeIntoWindowOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	titleNeedle := strings.TrimSpace(in.TitleContains)
	if titleNeedle == "" {
		return nil, fmt.Errorf("titleContains is required")
	}
	activate := true
	if in.Activate != nil {
		activate = *in.Activate
	}

	ls, err := s.ListWindows(ctx, &ListWindowsInput{
		TitleContains:     titleNeedle,
		Limit:             1,
		IncludeEmptyTitle: false,
	})
	if err != nil {
		return nil, err
	}
	if len(ls.Windows) == 0 {
		return nil, fmt.Errorf("no window found matching titleContains=%q", titleNeedle)
	}
	win := ls.Windows[0]

	if activate {
		if _, err := s.ActivateWindow(ctx, &ActivateWindowInput{Target: WindowTarget{Kind: "pid", ID: int64(win.Pid)}}); err != nil {
			return nil, err
		}
	}

	if in.DelayMs > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(in.DelayMs) * time.Millisecond):
		}
	}

	if _, err := s.Type(ctx, &TypeInput{Text: in.Text, Timing: in.Timing}); err != nil {
		return nil, err
	}

	return &TypeIntoWindowOutput{Pid: win.Pid, Title: win.Title}, nil
}
